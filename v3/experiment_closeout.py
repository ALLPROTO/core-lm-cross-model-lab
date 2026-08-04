#!/usr/bin/env python3
"""Canonical public closeout classifications for the blind-v3 experiment.

``NO_ATTEMPT_EXPIRED`` and ``LATE_PUBLICATION_INVALID`` are public experiment
or publication classifications.  They are deliberately not local attempt
terminal outcomes; the only attempt outcomes remain PASS, FAIL_GATES,
FAIL_EXECUTION, and CONSUMED_INCOMPLETE.

No-attempt classification requires a separately supplied, content-addressed
audit observation of one empty result root on one host after the hard
execution deadline.  It never promotes that local observation into a claim
that no attempt exists anywhere else.

Late-publication classification validates an archived evidence release
receipt with a dedicated relation of ``attestedAt >= registered deadline``.
That relation shares the exact ordinary release-verifier implementation for
all receipt, Git object, signature, GitHub response, immutable-release, and
local-asset checks.  The ordinary on-time entry point remains strict and
rejects the same canonical receipt.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from v3.release_receipt import (
    ReleaseAttestationCryptographicVerifier,
    ReleaseReceiptError,
    VerifiedReleaseReceipt,
    verify_late_release_receipt_for_closeout,
    verify_release_receipt,
)


SCHEMA_VERSION = "corelm-crossmodel-livewiki-v3-experiment-closeout-v1"
OBSERVATION_SCHEMA = (
    "corelm-crossmodel-livewiki-v3-empty-result-root-observation-v1"
)
AUDIT_REPORT_SCHEMA = "corelm-crossmodel-livewiki-v3-empty-result-root-audit-v1"
SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
DOCUMENT_TYPE = "PUBLIC_EXPERIMENT_CLOSEOUT"
CLASSIFICATION_SCOPE = (
    "PUBLIC_EXPERIMENT_OR_PUBLICATION_CLASSIFICATION_NOT_ATTEMPT_TERMINAL_OUTCOME"
)
ATTEMPT_TERMINAL_STATES = (
    "PASS",
    "FAIL_GATES",
    "FAIL_EXECUTION",
    "CONSUMED_INCOMPLETE",
)
CLASSIFICATIONS = frozenset(("NO_ATTEMPT_EXPIRED", "LATE_PUBLICATION_INVALID"))
DESIGN_PUBLICATION_DEADLINE = "2026-08-15T00:00:00Z"
SNAPSHOT_PUBLICATION_DEADLINE = "2026-09-01T18:00:00Z"
EXECUTION_HARD_DEADLINE = "2026-09-04T18:00:00Z"
EVIDENCE_PUBLICATION_DEADLINE = "2026-09-07T18:00:00Z"
CLOSEOUT_PUBLICATION_DEADLINE = "2026-09-14T18:00:00Z"
EVIDENCE_REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
EVIDENCE_TAG = "corelm-crossmodel-livewiki-v3-evidence"
CLOSEOUT_TAG = "corelm-crossmodel-livewiki-v3-closeout"
SIGNATURE_TYPE = "SSH"
CLOSEOUT_SIGNING_KEY_FINGERPRINT = (
    "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM"
)
CLOSEOUT_SIGNING_PUBLIC_KEY_SHA256 = (
    "beac537f2979026cd85facd195132979a5a3a77da65f87d563ffb6253d408ea2"
)
OBSERVATION_SCOPE = "ONLY_THIS_RESULT_ROOT_ON_THIS_HOST_AT_OBSERVED_AT"
EMPTY_INVENTORY_SHA256 = hashlib.sha256(b"[]").hexdigest()
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
SSH_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
MAXIMUM_DOCUMENT_BYTES = 64 * 1024 * 1024
MAXIMUM_HOST_ENVIRONMENT_BYTES = 64 * 1024 * 1024

DEADLINES = {
    "designPublicationDeadline": DESIGN_PUBLICATION_DEADLINE,
    "snapshotPublicationDeadline": SNAPSHOT_PUBLICATION_DEADLINE,
    "executionHardDeadline": EXECUTION_HARD_DEADLINE,
    "evidencePublicationDeadline": EVIDENCE_PUBLICATION_DEADLINE,
    "closeoutPublicationDeadline": CLOSEOUT_PUBLICATION_DEADLINE,
}
CLOSEOUT_RELEASE_PLAN = {
    "repository": EVIDENCE_REPOSITORY,
    "kind": "closeout",
    "tag": CLOSEOUT_TAG,
    "publishNoLaterThan": CLOSEOUT_PUBLICATION_DEADLINE,
    "serverTimestampRequired": True,
    "immutableReleaseRequired": True,
    "signedAnnotatedTagRequired": True,
    "signatureType": SIGNATURE_TYPE,
    "signingKeyFingerprint": CLOSEOUT_SIGNING_KEY_FINGERPRINT,
    "signingPublicKeySHA256": CLOSEOUT_SIGNING_PUBLIC_KEY_SHA256,
    "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
}


class ExperimentCloseoutError(ValueError):
    """A closeout classification is noncanonical, unsupported, or unproven."""


@dataclass(frozen=True)
class PublicationBindings:
    design_registration_sha256: str
    design_publication_receipt_sha256: str
    snapshot_registration_sha256: str
    snapshot_publication_receipt_sha256: str
    closeout_source_commit: str
    closeout_source_tree: str

    def __post_init__(self) -> None:
        for field, value in (
            ("design registration", self.design_registration_sha256),
            ("design publication receipt", self.design_publication_receipt_sha256),
            ("snapshot registration", self.snapshot_registration_sha256),
            ("snapshot publication receipt", self.snapshot_publication_receipt_sha256),
        ):
            _digest(value, label=field)
        _git_oid(self.closeout_source_commit, label="closeout source commit")
        _git_oid(self.closeout_source_tree, label="closeout source tree")

    @classmethod
    def from_exact_bytes(
        cls,
        *,
        design_registration: bytes,
        design_publication_receipt: bytes,
        snapshot_registration: bytes,
        snapshot_publication_receipt: bytes,
        closeout_source_commit: str | None = None,
        closeout_source_tree: str | None = None,
    ) -> "PublicationBindings":
        if (closeout_source_commit is None) != (closeout_source_tree is None):
            raise ExperimentCloseoutError(
                "closeout source commit and tree must be supplied together"
            )
        design = _load_canonical_line(
            design_registration,
            label="frozen design registration",
        )
        if (
            design.get("schemaVersion")
            != "corelm-crossmodel-livewiki-v3-design-v1"
            or design.get("status") != "PUBLIC_DESIGN_FROZEN"
        ):
            raise ExperimentCloseoutError(
                "frozen design identity cannot supply closeout source binding"
            )
        lab = design.get("labSource") if isinstance(design, dict) else None
        if not isinstance(lab, dict) or lab.get("status") != "FROZEN_BOUND":
            raise ExperimentCloseoutError("frozen design lab source binding is absent")
        frozen_commit, frozen_tree = lab.get("commit"), lab.get("tree")
        _git_oid(frozen_commit, label="frozen design lab source commit")
        _git_oid(frozen_tree, label="frozen design lab source tree")
        if closeout_source_commit is None and closeout_source_tree is None:
            closeout_source_commit, closeout_source_tree = frozen_commit, frozen_tree
        elif (
            closeout_source_commit != frozen_commit
            or closeout_source_tree != frozen_tree
        ):
            raise ExperimentCloseoutError(
                "supplied closeout source differs from frozen design lab source"
            )
        return cls(
            design_registration_sha256=sha256_bytes(design_registration),
            design_publication_receipt_sha256=sha256_bytes(
                design_publication_receipt
            ),
            snapshot_registration_sha256=sha256_bytes(snapshot_registration),
            snapshot_publication_receipt_sha256=sha256_bytes(
                snapshot_publication_receipt
            ),
            closeout_source_commit=closeout_source_commit,
            closeout_source_tree=closeout_source_tree,
        )

    def as_dict(self, *, evidence_receipt_sha256: str | None) -> dict[str, Any]:
        if evidence_receipt_sha256 is not None:
            _digest(evidence_receipt_sha256, label="evidence release receipt")
        return {
            "designRegistrationSHA256": self.design_registration_sha256,
            "designPublicationReceiptSHA256": (
                self.design_publication_receipt_sha256
            ),
            "snapshotRegistrationSHA256": self.snapshot_registration_sha256,
            "snapshotPublicationReceiptSHA256": (
                self.snapshot_publication_receipt_sha256
            ),
            "evidenceReleaseReceiptSHA256": evidence_receipt_sha256,
            "closeoutSourceCommit": self.closeout_source_commit,
            "closeoutSourceTree": self.closeout_source_tree,
        }


@dataclass(frozen=True)
class VerifiedExperimentCloseout:
    classification: str
    classified_at: str
    closeout_sha256: str
    evidence_release_receipt_sha256: str | None
    basis_sha256: str


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise ExperimentCloseoutError("value is not canonical JSON data") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_constant(value: str) -> None:
    raise ExperimentCloseoutError(f"non-finite JSON number is forbidden: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ExperimentCloseoutError(f"non-finite JSON number is forbidden: {value}")
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExperimentCloseoutError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or not 1 < len(raw) <= MAXIMUM_DOCUMENT_BYTES
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ExperimentCloseoutError(
            f"{label} must be bounded and end in exactly one LF"
        )
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except UnicodeDecodeError as error:
        raise ExperimentCloseoutError(f"{label} is not strict UTF-8") from error
    except json.JSONDecodeError as error:
        raise ExperimentCloseoutError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise ExperimentCloseoutError(f"{label} root must be an object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise ExperimentCloseoutError(f"{label} is not canonical JSON plus LF")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ExperimentCloseoutError(f"{label} must be lowercase SHA-256")
    return value


def _git_oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID.fullmatch(value) is None:
        raise ExperimentCloseoutError(f"{label} must be a full lowercase Git OID")
    return value


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise ExperimentCloseoutError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ExperimentCloseoutError(f"{label} is not a real timestamp") from error


def _seal_document(document: Mapping[str, Any]) -> bytes:
    if "contentSHA256" in document:
        raise ExperimentCloseoutError("document is already sealed")
    sealed = dict(document)
    sealed["contentSHA256"] = sha256_bytes(canonical_json_bytes(document))
    return canonical_json_bytes(sealed) + b"\n"


def _verify_content_digest(document: Mapping[str, Any], *, label: str) -> None:
    digest = _digest(document.get("contentSHA256"), label=f"{label} contentSHA256")
    unsigned = dict(document)
    del unsigned["contentSHA256"]
    if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
        raise ExperimentCloseoutError(f"{label} contentSHA256 differs")


def _safe_read_regular(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ExperimentCloseoutError(f"{label} is not a no-follow file") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ExperimentCloseoutError(f"{label} type or size is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ExperimentCloseoutError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity or observed != before.st_size:
            raise ExperimentCloseoutError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_empty_result_root_audit_report(
    raw: bytes,
    *,
    host_environment_raw: bytes,
) -> dict[str, Any]:
    """Validate the exact supporting audit bytes for a no-attempt observation."""

    if (
        not isinstance(host_environment_raw, bytes)
        or not 0 < len(host_environment_raw) <= MAXIMUM_HOST_ENVIRONMENT_BYTES
    ):
        raise ExperimentCloseoutError("host environment bytes are absent or unbounded")
    report = _load_canonical_line(raw, label="empty result-root audit report")
    fields = {
        "schemaVersion",
        "suiteId",
        "auditMethod",
        "observedAt",
        "hostEnvironmentSHA256",
        "resultRootPathSHA256",
        "rootDevice",
        "rootInode",
        "entryInventory",
        "claimScope",
        "globalAbsenceEstablished",
        "contentSHA256",
    }
    if set(report) != fields:
        raise ExperimentCloseoutError("empty result-root audit report fields differ")
    _verify_content_digest(report, label="empty result-root audit report")
    if (
        report["schemaVersion"] != AUDIT_REPORT_SCHEMA
        or report["suiteId"] != SUITE_ID
        or report["auditMethod"]
        != "NOFOLLOW_DIRECTORY_FD_EXACT_EMPTY_INVENTORY"
        or report["entryInventory"] != []
        or report["claimScope"] != OBSERVATION_SCOPE
        or report["globalAbsenceEstablished"] is not False
        or report["hostEnvironmentSHA256"] != sha256_bytes(host_environment_raw)
    ):
        raise ExperimentCloseoutError("empty result-root audit report boundary differs")
    _utc(report["observedAt"], label="audit report observedAt")
    for field in ("hostEnvironmentSHA256", "resultRootPathSHA256"):
        _digest(report[field], label=f"audit report {field}")
    for field in ("rootDevice", "rootInode"):
        if type(report[field]) is not int or report[field] < 1:
            raise ExperimentCloseoutError(f"audit report {field} is invalid")
    return report


def collect_empty_result_root_observation(
    *,
    result_root: Path,
    host_environment_raw: bytes,
    auditor_identity: str,
    now: Callable[[], str],
) -> tuple[bytes, bytes]:
    """Audit one exact empty directory and return observation/report bytes.

    The caller supplies the clock so production can use the system UTC clock
    while tests use fixed values.  The verified RFC3161 timestamp in the later
    signed closeout release attestation remains the external time boundary.
    """

    if not callable(now):
        raise ExperimentCloseoutError("empty-root audit clock is not callable")
    if (
        not isinstance(host_environment_raw, bytes)
        or not 0 < len(host_environment_raw) <= MAXIMUM_HOST_ENVIRONMENT_BYTES
    ):
        raise ExperimentCloseoutError("host environment bytes are absent or unbounded")
    if not isinstance(auditor_identity, str) or not 1 <= len(auditor_identity) <= 256:
        raise ExperimentCloseoutError("observation auditor identity is invalid")
    absolute = Path(os.path.abspath(os.fspath(result_root)))
    try:
        path_metadata = os.lstat(absolute)
    except OSError as error:
        raise ExperimentCloseoutError("result root cannot be inspected") from error
    if not stat.S_ISDIR(path_metadata.st_mode) or stat.S_ISLNK(path_metadata.st_mode):
        raise ExperimentCloseoutError("result root is not a no-follow directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ExperimentCloseoutError("result root cannot be opened no-follow") from error
    try:
        before = os.fstat(descriptor)
        first_inventory = sorted(os.listdir(descriptor))
        if first_inventory:
            raise ExperimentCloseoutError("result root inventory is not empty")
        observed_at = now()
        _utc(observed_at, label="empty-root audit observedAt")
        second_inventory = sorted(os.listdir(descriptor))
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino)
        after_identity = (after.st_dev, after.st_ino)
        if first_inventory != second_inventory or second_inventory or before_identity != after_identity:
            raise ExperimentCloseoutError("result root changed during empty audit")
    finally:
        os.close(descriptor)
    root_path_sha256 = sha256_bytes(os.fsencode(os.fspath(absolute)))
    host_sha256 = sha256_bytes(host_environment_raw)
    audit_report_raw = _seal_document(
        {
            "schemaVersion": AUDIT_REPORT_SCHEMA,
            "suiteId": SUITE_ID,
            "auditMethod": "NOFOLLOW_DIRECTORY_FD_EXACT_EMPTY_INVENTORY",
            "observedAt": observed_at,
            "hostEnvironmentSHA256": host_sha256,
            "resultRootPathSHA256": root_path_sha256,
            "rootDevice": after.st_dev,
            "rootInode": after.st_ino,
            "entryInventory": [],
            "claimScope": OBSERVATION_SCOPE,
            "globalAbsenceEstablished": False,
        }
    )
    validate_empty_result_root_audit_report(
        audit_report_raw,
        host_environment_raw=host_environment_raw,
    )
    implementation_raw = _safe_read_regular(
        Path(__file__),
        maximum_bytes=4 * 1024 * 1024,
        label="empty-root audit implementation",
    )
    created_at = now()
    _utc(created_at, label="empty-root observation createdAt")
    observation_raw = _seal_document(
        {
            "schemaVersion": OBSERVATION_SCHEMA,
            "suiteId": SUITE_ID,
            "auditMethod": "NOFOLLOW_DIRECTORY_FD_EXACT_EMPTY_INVENTORY",
            "observedAt": observed_at,
            "observationCreatedAt": created_at,
            "hostEnvironmentSHA256": host_sha256,
            "resultRootPathSHA256": root_path_sha256,
            "rootDevice": after.st_dev,
            "rootInode": after.st_ino,
            "entryCount": 0,
            "emptyInventorySHA256": EMPTY_INVENTORY_SHA256,
            "claimScope": OBSERVATION_SCOPE,
            "globalAbsenceEstablished": False,
            "auditImplementationSHA256": sha256_bytes(implementation_raw),
            "auditReportSHA256": sha256_bytes(audit_report_raw),
            "auditorIdentity": auditor_identity,
        }
    )
    observation = validate_empty_result_root_observation(observation_raw)
    report = validate_empty_result_root_audit_report(
        audit_report_raw,
        host_environment_raw=host_environment_raw,
    )
    if (
        observation["observedAt"] != report["observedAt"]
        or observation["hostEnvironmentSHA256"] != report["hostEnvironmentSHA256"]
        or observation["resultRootPathSHA256"] != report["resultRootPathSHA256"]
        or observation["rootDevice"] != report["rootDevice"]
        or observation["rootInode"] != report["rootInode"]
        or observation["auditReportSHA256"] != sha256_bytes(audit_report_raw)
    ):
        raise ExperimentCloseoutError("empty observation and audit report differ")
    return observation_raw, audit_report_raw


def validate_empty_result_root_observation(raw: bytes) -> dict[str, Any]:
    """Validate a supplied historical empty-root audit without widening its scope."""

    observation = _load_canonical_line(raw, label="empty result-root observation")
    fields = {
        "schemaVersion",
        "suiteId",
        "auditMethod",
        "observedAt",
        "observationCreatedAt",
        "hostEnvironmentSHA256",
        "resultRootPathSHA256",
        "rootDevice",
        "rootInode",
        "entryCount",
        "emptyInventorySHA256",
        "claimScope",
        "globalAbsenceEstablished",
        "auditImplementationSHA256",
        "auditReportSHA256",
        "auditorIdentity",
        "contentSHA256",
    }
    if set(observation) != fields:
        raise ExperimentCloseoutError("empty result-root observation fields differ")
    _verify_content_digest(observation, label="empty result-root observation")
    if (
        observation["schemaVersion"] != OBSERVATION_SCHEMA
        or observation["suiteId"] != SUITE_ID
        or observation["auditMethod"]
        != "NOFOLLOW_DIRECTORY_FD_EXACT_EMPTY_INVENTORY"
        or observation["entryCount"] != 0
        or observation["emptyInventorySHA256"] != EMPTY_INVENTORY_SHA256
        or observation["claimScope"] != OBSERVATION_SCOPE
        or observation["globalAbsenceEstablished"] is not False
    ):
        raise ExperimentCloseoutError(
            "empty result-root observation scope or inventory differs"
        )
    for field in (
        "hostEnvironmentSHA256",
        "resultRootPathSHA256",
        "auditImplementationSHA256",
        "auditReportSHA256",
    ):
        _digest(observation[field], label=f"observation {field}")
    for field in ("rootDevice", "rootInode"):
        if type(observation[field]) is not int or observation[field] < 1:
            raise ExperimentCloseoutError(f"observation {field} is invalid")
    auditor = observation["auditorIdentity"]
    if not isinstance(auditor, str) or not 1 <= len(auditor) <= 256:
        raise ExperimentCloseoutError("observation auditor identity is invalid")
    observed_at = _utc(observation["observedAt"], label="observation observedAt")
    created_at = _utc(
        observation["observationCreatedAt"],
        label="observation observationCreatedAt",
    )
    if observed_at < _utc(
        EXECUTION_HARD_DEADLINE, label="execution hard deadline"
    ):
        raise ExperimentCloseoutError(
            "empty result-root observation predates the hard execution deadline"
        )
    if created_at < observed_at:
        raise ExperimentCloseoutError("empty observation was created before its audit")
    return observation


def _publication_bindings(
    bindings: PublicationBindings,
    *,
    evidence_receipt_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(bindings, PublicationBindings):
        raise ExperimentCloseoutError("publication bindings are not typed")
    return bindings.as_dict(evidence_receipt_sha256=evidence_receipt_sha256)


def _base_document(
    *,
    classification: str,
    classified_at: str,
    publication_bindings: Mapping[str, Any],
    basis: Mapping[str, Any],
) -> dict[str, Any]:
    if classification not in CLASSIFICATIONS:
        raise ExperimentCloseoutError("unsupported experiment closeout classification")
    _utc(classified_at, label="classifiedAt")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "documentType": DOCUMENT_TYPE,
        "classification": classification,
        "classificationScope": CLASSIFICATION_SCOPE,
        "attemptTerminalOutcome": None,
        "attemptTerminalStatesExcluded": list(ATTEMPT_TERMINAL_STATES),
        "doesNotModifyAttemptOutcome": True,
        "deadlines": dict(DEADLINES),
        "closeoutReleasePlan": dict(CLOSEOUT_RELEASE_PLAN),
        "publicationBindings": dict(publication_bindings),
        "basis": dict(basis),
        "classifiedAt": classified_at,
        "countsTowardScientificVerdict": False,
        "retryPermitted": False,
    }


def create_no_attempt_expired(
    *,
    publication_bindings: PublicationBindings,
    empty_result_root_observation_raw: bytes,
    classified_at: str,
) -> bytes:
    """Create a closeout bound to one explicitly limited empty-root audit."""

    observation = validate_empty_result_root_observation(
        empty_result_root_observation_raw
    )
    classified = _utc(classified_at, label="classifiedAt")
    observation_created = _utc(
        observation["observationCreatedAt"],
        label="observation observationCreatedAt",
    )
    if classified < observation_created:
        raise ExperimentCloseoutError("classification predates its audit observation")
    basis = {
        "kind": "AUDITED_EMPTY_OBSERVED_RESULT_ROOT",
        "emptyResultRootObservationSHA256": sha256_bytes(
            empty_result_root_observation_raw
        ),
        "observedAt": observation["observedAt"],
        "observationCreatedAt": observation["observationCreatedAt"],
        "observedHostEnvironmentSHA256": observation[
            "hostEnvironmentSHA256"
        ],
        "observedResultRootPathSHA256": observation[
            "resultRootPathSHA256"
        ],
        "rootDevice": observation["rootDevice"],
        "rootInode": observation["rootInode"],
        "entryCount": 0,
        "emptyInventorySHA256": EMPTY_INVENTORY_SHA256,
        "claimScope": OBSERVATION_SCOPE,
        "globalAbsenceEstablished": False,
        "auditImplementationSHA256": observation[
            "auditImplementationSHA256"
        ],
        "auditReportSHA256": observation["auditReportSHA256"],
        "auditorIdentity": observation["auditorIdentity"],
    }
    raw = _seal_document(
        _base_document(
            classification="NO_ATTEMPT_EXPIRED",
            classified_at=classified_at,
            publication_bindings=_publication_bindings(
                publication_bindings,
                evidence_receipt_sha256=None,
            ),
            basis=basis,
        )
    )
    verify_experiment_closeout(
        raw,
        expected_publication_bindings=publication_bindings,
        empty_result_root_observation_raw=empty_result_root_observation_raw,
    )
    return raw


def _load_original_evidence_receipt(raw: bytes) -> dict[str, Any]:
    receipt = _load_canonical_line(raw, label="evidence release receipt")
    fields = {
        "schemaVersion",
        "suiteId",
        "githubAPIVersion",
        "repository",
        "kind",
        "tag",
        "release",
        "source",
        "annotatedTag",
        "signatureVerification",
        "githubReleaseAttestation",
        "requiredAssets",
        "githubAPIResponses",
        "receiptCreatedAt",
        "contentSHA256",
    }
    if set(receipt) != fields:
        raise ExperimentCloseoutError("evidence release receipt fields differ")
    _verify_content_digest(receipt, label="evidence release receipt")
    release = receipt.get("release")
    if not isinstance(release, dict) or set(release) != {
        "id",
        "apiURL",
        "htmlURL",
        "publishedAt",
        "deadline",
    }:
        raise ExperimentCloseoutError("evidence release record fields differ")
    if (
        receipt.get("suiteId") != SUITE_ID
        or receipt.get("kind") != "evidence"
        or receipt.get("tag") != EVIDENCE_TAG
        or release.get("deadline") != EVIDENCE_PUBLICATION_DEADLINE
    ):
        raise ExperimentCloseoutError(
            "evidence release identity or registered deadline differs"
        )
    _utc(release["publishedAt"], label="evidence release publishedAt")
    return receipt


def verify_late_evidence_release_receipt(
    raw_receipt: bytes,
    asset_root: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_key_fingerprint: str,
    expected_public_key_sha256: str,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> tuple[VerifiedReleaseReceipt, Mapping[str, Any]]:
    """Reuse the strict normal verifier while preserving the original lateness."""

    _git_oid(expected_commit, label="expected evidence commit")
    _git_oid(expected_tree, label="expected evidence tree")
    if (
        not isinstance(expected_key_fingerprint, str)
        or SSH_FINGERPRINT.fullmatch(expected_key_fingerprint) is None
    ):
        raise ExperimentCloseoutError("expected SSH signing fingerprint is invalid")
    _digest(
        expected_public_key_sha256,
        label="expected signing public-key SHA-256",
    )
    original = _load_original_evidence_receipt(raw_receipt)

    try:
        verify_release_receipt(
            raw_receipt,
            asset_root,
            expected_repository=EVIDENCE_REPOSITORY,
            expected_kind="evidence",
            expected_tag=EVIDENCE_TAG,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            expected_deadline=EVIDENCE_PUBLICATION_DEADLINE,
            expected_signature_type=SIGNATURE_TYPE,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_public_key_sha256=expected_public_key_sha256,
            cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        )
    except ReleaseReceiptError:
        pass
    else:
        raise ExperimentCloseoutError(
            "evidence release is on time and cannot be classified as late"
        )

    try:
        verified = verify_late_release_receipt_for_closeout(
            raw_receipt,
            asset_root,
            expected_repository=EVIDENCE_REPOSITORY,
            expected_tag=EVIDENCE_TAG,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            expected_deadline=EVIDENCE_PUBLICATION_DEADLINE,
            expected_signature_type=SIGNATURE_TYPE,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_public_key_sha256=expected_public_key_sha256,
            cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        )
    except ReleaseReceiptError as error:
        raise ExperimentCloseoutError(
            "late evidence release receipt failed ordinary integrity verification"
        ) from error
    return verified, original


def _require_evidence_source_matches_bindings(
    publication_bindings: PublicationBindings,
    *,
    expected_commit: str,
    expected_tree: str,
) -> None:
    if (
        expected_commit != publication_bindings.closeout_source_commit
        or expected_tree != publication_bindings.closeout_source_tree
    ):
        raise ExperimentCloseoutError(
            "evidence publication source differs from frozen design lab source"
        )


def _late_basis(
    *,
    raw_receipt: bytes,
    verified: VerifiedReleaseReceipt,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    required_assets = receipt["requiredAssets"]
    if not isinstance(required_assets, list):
        raise ExperimentCloseoutError("evidence release assets are invalid")
    assets = [
        {
            "role": item["role"],
            "name": item["name"],
            "bytes": item["bytes"],
            "sha256": item["sha256"],
        }
        for item in required_assets
    ]
    return {
        "kind": "ARCHIVED_LATE_EVIDENCE_PUBLICATION",
        "evidenceReleaseReceiptSHA256": sha256_bytes(raw_receipt),
        "publishedAt": receipt["release"]["publishedAt"],
        "attestedAt": verified.attested_at,
        "deadline": EVIDENCE_PUBLICATION_DEADLINE,
        "latenessRelation": "ATTESTED_AT_OR_AFTER_DEADLINE",
        "repository": verified.repository,
        "tag": verified.tag,
        "commit": verified.commit,
        "tree": verified.tree,
        "signatureType": verified.signature_type,
        "keyFingerprint": verified.key_fingerprint,
        "publicKeySHA256": verified.public_key_sha256,
        "requiredAssets": assets,
    }


def create_late_publication_invalid(
    *,
    publication_bindings: PublicationBindings,
    evidence_release_receipt_raw: bytes,
    evidence_asset_root: Path,
    expected_commit: str,
    expected_tree: str,
    expected_key_fingerprint: str,
    expected_public_key_sha256: str,
    classified_at: str,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> bytes:
    """Create a closeout for a fully verified but server-late evidence release."""

    _require_evidence_source_matches_bindings(
        publication_bindings,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
    )
    verified, receipt = verify_late_evidence_release_receipt(
        evidence_release_receipt_raw,
        evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )
    classified = _utc(classified_at, label="classifiedAt")
    attested = _utc(
        verified.attested_at,
        label="evidence release attestedAt",
    )
    if classified < attested:
        raise ExperimentCloseoutError(
            "late-publication classification predates release attestation"
        )
    receipt_sha256 = sha256_bytes(evidence_release_receipt_raw)
    raw = _seal_document(
        _base_document(
            classification="LATE_PUBLICATION_INVALID",
            classified_at=classified_at,
            publication_bindings=_publication_bindings(
                publication_bindings,
                evidence_receipt_sha256=receipt_sha256,
            ),
            basis=_late_basis(
                raw_receipt=evidence_release_receipt_raw,
                verified=verified,
                receipt=receipt,
            ),
        )
    )
    verify_experiment_closeout(
        raw,
        expected_publication_bindings=publication_bindings,
        evidence_release_receipt_raw=evidence_release_receipt_raw,
        evidence_asset_root=evidence_asset_root,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )
    return raw


def _validate_common_closeout(
    closeout: Mapping[str, Any],
    *,
    expected_publication_bindings: PublicationBindings,
) -> None:
    fields = {
        "schemaVersion",
        "suiteId",
        "documentType",
        "classification",
        "classificationScope",
        "attemptTerminalOutcome",
        "attemptTerminalStatesExcluded",
        "doesNotModifyAttemptOutcome",
        "deadlines",
        "closeoutReleasePlan",
        "publicationBindings",
        "basis",
        "classifiedAt",
        "countsTowardScientificVerdict",
        "retryPermitted",
        "contentSHA256",
    }
    if set(closeout) != fields:
        raise ExperimentCloseoutError("experiment closeout fields differ")
    _verify_content_digest(closeout, label="experiment closeout")
    if (
        closeout["schemaVersion"] != SCHEMA_VERSION
        or closeout["suiteId"] != SUITE_ID
        or closeout["documentType"] != DOCUMENT_TYPE
        or closeout["classification"] not in CLASSIFICATIONS
        or closeout["classificationScope"] != CLASSIFICATION_SCOPE
        or closeout["attemptTerminalOutcome"] is not None
        or closeout["attemptTerminalStatesExcluded"]
        != list(ATTEMPT_TERMINAL_STATES)
        or closeout["doesNotModifyAttemptOutcome"] is not True
        or closeout["deadlines"] != DEADLINES
        or closeout["closeoutReleasePlan"] != CLOSEOUT_RELEASE_PLAN
        or closeout["countsTowardScientificVerdict"] is not False
        or closeout["retryPermitted"] is not False
    ):
        raise ExperimentCloseoutError("experiment closeout common boundary differs")
    classified_at = _utc(closeout["classifiedAt"], label="classifiedAt")
    if classified_at >= _utc(
        CLOSEOUT_PUBLICATION_DEADLINE,
        label="closeout publication deadline",
    ):
        raise ExperimentCloseoutError(
            "experiment closeout was classified at or after its release deadline"
        )
    bindings = closeout["publicationBindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "designRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotRegistrationSHA256",
        "snapshotPublicationReceiptSHA256",
        "evidenceReleaseReceiptSHA256",
        "closeoutSourceCommit",
        "closeoutSourceTree",
    }:
        raise ExperimentCloseoutError("experiment publication bindings differ")
    expected_base = expected_publication_bindings.as_dict(
        evidence_receipt_sha256=bindings.get("evidenceReleaseReceiptSHA256")
    )
    if bindings != expected_base:
        raise ExperimentCloseoutError("experiment publication digest binding differs")


def verify_experiment_closeout(
    raw: bytes,
    *,
    expected_publication_bindings: PublicationBindings,
    empty_result_root_observation_raw: bytes | None = None,
    evidence_release_receipt_raw: bytes | None = None,
    evidence_asset_root: Path | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_key_fingerprint: str | None = None,
    expected_public_key_sha256: str | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedExperimentCloseout:
    """Verify one closeout against independently supplied basis bytes."""

    closeout = _load_canonical_line(raw, label="experiment closeout")
    _validate_common_closeout(
        closeout,
        expected_publication_bindings=expected_publication_bindings,
    )
    classification = closeout["classification"]
    basis = closeout["basis"]
    if not isinstance(basis, dict):
        raise ExperimentCloseoutError("experiment closeout basis is not an object")

    if classification == "NO_ATTEMPT_EXPIRED":
        if (
            empty_result_root_observation_raw is None
            or evidence_release_receipt_raw is not None
            or evidence_asset_root is not None
            or any(
                value is not None
                for value in (
                    expected_commit,
                    expected_tree,
                    expected_key_fingerprint,
                    expected_public_key_sha256,
                )
            )
        ):
            raise ExperimentCloseoutError(
                "no-attempt verification requires only its explicit empty-root observation"
            )
        observation = validate_empty_result_root_observation(
            empty_result_root_observation_raw
        )
        expected_basis = {
            "kind": "AUDITED_EMPTY_OBSERVED_RESULT_ROOT",
            "emptyResultRootObservationSHA256": sha256_bytes(
                empty_result_root_observation_raw
            ),
            "observedAt": observation["observedAt"],
            "observationCreatedAt": observation["observationCreatedAt"],
            "observedHostEnvironmentSHA256": observation[
                "hostEnvironmentSHA256"
            ],
            "observedResultRootPathSHA256": observation[
                "resultRootPathSHA256"
            ],
            "rootDevice": observation["rootDevice"],
            "rootInode": observation["rootInode"],
            "entryCount": 0,
            "emptyInventorySHA256": EMPTY_INVENTORY_SHA256,
            "claimScope": OBSERVATION_SCOPE,
            "globalAbsenceEstablished": False,
            "auditImplementationSHA256": observation[
                "auditImplementationSHA256"
            ],
            "auditReportSHA256": observation["auditReportSHA256"],
            "auditorIdentity": observation["auditorIdentity"],
        }
        if basis != expected_basis:
            raise ExperimentCloseoutError("no-attempt closeout basis differs")
        if closeout["publicationBindings"]["evidenceReleaseReceiptSHA256"] is not None:
            raise ExperimentCloseoutError(
                "no-attempt closeout cannot bind an evidence release receipt"
            )
        if _utc(closeout["classifiedAt"], label="classifiedAt") < _utc(
            observation["observationCreatedAt"],
            label="observation observationCreatedAt",
        ):
            raise ExperimentCloseoutError(
                "no-attempt closeout predates its observation"
            )
        basis_sha256 = sha256_bytes(empty_result_root_observation_raw)
        evidence_receipt_sha256 = None
    else:
        if (
            empty_result_root_observation_raw is not None
            or evidence_release_receipt_raw is None
            or evidence_asset_root is None
            or not all(
                isinstance(value, str)
                for value in (
                    expected_commit,
                    expected_tree,
                    expected_key_fingerprint,
                    expected_public_key_sha256,
                )
            )
        ):
            raise ExperimentCloseoutError(
                "late-publication verification requires its exact receipt, assets, and signing/source expectations"
            )
        _require_evidence_source_matches_bindings(
            expected_publication_bindings,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
        verified, receipt = verify_late_evidence_release_receipt(
            evidence_release_receipt_raw,
            evidence_asset_root,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            expected_key_fingerprint=expected_key_fingerprint,
            expected_public_key_sha256=expected_public_key_sha256,
            cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        )
        expected_basis = _late_basis(
            raw_receipt=evidence_release_receipt_raw,
            verified=verified,
            receipt=receipt,
        )
        if basis != expected_basis:
            raise ExperimentCloseoutError("late-publication closeout basis differs")
        evidence_receipt_sha256 = sha256_bytes(evidence_release_receipt_raw)
        if (
            closeout["publicationBindings"]["evidenceReleaseReceiptSHA256"]
            != evidence_receipt_sha256
        ):
            raise ExperimentCloseoutError(
                "late-publication receipt digest binding differs"
            )
        if _utc(closeout["classifiedAt"], label="classifiedAt") < _utc(
            verified.attested_at,
            label="evidence release attestedAt",
        ):
            raise ExperimentCloseoutError(
                "late-publication closeout predates release attestation"
            )
        basis_sha256 = evidence_receipt_sha256

    return VerifiedExperimentCloseout(
        classification=classification,
        classified_at=closeout["classifiedAt"],
        closeout_sha256=sha256_bytes(raw),
        evidence_release_receipt_sha256=evidence_receipt_sha256,
        basis_sha256=basis_sha256,
    )


__all__ = [
    "AUDIT_REPORT_SCHEMA",
    "ATTEMPT_TERMINAL_STATES",
    "CLASSIFICATIONS",
    "CLOSEOUT_PUBLICATION_DEADLINE",
    "CLOSEOUT_RELEASE_PLAN",
    "CLOSEOUT_SIGNING_KEY_FINGERPRINT",
    "CLOSEOUT_SIGNING_PUBLIC_KEY_SHA256",
    "CLOSEOUT_TAG",
    "DEADLINES",
    "EMPTY_INVENTORY_SHA256",
    "EVIDENCE_PUBLICATION_DEADLINE",
    "EXECUTION_HARD_DEADLINE",
    "ExperimentCloseoutError",
    "OBSERVATION_SCOPE",
    "OBSERVATION_SCHEMA",
    "PublicationBindings",
    "VerifiedExperimentCloseout",
    "canonical_json_bytes",
    "collect_empty_result_root_observation",
    "create_late_publication_invalid",
    "create_no_attempt_expired",
    "sha256_bytes",
    "validate_empty_result_root_observation",
    "validate_empty_result_root_audit_report",
    "verify_experiment_closeout",
    "verify_late_evidence_release_receipt",
]
