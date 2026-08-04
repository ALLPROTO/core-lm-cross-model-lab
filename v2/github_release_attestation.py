#!/usr/bin/env python3
"""Parse and bind GitHub immutable-release attestations.

The online collector invokes one exact, pinned GitHub CLI binary.  That binary
performs the Sigstore verification and returns both the complete bundle and its
verification result.  This module performs a dependency-free offline replay of
all semantic bindings: DSSE payload, release identity, commit, complete asset
set, GitHub release signer identity, and verified RFC3161 timestamp.

The offline replay deliberately does not claim to reimplement X.509, ECDSA,
DSSE, or RFC3161 cryptography.  Fresh cryptographic verification is the pinned
``gh release verify`` collection step; the archived bundle remains available
for independent Sigstore tooling.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


GH_CLI_NAME = "gh"
GH_CLI_VERSION = "2.97.0"
GH_CLI_PLATFORM = "macOS-arm64"
GH_CLI_BINARY_BYTES = 38_857_376
GH_CLI_BINARY_SHA256 = (
    "0d17dddf96bcc1dc50f3420a064d593d64016b0be16286a6c26121f2a5cb8316"
)
GH_CLI_DISTRIBUTION_SHA256 = (
    "a58b8fd77b417a38f47a0b54d1370c59b0fcdb324ccc9ca002b0998f7c4c999e"
)
GH_CLI_DISTRIBUTION_URL = (
    "https://github.com/cli/cli/releases/download/v2.97.0/"
    "gh_2.97.0_macOS_arm64.zip"
)
GH_CLI_VERSION_OUTPUT = (
    "gh version 2.97.0 (2026-07-31)\n"
    "https://github.com/cli/cli/releases/tag/v2.97.0\n"
)
ATTESTATION_STATUS = "VERIFIED"
ATTESTATION_METHOD = "gh release verify --format json"
ATTESTATION_TRUST_POLICY = (
    "PINNED_GH_SIGSTORE_VERIFICATION_AT_COLLECTION;"
    "OFFLINE_SEMANTIC_BINDING_REPLAY"
)
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
VERIFICATION_RESULT_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
)
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
GITHUB_RELEASE_SAN = "https://dotcom.releases.github.com"
GITHUB_RELEASE_SAN_REGEXP = r"^https://dotcom\.releases\.github\.com$"
GITHUB_FULCIO_ISSUER = "CN=Fulcio Intermediate l1,O=GitHub\\, Inc."
GITHUB_TIMESTAMP_TYPE = "TimestampAuthority"
GITHUB_TIMESTAMP_URI = "timestamp.githubapp.com"
MAXIMUM_RAW_OUTPUT_BYTES = 16 * 1024 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class ReleaseAttestationError(ValueError):
    """The archived release attestation is missing or inconsistently bound."""


@dataclass(frozen=True)
class VerifiedReleaseAttestation:
    repository: str
    repository_id: int
    owner_id: int
    release_id: int
    tag: str
    commit: str
    attested_at: str
    bundle_sha256: str
    raw_output_sha256: str
    asset_sha256: tuple[tuple[str, str], ...]


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
        raise ReleaseAttestationError("attestation is not canonical JSON data") from error


def archived_bytes(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAXIMUM_RAW_OUTPUT_BYTES:
        raise ReleaseAttestationError("attestation output is empty or exceeds its bound")
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseAttestationError(f"{label} fields differ")
    return value


def _strict_json(raw: bytes, *, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReleaseAttestationError(f"duplicate key in {label}: {key}")
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseAttestationError(f"{label} is not strict JSON") from error


def _decode_base64(value: Any, *, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum_bytes + 2) // 3) * 4:
        raise ReleaseAttestationError(f"{label} base64 is invalid")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ReleaseAttestationError(f"{label} base64 is invalid") from error
    if not raw or len(raw) > maximum_bytes or base64.b64encode(raw).decode("ascii") != value:
        raise ReleaseAttestationError(f"{label} base64 is non-canonical")
    return raw


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise ReleaseAttestationError(f"{label} must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ReleaseAttestationError(f"{label} is not a real timestamp") from error


def _digest(value: Any, pattern: re.Pattern[str], *, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseAttestationError(f"{label} is invalid")
    return value


def _archived_raw(record: Mapping[str, Any]) -> bytes:
    archived = _mapping(
        record,
        {"encoding", "bytes", "sha256", "dataBase64"},
        label="attestation raw output",
    )
    if archived["encoding"] != "base64":
        raise ReleaseAttestationError("attestation raw output encoding differs")
    size = archived["bytes"]
    if type(size) is not int or not 0 < size <= MAXIMUM_RAW_OUTPUT_BYTES:
        raise ReleaseAttestationError("attestation raw output byte count is invalid")
    digest = _digest(archived["sha256"], SHA256, label="attestation output SHA-256")
    raw = _decode_base64(
        archived["dataBase64"],
        label="attestation raw output",
        maximum_bytes=MAXIMUM_RAW_OUTPUT_BYTES,
    )
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ReleaseAttestationError("attestation raw output commitment differs")
    return raw


def build_attestation_record(
    raw_output: bytes,
    offline_cryptographic_verification: Mapping[str, Any],
) -> dict[str, Any]:
    """Wrap exact successful pinned-CLI output for the release receipt."""

    if not isinstance(offline_cryptographic_verification, dict):
        raise ReleaseAttestationError(
            "offline cryptographic verification record is absent"
        )

    return {
        "status": ATTESTATION_STATUS,
        "method": ATTESTATION_METHOD,
        "trustPolicy": ATTESTATION_TRUST_POLICY,
        "tool": {
            "name": GH_CLI_NAME,
            "version": GH_CLI_VERSION,
            "platform": GH_CLI_PLATFORM,
            "binaryBytes": GH_CLI_BINARY_BYTES,
            "binarySHA256": GH_CLI_BINARY_SHA256,
            "distributionSHA256": GH_CLI_DISTRIBUTION_SHA256,
            "distributionURL": GH_CLI_DISTRIBUTION_URL,
        },
        "offlineCryptographicVerification": dict(
            offline_cryptographic_verification
        ),
        "rawVerificationOutput": archived_bytes(raw_output),
    }


def verify_attestation_record(
    value: Any,
    *,
    expected_repository: str,
    expected_release_id: int,
    expected_tag: str,
    expected_commit: str,
    expected_assets: Sequence[tuple[str, str]],
    expected_published_at: str,
    expected_receipt_created_at: str,
    expected_deadline: str,
    expected_attestation_relation: str,
) -> VerifiedReleaseAttestation:
    """Replay every semantic binding in one pinned-CLI verification output."""

    record = _mapping(
        value,
        {
            "status",
            "method",
            "trustPolicy",
            "tool",
            "offlineCryptographicVerification",
            "rawVerificationOutput",
        },
        label="GitHub release attestation",
    )
    if (
        record["status"] != ATTESTATION_STATUS
        or record["method"] != ATTESTATION_METHOD
        or record["trustPolicy"] != ATTESTATION_TRUST_POLICY
    ):
        raise ReleaseAttestationError("attestation verification policy differs")
    tool = _mapping(
        record["tool"],
        {
            "name",
            "version",
            "platform",
            "binaryBytes",
            "binarySHA256",
            "distributionSHA256",
            "distributionURL",
        },
        label="attestation tool",
    )
    if tool != {
        "name": GH_CLI_NAME,
        "version": GH_CLI_VERSION,
        "platform": GH_CLI_PLATFORM,
        "binaryBytes": GH_CLI_BINARY_BYTES,
        "binarySHA256": GH_CLI_BINARY_SHA256,
        "distributionSHA256": GH_CLI_DISTRIBUTION_SHA256,
        "distributionURL": GH_CLI_DISTRIBUTION_URL,
    }:
        raise ReleaseAttestationError("attestation tool is not the pinned verifier")

    raw = _archived_raw(record["rawVerificationOutput"])
    root = _mapping(
        _strict_json(raw, label="gh release verify output"),
        {"attestation", "verificationResult"},
        label="gh release verify output",
    )
    attestation = _mapping(
        root["attestation"],
        {"bundle", "bundle_url", "initiator"},
        label="GitHub attestation",
    )
    if not isinstance(attestation["bundle_url"], str) or not isinstance(
        attestation["initiator"], str
    ):
        raise ReleaseAttestationError("GitHub attestation metadata is invalid")
    bundle = _mapping(
        attestation["bundle"],
        {"mediaType", "dsseEnvelope", "verificationMaterial"},
        label="Sigstore bundle",
    )
    if bundle["mediaType"] != BUNDLE_MEDIA_TYPE:
        raise ReleaseAttestationError("Sigstore bundle media type differs")
    envelope = _mapping(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        label="DSSE envelope",
    )
    if envelope["payloadType"] != DSSE_PAYLOAD_TYPE:
        raise ReleaseAttestationError("DSSE payload type differs")
    payload_raw = _decode_base64(
        envelope["payload"], label="DSSE payload", maximum_bytes=4 * 1024 * 1024
    )
    statement = _strict_json(payload_raw, label="DSSE statement")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ReleaseAttestationError("DSSE signature inventory differs")
    signature = _mapping(signatures[0], {"sig"}, label="DSSE signature")
    _decode_base64(signature["sig"], label="DSSE signature", maximum_bytes=4096)

    material = _mapping(
        bundle["verificationMaterial"],
        {"certificate", "timestampVerificationData"},
        label="Sigstore verification material",
    )
    certificate = _mapping(material["certificate"], {"rawBytes"}, label="certificate")
    _decode_base64(certificate["rawBytes"], label="certificate", maximum_bytes=65536)
    timestamp_material = _mapping(
        material["timestampVerificationData"],
        {"rfc3161Timestamps"},
        label="timestamp verification material",
    )
    timestamps = timestamp_material["rfc3161Timestamps"]
    if not isinstance(timestamps, list) or len(timestamps) != 1:
        raise ReleaseAttestationError("RFC3161 timestamp inventory differs")
    timestamp_record = _mapping(
        timestamps[0], {"signedTimestamp"}, label="RFC3161 timestamp"
    )
    _decode_base64(
        timestamp_record["signedTimestamp"],
        label="RFC3161 timestamp",
        maximum_bytes=1024 * 1024,
    )

    result = _mapping(
        root["verificationResult"],
        {"mediaType", "signature", "statement", "verifiedIdentity", "verifiedTimestamps"},
        label="Sigstore verification result",
    )
    if result["mediaType"] != VERIFICATION_RESULT_MEDIA_TYPE or result["statement"] != statement:
        raise ReleaseAttestationError("verification result does not bind the DSSE statement")
    result_signature = _mapping(
        result["signature"], {"certificate"}, label="verified signature"
    )
    result_certificate = _mapping(
        result_signature["certificate"],
        {"certificateIssuer", "subjectAlternativeName"},
        label="verified certificate",
    )
    if result_certificate != {
        "certificateIssuer": GITHUB_FULCIO_ISSUER,
        "subjectAlternativeName": GITHUB_RELEASE_SAN,
    }:
        raise ReleaseAttestationError("verified release signer identity differs")
    identity = _mapping(
        result["verifiedIdentity"],
        {"subjectAlternativeName", "issuer"},
        label="verified identity policy",
    )
    san_policy = _mapping(
        identity["subjectAlternativeName"],
        {"subjectAlternativeName", "regexp"},
        label="SAN policy",
    )
    issuer_policy = _mapping(
        identity["issuer"], {"issuer", "regexp"}, label="issuer policy"
    )
    if san_policy != {"subjectAlternativeName": "", "regexp": GITHUB_RELEASE_SAN_REGEXP} or issuer_policy != {
        "issuer": "",
        "regexp": ".*",
    }:
        raise ReleaseAttestationError("verified release identity policy differs")
    verified_timestamps = result["verifiedTimestamps"]
    if not isinstance(verified_timestamps, list) or len(verified_timestamps) != 1:
        raise ReleaseAttestationError("verified timestamp inventory differs")
    verified_timestamp = _mapping(
        verified_timestamps[0],
        {"type", "uri", "timestamp"},
        label="verified timestamp",
    )
    if (
        verified_timestamp["type"] != GITHUB_TIMESTAMP_TYPE
        or verified_timestamp["uri"] != GITHUB_TIMESTAMP_URI
    ):
        raise ReleaseAttestationError("verified timestamp authority differs")
    attested_at = _utc(verified_timestamp["timestamp"], label="attestedAt")
    published_at = _utc(expected_published_at, label="publishedAt observation")
    receipt_created = _utc(expected_receipt_created_at, label="receiptCreatedAt")
    deadline = _utc(expected_deadline, label="release deadline")
    if attested_at < published_at or attested_at > receipt_created:
        raise ReleaseAttestationError("verified release timestamp is outside its allowed window")
    if expected_attestation_relation == "STRICTLY_BEFORE_DEADLINE":
        if attested_at >= deadline:
            raise ReleaseAttestationError(
                "verified release timestamp is not before the deadline"
            )
    elif expected_attestation_relation == "AT_OR_AFTER_DEADLINE":
        if attested_at < deadline:
            raise ReleaseAttestationError(
                "verified release timestamp is not at or after the deadline"
            )
    else:
        raise ReleaseAttestationError("attestation deadline relation is unsupported")

    statement_record = _mapping(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        label="release statement",
    )
    if statement_record["_type"] != STATEMENT_TYPE or statement_record["predicateType"] != RELEASE_PREDICATE_TYPE:
        raise ReleaseAttestationError("release statement type differs")
    predicate = _mapping(
        statement_record["predicate"],
        {"databaseId", "ownerId", "packageId", "purl", "repository", "repositoryId", "tag"},
        label="release predicate",
    )
    if type(expected_release_id) is not int or expected_release_id <= 0:
        raise ReleaseAttestationError("expected release ID is invalid")
    if expected_repository.count("/") != 1:
        raise ReleaseAttestationError("expected repository is invalid")
    expected_purl = f"pkg:github/{expected_repository}@{expected_tag}"
    if (
        predicate["databaseId"] != str(expected_release_id)
        or predicate["repository"] != expected_repository
        or predicate["tag"] != expected_tag
        or predicate["purl"] != expected_purl
        or predicate["packageId"] != predicate["repositoryId"]
    ):
        raise ReleaseAttestationError("release predicate identity differs")
    try:
        repository_id = int(predicate["repositoryId"], 10)
        owner_id = int(predicate["ownerId"], 10)
    except (TypeError, ValueError) as error:
        raise ReleaseAttestationError("release predicate numeric identity is invalid") from error
    if repository_id <= 0 or owner_id <= 0 or str(repository_id) != predicate["repositoryId"] or str(owner_id) != predicate["ownerId"]:
        raise ReleaseAttestationError("release predicate numeric identity is non-canonical")

    subjects = statement_record["subject"]
    if not isinstance(subjects, list) or len(subjects) < 2:
        raise ReleaseAttestationError("release subject inventory is incomplete")
    release_subject = _mapping(subjects[0], {"uri", "digest"}, label="release subject")
    release_digest = _mapping(release_subject["digest"], {"sha1"}, label="release digest")
    commit = _digest(release_digest["sha1"], SHA1, label="release commit")
    if release_subject["uri"] != expected_purl or commit != expected_commit:
        raise ReleaseAttestationError("release subject does not bind the expected commit")
    expected_asset_map = dict(expected_assets)
    if len(expected_asset_map) != len(expected_assets) or not expected_asset_map:
        raise ReleaseAttestationError("expected release asset inventory is invalid")
    observed_assets: dict[str, str] = {}
    for index, subject in enumerate(subjects[1:], start=1):
        item = _mapping(subject, {"name", "digest"}, label=f"asset subject {index}")
        name = item["name"]
        digest_record = _mapping(item["digest"], {"sha256"}, label=f"asset digest {index}")
        digest = _digest(digest_record["sha256"], SHA256, label=f"asset SHA-256 {index}")
        if not isinstance(name, str) or not name or name in observed_assets:
            raise ReleaseAttestationError("release asset subject name is invalid or duplicated")
        observed_assets[name] = digest
    if observed_assets != expected_asset_map:
        raise ReleaseAttestationError("release attestation asset set/digests differ")

    bundle_sha256 = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
    return VerifiedReleaseAttestation(
        repository=expected_repository,
        repository_id=repository_id,
        owner_id=owner_id,
        release_id=expected_release_id,
        tag=expected_tag,
        commit=expected_commit,
        attested_at=attested_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        bundle_sha256=bundle_sha256,
        raw_output_sha256=hashlib.sha256(raw).hexdigest(),
        asset_sha256=tuple(sorted(observed_assets.items(), key=lambda item: item[0].encode())),
    )


__all__ = [
    "ATTESTATION_METHOD",
    "ATTESTATION_STATUS",
    "ATTESTATION_TRUST_POLICY",
    "GH_CLI_BINARY_BYTES",
    "GH_CLI_BINARY_SHA256",
    "GH_CLI_DISTRIBUTION_SHA256",
    "GH_CLI_DISTRIBUTION_URL",
    "GH_CLI_NAME",
    "GH_CLI_PLATFORM",
    "GH_CLI_VERSION",
    "GH_CLI_VERSION_OUTPUT",
    "ReleaseAttestationError",
    "VerifiedReleaseAttestation",
    "archived_bytes",
    "build_attestation_record",
    "canonical_json_bytes",
    "verify_attestation_record",
]
