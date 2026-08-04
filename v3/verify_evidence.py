#!/usr/bin/env python3
"""Recompute the complete blind-v3 verdict from frozen raw evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import socket
import sys
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.evidence import (  # noqa: E402
    EvidenceError,
    load_canonical_jsonl_beneath,
    read_evidence_file,
    require_manifest_paths,
    verify_sha256_manifest,
)
from v3.create_sbom import build_sbom  # noqa: E402
from v3.git_source import GitSourceError, verify_copied_source  # noqa: E402
from v3.github_gate_receipt import (  # noqa: E402
    GitHubGateReceiptError,
    verify_github_gate_receipt,
)
from v3.freeze_manifest import (  # noqa: E402
    FreezeManifestError,
    _gate_manifest_sections,
    validate_freeze_manifest as validate_freeze_manifest_contract,
)
from v3.independent_verifier_core import (  # noqa: E402
    IndependentVerificationError,
    TARGET_ENDPOINT,
    TARGET_UNIX_MILLISECONDS,
    canonical_nist_verification_bytes,
    decode_float32_bits,
    derive_selection,
    evaluate_evidence,
    extract_ledger_token_commitments,
    load_independent_trust_bundle,
    validate_worker_job,
    verify_nist_response,
    verify_page_token_bindings,
)
from v3.independent_model_replay import (  # noqa: E402
    IndependentModelReplayError,
    run_independent_model_replay,
)
from v3.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict_bytes,
    validate_frozen_design_registration,
    validate_model_asset_manifest,
)
from v3.package_design_release import (  # noqa: E402
    DesignReleaseError,
    verify_design_release_package,
)
from v3.publication import (  # noqa: E402
    PublicationError,
    require_frozen_lab_publication_source,
    verify_publication,
)
from v3.release_attestation_crypto import (  # noqa: E402
    PinnedCosignReleaseAttestationVerifier,
)
from v3.release_receipt import (  # noqa: E402
    ReleaseAttestationCryptographicVerifier,
)
from v3.state_machine import (  # noqa: E402
    ATTEMPT_FILENAME,
    RESERVATION_FILENAME,
    StateMachineError,
    load_attempt_marker,
)


SELECTION_PATH = "selection.json"
NIST_REQUEST_URI_PATH = "nist/request-uri.txt"
NIST_RESPONSE_HEADERS_PATH = "nist/response-headers.bin"
NIST_RESPONSE_BODY_PATH = "nist/response-body.json"
NIST_VERIFICATION_PATH = "nist/verification.json"
PRIVATE_SNAPSHOT_MANIFEST_PATH = "private-snapshot-manifest.json"
HOST_ENVIRONMENT_PATH = "environment/host-preflight.json"

RESERVATION_MARKER_BINDING_FIELDS = (
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


def install_network_denial() -> None:
    def deny_audit(event: str, _arguments: tuple[Any, ...]) -> None:
        if event.startswith("socket."):
            raise EvidenceError(f"network forbidden in independent verifier: {event}")

    sys.addaudithook(deny_audit)

    class DeniedSocket:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise EvidenceError("network forbidden in independent verifier")

    socket.socket = DeniedSocket  # type: ignore[assignment]
    socket.create_connection = DeniedSocket  # type: ignore[assignment]


def read_external_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read a bounded external input without following a final or parent symlink."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name:
        raise EvidenceError("external evidence path has no file name")
    return read_evidence_file(
        absolute.parent,
        absolute.name,
        maximum_bytes=maximum_bytes,
    )


def validate_frozen_design(design: Any) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise EvidenceError(
            "locked independent-verifier runtime lacks jsonschema"
        ) from error
    schema_raw = read_evidence_file(
        V3_ROOT,
        "schemas/design.schema.json",
        maximum_bytes=2 * 1024 * 1024,
    )
    schema = load_json_strict_bytes(schema_raw, label="canonical design schema")
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(design),
        key=lambda item: list(item.path),
    )
    if schema_errors:
        first = schema_errors[0]
        location = "$" + "".join(f"[{part!r}]" for part in first.path)
        raise EvidenceError(
            f"design.schema.json validation failed at {location}: {first.message}"
        )
    try:
        validate_frozen_design_registration(design)
    except (TypeError, ValueError) as error:
        raise EvidenceError(
            f"frozen design fails exhaustive normative validation: {error}"
        ) from error
    if not isinstance(design, dict):
        raise EvidenceError("design registration must be an object")
    if design.get("suiteId") != "corelm-voidtoken-crossmodel-livewiki-v3-author-verified":
        raise EvidenceError("design suiteId differs")
    if design.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-design-v1":
        raise EvidenceError("scientific evidence requires the canonical frozen design schema")
    if design.get("status") != "PUBLIC_DESIGN_FROZEN":
        raise EvidenceError("scientific evidence requires a public frozen design")
    if design.get("readyToFreeze") is not True:
        raise EvidenceError("frozen design does not declare verified readiness")
    if design.get("countsTowardScientificVerdict") is not False:
        raise EvidenceError("design registration must not itself claim a verdict")
    if design.get("freezeBlockers") not in ([], None):
        raise EvidenceError("frozen design still contains freeze blockers")
    lab = design.get("labSource")
    runtime = design.get("runtime")
    beacon = design.get("beacon")
    if not isinstance(lab, dict) or not isinstance(runtime, dict) or not isinstance(beacon, dict):
        raise EvidenceError("frozen source/runtime bindings are absent")
    if lab.get("status") != "FROZEN_BOUND" or runtime.get("status") != "FROZEN_BOUND":
        raise EvidenceError("frozen source/runtime statuses are not bound")
    if (
        beacon.get("pulseVersion") != "2.0"
        or beacon.get("pulseCipherSuite") != 0
        or beacon.get("pulsePeriodMilliseconds") != 60000
        or beacon.get("nistTrustRootDERsSHA256")
        != ["cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"]
    ):
        raise EvidenceError("frozen NIST pulse profile differs")
    for value, label, length in (
        (lab.get("commit"), "lab commit", 40),
        (lab.get("tree"), "lab tree", 40),
        (lab.get("freezeManifestSHA256"), "freeze manifest", 64),
        (runtime.get("runtimeManifestSHA256"), "runtime manifest", 64),
        (beacon.get("transportCABundleSHA256"), "transport CA bundle", 64),
        (beacon.get("offlineTrustBundleSHA256"), "offline trust bundle", 64),
    ):
        if not isinstance(value, str) or re.fullmatch(
            rf"[0-9a-f]{{{length}}}", value
        ) is None:
            raise EvidenceError(f"frozen {label} binding is invalid")
    release_identities: list[tuple[str, str]] = []
    for field in (
        "designRelease",
        "snapshotRelease",
        "evidenceRelease",
        "closeoutRelease",
    ):
        release = design.get(field)
        if (
            not isinstance(release, dict)
            or release.get("sourcePolicy")
            != "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE"
            or release.get("signedAnnotatedTagRequired") is not True
            or release.get("signatureType") != "SSH"
            or not isinstance(release.get("signingKeyFingerprint"), str)
            or re.fullmatch(
                r"SHA256:[A-Za-z0-9+/]{43}", release["signingKeyFingerprint"]
            )
            is None
            or not isinstance(release.get("signingPublicKeySHA256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", release["signingPublicKeySHA256"])
            is None
        ):
            raise EvidenceError(f"frozen {field} signing identity is invalid")
        release_identities.append(
            (release["signingKeyFingerprint"], release["signingPublicKeySHA256"])
        )
    if len(set(release_identities)) != 1:
        raise EvidenceError("frozen release signing identities differ")


def verify_registered_ci_workflow_bytes(
    lab_root: Path,
    design: dict[str, Any],
) -> str:
    """Reopen and verify the exact registered workflow from the sealed lab tree."""

    ci = design.get("continuousIntegration")
    if not isinstance(ci, dict):
        raise EvidenceError("frozen continuous-integration binding is absent")
    path = ci.get("workflowPath")
    expected_bytes = ci.get("workflowFileBytes")
    expected_digest = ci.get("workflowFileSHA256")
    if (
        not isinstance(path, str)
        or type(expected_bytes) is not int
        or not isinstance(expected_digest, str)
    ):
        raise EvidenceError("frozen continuous-integration byte binding is invalid")
    try:
        raw = read_evidence_file(
            lab_root,
            path,
            maximum_bytes=expected_bytes,
        )
    except EvidenceError as error:
        raise EvidenceError(
            "registered CI workflow bytes differ from the sealed lab source"
        ) from error
    observed_digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_bytes or observed_digest != expected_digest:
        raise EvidenceError(
            "registered CI workflow bytes differ from the sealed lab source"
        )
    return observed_digest


def validate_marker_design_bindings(
    marker: dict[str, Any], design: dict[str, Any]
) -> None:
    expected = {
        "codecCommit": design["codecSource"]["commit"],
        "codecTree": design["codecSource"]["tree"],
        "labCommit": design["labSource"]["commit"],
        "labTree": design["labSource"]["tree"],
        "runtimeManifestSHA256": design["runtime"]["runtimeManifestSHA256"],
    }
    for marker_field, design_value in expected.items():
        if marker.get(marker_field) != design_value:
            raise EvidenceError(
                f"attempt marker {marker_field} differs from the frozen design"
            )


def validate_model_replay_summary(
    summary: Any,
    *,
    marker: dict[str, Any],
    design: dict[str, Any],
    selection: dict[str, Any],
) -> str:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise EvidenceError(
            "locked independent-verifier runtime lacks jsonschema"
        ) from error
    schema_raw = read_evidence_file(
        V3_ROOT,
        "schemas/independent-model-replay.schema.json",
        maximum_bytes=2 * 1024 * 1024,
    )
    schema = load_json_strict_bytes(
        schema_raw, label="canonical independent-model-replay schema"
    )
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(summary),
        key=lambda item: list(item.path),
    )
    if schema_errors:
        first = schema_errors[0]
        location = "$" + "".join(f"[{part!r}]" for part in first.path)
        raise EvidenceError(
            "independent-model-replay.schema.json validation failed at "
            f"{location}: {first.message}"
        )
    if not isinstance(summary, dict):
        raise EvidenceError("independent model replay summary is not an object")
    unsigned = dict(summary)
    content_digest = unsigned.pop("contentSHA256")
    observed_digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if content_digest != observed_digest:
        raise EvidenceError("independent model replay summary self-digest differs")
    expected_containers = 32 * sum(item["layers"] for item in design["models"])
    replay_models = summary["models"]
    design_models = {item["key"]: item for item in design["models"]}
    if (
        summary["suiteId"] != marker["suiteId"]
        or summary["attemptId"] != marker["attemptId"]
        or summary["modelOrder"] != selection["modelExecutionOrder"]
        or summary["selectedCorpora"] != selection["selectedCorpora"]
        or summary["totalReplayedPages"] != 96
        or summary["totalReplayedPredictions"] != 96 * 128
        or summary["totalReplayedContainers"] != expected_containers
        or [item["modelKey"] for item in replay_models]
        != selection["modelExecutionOrder"]
        or any(
            item["replayedContainers"]
            != 32 * design_models[item["modelKey"]]["layers"]
            or item["weightSHA256"]
            != design_models[item["modelKey"]]["weightSHA256"]
            for item in replay_models
        )
    ):
        raise EvidenceError("independent model replay coverage/binding differs")
    return content_digest


def verify_codec_required_files(codec_root: Path, design: dict[str, Any]) -> str:
    source = design.get("codecSource")
    files = source.get("requiredFiles") if isinstance(source, dict) else None
    if not isinstance(files, dict) or not files:
        raise EvidenceError("frozen design has no codec required-file commitments")
    commitments: list[dict[str, Any]] = []
    for relative_path in sorted(files):
        specification = files[relative_path]
        if not isinstance(specification, dict) or set(specification) != {
            "bytes",
            "sha256",
        }:
            raise EvidenceError("codec required-file commitment fields differ")
        size = specification["bytes"]
        digest = specification["sha256"]
        if type(size) is not int or not 1 <= size <= 128 * 1024 * 1024:
            raise EvidenceError("codec required-file byte count is invalid")
        raw = read_evidence_file(
            codec_root,
            relative_path,
            maximum_bytes=size,
        )
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise EvidenceError(f"codec required-file commitment differs: {relative_path}")
        commitments.append(
            {"path": relative_path, "bytes": size, "sha256": digest}
        )
    return hashlib.sha256(canonical_json_bytes(commitments)).hexdigest()


def verify_manifested_source_tree(
    root: Path,
    private_manifest: dict[str, Any],
    *,
    prefix: str,
    role: str,
) -> str:
    """Match an executable private source tree to every sealed file entry."""

    absolute_root = Path(os.path.abspath(os.fspath(root)))
    try:
        root_metadata = os.lstat(absolute_root)
    except OSError as error:
        raise EvidenceError(f"private {role} root is missing") from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError(f"private {role} root is not a real directory")
    expected: dict[str, dict[str, Any]] = {}
    marker = prefix + "/"
    for entry in private_manifest["files"]:
        path = entry["path"]
        if entry["role"] == role:
            if not path.startswith(marker):
                raise EvidenceError(f"private {role} entry has the wrong prefix")
            relative = path[len(marker) :]
            if not relative or relative in expected:
                raise EvidenceError(f"private {role} entry is duplicated")
            expected[relative] = entry
    if not expected:
        raise EvidenceError(f"private snapshot has no {role} entries")
    observed: set[str] = set()
    for directory, child_directories, filenames in os.walk(
        absolute_root, topdown=True, followlinks=False
    ):
        for child in child_directories:
            metadata = os.lstat(Path(directory) / child)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceError(f"private {role} contains a directory symlink")
        for filename in filenames:
            path = Path(directory) / filename
            relative = path.relative_to(absolute_root).as_posix()
            entry = expected.get(relative)
            if entry is None:
                raise EvidenceError(f"private {role} contains an unmanifested file: {relative}")
            raw = read_evidence_file(
                absolute_root,
                relative,
                maximum_bytes=entry["bytes"],
            )
            if (
                len(raw) != entry["bytes"]
                or hashlib.sha256(raw).hexdigest() != entry["sha256"]
            ):
                raise EvidenceError(f"private {role} file commitment differs: {relative}")
            observed.add(relative)
    missing = sorted(set(expected) - observed)
    if missing:
        raise EvidenceError(f"private {role} files are missing: {', '.join(missing)}")
    commitments = [
        {
            "path": relative,
            "bytes": expected[relative]["bytes"],
            "sha256": expected[relative]["sha256"],
        }
        for relative in sorted(expected, key=os.fsencode)
    ]
    return hashlib.sha256(canonical_json_bytes(commitments)).hexdigest()


def verify_git_source_identity(
    source_root: Path,
    private_manifest: dict[str, Any],
    *,
    prefix: str,
    manifest_field: str,
    commit_field: str,
    tree_field: str,
) -> str:
    """Reconstruct an exported source tree from its sealed Git object proof."""

    relative = f"bindings/{prefix}-source-manifest.json"
    matching = [
        entry for entry in private_manifest["files"] if entry["path"] == relative
    ]
    if len(matching) != 1:
        raise EvidenceError(f"private {prefix} Git-source manifest is absent")
    raw = read_external_file(
        source_root.parent / relative,
        maximum_bytes=64 * 1024 * 1024,
    )
    observed_sha = hashlib.sha256(raw).hexdigest()
    if (
        len(raw) != matching[0]["bytes"]
        or observed_sha != matching[0]["sha256"]
        or observed_sha != private_manifest[manifest_field]
    ):
        raise EvidenceError(f"private {prefix} Git-source manifest differs")
    try:
        verify_copied_source(
            source_root,
            raw,
            expected_commit=private_manifest[commit_field],
            expected_tree=private_manifest[tree_field],
        )
    except GitSourceError as error:
        raise EvidenceError(
            f"private {prefix} source does not reconstruct its Git identity: {error}"
        ) from error
    return observed_sha


def verify_private_snapshot_manifest(
    evidence_root: Path,
    marker: dict[str, Any],
    design: dict[str, Any],
) -> dict[str, Any]:
    raw = read_evidence_file(
        evidence_root,
        PRIVATE_SNAPSHOT_MANIFEST_PATH,
        maximum_bytes=64 * 1024 * 1024,
    )
    if hashlib.sha256(raw).hexdigest() != marker["privateSnapshotManifestSHA256"]:
        raise EvidenceError("private snapshot manifest differs from the attempt marker")
    value = load_canonical_line(raw, label="private snapshot manifest")
    if not isinstance(value, dict):
        raise EvidenceError("private snapshot manifest must contain an object")
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "status",
        "createdAt",
        "countsTowardScientificVerdict",
        "designSHA256",
        "snapshotRegistrationSHA256",
        "designPublicationReceiptSHA256",
        "snapshotPublicationReceiptSHA256",
        "signingPublicKeySHA256",
        "runtimeManifestSHA256",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "corpusManifestSHA256",
        "freezeManifestSHA256",
        "githubGateReceiptSHA256",
        "transportCABundleSHA256",
        "offlineTrustBundleSHA256",
        "cosignBinarySHA256",
        "labCommit",
        "labTree",
        "codecCommit",
        "codecTree",
        "labSourceManifestSHA256",
        "codecSourceManifestSHA256",
        "files",
        "contentSHA256",
    }
    if set(value) != expected_fields:
        raise EvidenceError("private snapshot manifest fields differ")
    if (
        value["schemaVersion"]
        != "corelm-crossmodel-livewiki-v3-private-snapshot-manifest-v1"
        or value["suiteId"] != marker["suiteId"]
        or value["status"] != "SEALED_BEFORE_ATTEMPT"
        or value["countsTowardScientificVerdict"] is not False
    ):
        raise EvidenceError("private snapshot manifest identity/state differs")
    content = dict(value)
    content_digest = content.pop("contentSHA256")
    if (
        not isinstance(content_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", content_digest) is None
        or hashlib.sha256(canonical_json_bytes(content)).hexdigest()
        != content_digest
    ):
        raise EvidenceError("private snapshot manifest content digest differs")
    created_at = value["createdAt"]
    if (
        not isinstance(created_at, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            created_at,
        )
        is None
        or created_at > marker["createdAt"]
    ):
        raise EvidenceError("private snapshot was not sealed before the attempt")
    expected_bindings = {
        "designSHA256": marker["designSHA256"],
        "snapshotRegistrationSHA256": marker["snapshotRegistrationSHA256"],
        "designPublicationReceiptSHA256": marker[
            "designPublicationReceiptSHA256"
        ],
        "snapshotPublicationReceiptSHA256": marker[
            "snapshotPublicationReceiptSHA256"
        ],
        "signingPublicKeySHA256": design["designRelease"][
            "signingPublicKeySHA256"
        ],
        "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
        "modelAssetSourceManifestSHA256": marker[
            "modelAssetSourceManifestSHA256"
        ],
        "fullAssetReceiptSHA256": marker["fullAssetReceiptSHA256"],
        "corpusManifestSHA256": marker["corpusManifestSHA256"],
        "freezeManifestSHA256": design["labSource"]["freezeManifestSHA256"],
        "githubGateReceiptSHA256": marker["githubGateReceiptSHA256"],
        "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
        "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
        "labCommit": marker["labCommit"],
        "labTree": marker["labTree"],
        "codecCommit": marker["codecCommit"],
        "codecTree": marker["codecTree"],
    }
    for field, expected in expected_bindings.items():
        if value[field] != expected:
            raise EvidenceError(f"private snapshot binding differs: {field}")
    for field in (
        "labSourceManifestSHA256",
        "codecSourceManifestSHA256",
        "cosignBinarySHA256",
    ):
        if (
            not isinstance(value[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
        ):
            raise EvidenceError(f"private snapshot binding is invalid: {field}")
    allowed_roles = {
        "asset-source-manifest",
        "codec-source-manifest",
        "codec-source",
        "corpus-manifest",
        "design-publication-receipt",
        "design-release-asset",
        "development-control-archive-asset",
        "development-control-archive-receipt",
        "development-control-artifact",
        "development-control-report",
        "eligible-corpus-record",
        "eligible-ledger",
        "freeze-manifest",
        "frozen-design",
        "frozen-snapshot-registration",
        "full-asset-manifest",
        "github-gate-receipt",
        "lab-source",
        "lab-source-manifest",
        "model-asset",
        "nist-certificate-chain",
        "nist-trust-manifest",
        "pinned-cosign-binary",
        "release-signing-public-key",
        "runtime-manifest",
        "snapshot-publication-receipt",
        "snapshot-release-asset",
        "transport-ca-bundle",
    }
    files = value["files"]
    if not isinstance(files, list) or not files:
        raise EvidenceError("private snapshot manifest has no file entries")
    previous: bytes | None = None
    paths: set[str] = set()
    observed_roles: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "bytes",
            "sha256",
            "role",
        }:
            raise EvidenceError("private snapshot file entry fields differ")
        path = entry["path"]
        if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
            raise EvidenceError("private snapshot path is invalid")
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or str(relative) != path
            or ".." in relative.parts
            or any(part in {"", "."} for part in relative.parts)
        ):
            raise EvidenceError("private snapshot path is not canonical")
        encoded_path = os.fsencode(path)
        if previous is not None and encoded_path <= previous:
            raise EvidenceError("private snapshot file paths are not strictly sorted")
        previous = encoded_path
        if path in paths:
            raise EvidenceError("private snapshot contains a duplicate path")
        paths.add(path)
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] < 1
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
            or entry["role"] not in allowed_roles
        ):
            raise EvidenceError("private snapshot file entry value is invalid")
        observed_roles.add(entry["role"])
    if observed_roles != allowed_roles:
        missing = sorted(allowed_roles - observed_roles)
        extra = sorted(observed_roles - allowed_roles)
        raise EvidenceError(
            "private snapshot role coverage differs: "
            f"missing={missing!r}, extra={extra!r}"
        )
    cosign_entries = [
        entry
        for entry in files
        if entry["role"] == "pinned-cosign-binary"
    ]
    if (
        len(cosign_entries) != 1
        or cosign_entries[0]["path"] != "tools/cosign"
        or cosign_entries[0]["sha256"] != value["cosignBinarySHA256"]
    ):
        raise EvidenceError("private pinned Cosign binding differs")
    return value


def _github_repository_slug(repository: Any) -> str:
    if not isinstance(repository, str):
        raise EvidenceError("freeze implementation repository is invalid")
    parsed = urlsplit(repository)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceError("freeze implementation repository is not canonical GitHub HTTPS")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if path.count("/") != 1 or not all(path.split("/")):
        raise EvidenceError("freeze implementation repository slug is invalid")
    return path


def _private_committed_file(
    private_root: Path,
    private_manifest: dict[str, Any],
    relative_path: str,
    *,
    role: str,
    maximum_bytes: int,
) -> bytes:
    matches = [
        entry
        for entry in private_manifest["files"]
        if entry["path"] == relative_path and entry["role"] == role
    ]
    if len(matches) != 1:
        raise EvidenceError(f"private snapshot lacks exact {role} entry")
    entry = matches[0]
    if entry["bytes"] > maximum_bytes:
        raise EvidenceError(f"private {role} exceeds its verifier bound")
    raw = read_evidence_file(
        private_root, relative_path, maximum_bytes=maximum_bytes
    )
    if (
        len(raw) != entry["bytes"]
        or hashlib.sha256(raw).hexdigest() != entry["sha256"]
    ):
        raise EvidenceError(f"private {role} differs from its sealed commitment")
    return raw


def verify_github_gate_binding(
    private_root: Path,
    private_manifest: dict[str, Any],
    *,
    marker: dict[str, Any],
    design: dict[str, Any],
) -> str:
    """Replay archived author/CI bytes and bind them to the frozen implementation."""

    gate_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/github-gate-receipt.json",
        role="github-gate-receipt",
        maximum_bytes=128 * 1024 * 1024,
    )
    gate_sha256 = hashlib.sha256(gate_raw).hexdigest()
    if (
        gate_sha256 != private_manifest["githubGateReceiptSHA256"]
        or gate_sha256 != marker["githubGateReceiptSHA256"]
    ):
        raise EvidenceError("GitHub gate receipt digest binding differs")
    freeze_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/freeze-manifest.json",
        role="freeze-manifest",
        maximum_bytes=2 * 1024 * 1024,
    )
    if hashlib.sha256(freeze_raw).hexdigest() != design["labSource"][
        "freezeManifestSHA256"
    ]:
        raise EvidenceError("private freeze manifest differs from the frozen design")
    freeze = load_canonical_line(freeze_raw, label="freeze manifest")
    try:
        validate_freeze_manifest_contract(freeze)
    except FreezeManifestError as error:
        raise EvidenceError(f"freeze manifest failed canonical verification: {error}") from error
    if freeze["suiteId"] != design["suiteId"]:
        raise EvidenceError("freeze manifest suite differs from frozen design")
    expected_implementation = {
        "repository": design["labSource"]["repository"],
        "commit": design["labSource"]["commit"],
        "tree": design["labSource"]["tree"],
    }
    expected_codec = {
        "repository": design["codecSource"]["repository"],
        "commit": design["codecSource"]["commit"],
        "tree": design["codecSource"]["tree"],
    }
    if freeze["implementation"] != expected_implementation:
        raise EvidenceError("freeze implementation identity differs from design")
    if freeze["codec"] != expected_codec:
        raise EvidenceError("freeze codec identity differs from design")
    expected_artifacts = {
        "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
        "fullAssetReceiptSHA256": marker["fullAssetReceiptSHA256"],
        "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
        "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
        "githubGateReceiptSHA256": gate_sha256,
    }
    for field, value in expected_artifacts.items():
        if freeze["artifacts"].get(field) != value:
            raise EvidenceError(f"freeze artifact binding differs: {field}")
    author_verification = freeze["authorVerification"]
    ci = freeze["continuousIntegration"]
    if not isinstance(author_verification, dict) or not isinstance(ci, dict):
        raise EvidenceError("freeze author-verification/CI statements are absent")
    try:
        verified = verify_github_gate_receipt(
            gate_raw,
            expected_repository=_github_repository_slug(
            expected_implementation["repository"]
            ),
            expected_pull_request_number=author_verification["pullRequestNumber"],
            expected_implementation_commit=expected_implementation["commit"],
            expected_workflow_run_id=ci["runId"],
            expected_workflow_name=ci["workflowName"],
            expected_workflow_path=ci["workflowPath"],
        )
    except (GitHubGateReceiptError, KeyError, TypeError) as error:
        raise EvidenceError(
            f"archived GitHub author/CI gate failed offline replay: {error}"
        ) from error
    expected_author_verification, expected_ci = _gate_manifest_sections(
        verified,
        implementation_repository=expected_implementation["repository"],
    )
    if (
        author_verification != expected_author_verification
        or ci != expected_ci
    ):
        raise EvidenceError(
            "freeze author-verification/CI statements differ from archived GitHub bytes"
        )
    if verified.receipt_sha256 != gate_sha256:
        raise EvidenceError("GitHub gate verifier digest differs")
    return gate_sha256


def verify_host_environment(
    evidence_root: Path,
    *,
    marker: dict[str, Any],
    design: dict[str, Any],
) -> dict[str, Any]:
    raw = read_evidence_file(
        evidence_root, HOST_ENVIRONMENT_PATH, maximum_bytes=128 * 1024
    )
    value = load_canonical_line(raw, label="host environment")
    fields = {
        "schemaVersion",
        "suiteId",
        "observedAt",
        "system",
        "machine",
        "osProductVersion",
        "osBuildVersion",
        "kernelRelease",
        "kernelVersion",
        "cpuBrand",
        "logicalCPUCount",
        "physicalMemoryBytes",
        "pythonVersion",
        "pythonExecutableSHA256",
        "effectiveExecutionEnvironment",
        "acPower",
        "freeMemoryPercent",
        "freeDiskBytes",
        "runtimeManifestSHA256",
        "maximumWorkerRSSBytes",
        "watchdogPollMilliseconds",
        "minimumFreeDiskBytes",
        "networkSandbox",
        "countsTowardScientificVerdict",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError("host environment fields differ")
    execution = design["execution"]
    expected = {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-host-environment-v1",
        "suiteId": marker["suiteId"],
        "observedAt": marker["createdAt"],
        "system": "Darwin",
        "machine": "arm64",
        "acPower": True,
        "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
        "maximumWorkerRSSBytes": execution["maximumWorkerRSSBytes"],
        "watchdogPollMilliseconds": execution["watchdogPollMilliseconds"],
        "minimumFreeDiskBytes": execution["minimumFreeDiskBytes"],
        "countsTowardScientificVerdict": True,
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise EvidenceError(f"host environment binding differs: {field}")
    for field in (
        "osProductVersion",
        "osBuildVersion",
        "kernelRelease",
        "kernelVersion",
        "cpuBrand",
    ):
        if not isinstance(value[field], str) or not value[field].strip():
            raise EvidenceError(f"host environment identity is invalid: {field}")
    if (
        type(value["logicalCPUCount"]) is not int
        or value["logicalCPUCount"] < 1
        or type(value["physicalMemoryBytes"]) is not int
        or value["physicalMemoryBytes"] < 1
    ):
        raise EvidenceError("host CPU/memory identity is invalid")
    if value["pythonVersion"] != "3.12.10":
        raise EvidenceError("host Python version differs from the frozen runtime")
    if (
        not isinstance(value["pythonExecutableSHA256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["pythonExecutableSHA256"])
        is None
    ):
        raise EvidenceError("host Python executable commitment is invalid")
    intra_op_threads = execution.get("intraOpThreads")
    if type(intra_op_threads) is not int or intra_op_threads < 1:
        raise EvidenceError("frozen intra-op thread count is invalid")
    thread_count = str(intra_op_threads)
    expected_environment = {
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_OFFLINE": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "MKL_NUM_THREADS": thread_count,
        "NO_PROXY": "*",
        "NUMEXPR_NUM_THREADS": thread_count,
        "OMP_NUM_THREADS": thread_count,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TOKENIZERS_PARALLELISM": "false",
        "TRANSFORMERS_OFFLINE": "1",
        "VECLIB_MAXIMUM_THREADS": thread_count,
        "no_proxy": "*",
    }
    if value["effectiveExecutionEnvironment"] != expected_environment:
        raise EvidenceError("host effective execution environment differs")
    if (
        type(value["freeMemoryPercent"]) is not int
        or value["freeMemoryPercent"] < execution["minimumFreeMemoryPercent"]
        or type(value["freeDiskBytes"]) is not int
        or value["freeDiskBytes"] < execution["minimumFreeDiskBytes"]
    ):
        raise EvidenceError("host environment was below a frozen resource floor")
    sandbox = value["networkSandbox"]
    if sandbox != {
        "backend": execution["networkIsolationBackend"],
        "executablePath": "/usr/bin/sandbox-exec",
        "executableBytes": sandbox.get("executableBytes")
        if isinstance(sandbox, dict)
        else None,
        "executableSHA256": sandbox.get("executableSHA256")
        if isinstance(sandbox, dict)
        else None,
        "profile": execution["networkIsolationProfile"],
    }:
        raise EvidenceError("host network-sandbox binding differs")
    if (
        type(sandbox["executableBytes"]) is not int
        or sandbox["executableBytes"] <= 0
        or not isinstance(sandbox["executableSHA256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", sandbox["executableSHA256"]) is None
    ):
        raise EvidenceError("host network-sandbox executable commitment is invalid")
    return value


def _verify_content_digest(value: dict[str, Any], *, label: str) -> None:
    content_digest = value.get("contentSHA256")
    unsigned = dict(value)
    unsigned.pop("contentSHA256", None)
    if (
        not isinstance(content_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", content_digest) is None
        or hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        != content_digest
    ):
        raise EvidenceError(f"{label} content digest differs")


def _expected_asset_receipt_models(source: dict[str, Any]) -> dict[str, Any]:
    models = source.get("models")
    if not isinstance(models, dict):
        raise EvidenceError("asset-source manifest model set is absent")
    expected: dict[str, Any] = {}
    for model_key, model in models.items():
        if not isinstance(model, dict) or not isinstance(model.get("files"), dict):
            raise EvidenceError(f"asset-source model differs: {model_key}")
        expected[model_key] = {
            "repository": model.get("repository"),
            "revision": model.get("revision"),
            "license": model.get("license"),
            "licenseURL": model.get("licenseURL"),
            "files": {
                filename: {
                    "bytes": commitment.get("bytes"),
                    "sha256": commitment.get("sha256"),
                }
                for filename, commitment in model["files"].items()
                if isinstance(commitment, dict)
            },
        }
    return expected


def verify_runtime_asset_sbom_bindings(
    private_root: Path,
    private_manifest: dict[str, Any],
    *,
    marker: dict[str, Any],
    design: dict[str, Any],
    host_environment: dict[str, Any],
) -> dict[str, str]:
    """Replay runtime, complete asset, private-byte and SBOM commitments."""

    runtime_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/runtime-manifest.json",
        role="runtime-manifest",
        maximum_bytes=512 * 1024 * 1024,
    )
    asset_source_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/model-assets-source.json",
        role="asset-source-manifest",
        maximum_bytes=16 * 1024 * 1024,
    )
    asset_receipt_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/asset-receipt.json",
        role="full-asset-manifest",
        maximum_bytes=64 * 1024 * 1024,
    )
    sbom_raw = _private_committed_file(
        private_root,
        private_manifest,
        "bindings/sbom.cdx.json",
        role="design-release-asset",
        maximum_bytes=64 * 1024 * 1024,
    )
    digests = {
        "runtimeManifestSHA256": hashlib.sha256(runtime_raw).hexdigest(),
        "assetSourceManifestSHA256": hashlib.sha256(asset_source_raw).hexdigest(),
        "fullAssetReceiptSHA256": hashlib.sha256(asset_receipt_raw).hexdigest(),
        "sbomSHA256": hashlib.sha256(sbom_raw).hexdigest(),
    }
    if (
        digests["runtimeManifestSHA256"] != marker["runtimeManifestSHA256"]
        or digests["assetSourceManifestSHA256"]
        != marker["modelAssetSourceManifestSHA256"]
        or digests["fullAssetReceiptSHA256"] != marker["fullAssetReceiptSHA256"]
    ):
        raise EvidenceError("runtime/asset bytes differ from the attempt marker")

    runtime = load_canonical_line(runtime_raw, label="runtime manifest")
    asset_receipt = load_canonical_line(
        asset_receipt_raw, label="full asset receipt"
    )
    sbom = load_canonical_line(sbom_raw, label="CycloneDX SBOM")
    asset_source = load_json_strict_bytes(
        asset_source_raw, label="tracked asset-source manifest"
    )
    if not all(
        isinstance(item, dict)
        for item in (runtime, asset_receipt, sbom, asset_source)
    ):
        raise EvidenceError("runtime/asset/SBOM document type differs")
    _verify_content_digest(runtime, label="runtime manifest")
    _verify_content_digest(asset_receipt, label="full asset receipt")

    expected_runtime_fields = {
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
    if set(runtime) != expected_runtime_fields:
        raise EvidenceError("runtime manifest fields differ")
    if (
        runtime.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v3-runtime-manifest-v1"
        or runtime.get("status") != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
        or any(
            runtime.get(field) is not False
            for field in (
                "countsTowardScientificVerdict",
                "networkUsed",
                "modelInferenceUsed",
            )
        )
    ):
        raise EvidenceError("runtime manifest identity/boundary differs")
    runtime_host = runtime.get("host")
    python = runtime.get("python")
    executable = python.get("executable") if isinstance(python, dict) else None
    if (
        not isinstance(runtime_host, dict)
        or runtime_host.get("system") != "Darwin"
        or runtime_host.get("machine") != "arm64"
        or not isinstance(runtime_host.get("macVersion"), str)
        or not runtime_host["macVersion"]
        or not isinstance(python, dict)
        or python.get("registeredVersion") != "3.12.10"
        or python.get("version") != "3.12.10"
        or not isinstance(python.get("platformTag"), str)
        or re.fullmatch(r"macosx-[A-Za-z0-9_.-]+-arm64", python["platformTag"])
        is None
        or not isinstance(executable, dict)
        or type(executable.get("bytes")) is not int
        or executable["bytes"] <= 0
        or not isinstance(executable.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", executable["sha256"]) is None
    ):
        raise EvidenceError("runtime macOS/Python identity differs")
    if host_environment["pythonExecutableSHA256"] != executable["sha256"]:
        raise EvidenceError("host Python executable differs from runtime manifest")
    expected_locks = [
        {
            "name": "pip-bootstrap.txt",
            "bytes": 173,
            "sha256": design["runtime"]["pipBootstrapLockSHA256"],
        },
        {
            "name": "requirements.lock",
            "bytes": 55_781,
            "sha256": design["runtime"]["requirementsLockSHA256"],
        },
    ]
    if runtime.get("requirementsLocks") != expected_locks:
        raise EvidenceError("runtime requirements lock set differs")
    distributions = runtime.get("installedDistributions")
    if (
        not isinstance(distributions, list)
        or not distributions
        or runtime.get("installedDistributionCount") != len(distributions)
    ):
        raise EvidenceError("runtime distribution inventory differs")
    for field in ("runtimeTree", "basePythonTree"):
        tree = runtime.get(field)
        if (
            not isinstance(tree, dict)
            or type(tree.get("entryCount")) is not int
            or tree["entryCount"] <= 0
            or not isinstance(tree.get("treeSHA256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", tree["treeSHA256"]) is None
        ):
            raise EvidenceError(f"runtime {field} commitment differs")
    for field, frozen_source in (
        ("labSource", design["labSource"]),
        ("codecSource", design["codecSource"]),
    ):
        source = runtime.get(field)
        if (
            not isinstance(source, dict)
            or source.get("commit") != frozen_source["commit"]
            or source.get("tree") != frozen_source["tree"]
            or source.get("worktreeClean") is not True
            or _github_repository_slug(source.get("origin"))
            != _github_repository_slug(frozen_source["repository"])
        ):
            raise EvidenceError(f"runtime {field} source identity differs")

    try:
        validate_model_asset_manifest(asset_source, design)
    except (TypeError, ValueError) as error:
        raise EvidenceError(
            f"tracked asset-source manifest differs from design: {error}"
        ) from error
    if (
        asset_receipt.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v3-asset-receipt-v1"
        or asset_receipt.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED"
        or asset_receipt.get("fullSafetensorsBytesLocallyVerified") is not True
        or asset_receipt.get("fileCount") != 24
        or asset_receipt.get("totalBytes") != 1_916_375_741
        or asset_receipt.get("fullSafetensorsBytes") != 1_906_255_408
        or any(
            asset_receipt.get(field) is not False
            for field in (
                "countsTowardScientificVerdict",
                "networkUsed",
                "modelInferenceUsed",
            )
        )
    ):
        raise EvidenceError("full asset receipt identity/aggregate differs")
    if (
        asset_receipt.get("manifestFile") != "model-assets.draft.json"
        or asset_receipt.get("manifestFileBytes") != len(asset_source_raw)
        or asset_receipt.get("manifestFileSHA256")
        != digests["assetSourceManifestSHA256"]
        or asset_receipt.get("manifestSchemaVersion")
        != asset_source.get("schemaVersion")
        or asset_receipt.get("manifestDeclaredStatus") != asset_source.get("status")
        or asset_receipt.get("manifestDeclaredFullSafetensorsBytesLocallyVerified")
        != asset_source.get("fullSafetensorsBytesLocallyVerified")
        or asset_receipt.get("models")
        != _expected_asset_receipt_models(asset_source)
    ):
        raise EvidenceError("full asset receipt/source cross-binding differs")
    expected_private_assets: dict[str, dict[str, Any]] = {}
    for model_key, model in asset_receipt["models"].items():
        for filename, commitment in model["files"].items():
            expected_private_assets[f"models/{model_key}/{filename}"] = commitment
    observed_private_assets = {
        entry["path"]: {"bytes": entry["bytes"], "sha256": entry["sha256"]}
        for entry in private_manifest["files"]
        if entry["role"] == "model-asset"
    }
    if observed_private_assets != expected_private_assets:
        raise EvidenceError("private model bytes differ from the full asset receipt")
    try:
        expected_sbom = build_sbom(runtime, asset_receipt)
    except (KeyError, TypeError, ValueError) as error:
        raise EvidenceError(f"runtime/assets cannot reproduce SBOM: {error}") from error
    if sbom != expected_sbom:
        raise EvidenceError("CycloneDX SBOM differs from runtime/asset receipts")
    return digests


def validate_selection(selection: Any, design: dict[str, Any], snapshot_digest: str):
    if not isinstance(selection, dict):
        raise EvidenceError("selection must be an object")
    if selection.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-selection-v1":
        raise EvidenceError("selection schemaVersion differs")
    if selection.get("suiteId") != design["suiteId"]:
        raise EvidenceError("selection suiteId differs")
    if selection.get("snapshotRegistrationSHA256") != snapshot_digest:
        raise EvidenceError("selection is not bound to the attempt snapshot")
    projects = design["futureCorpus"]["projects"]
    corpora = selection.get("selectedCorpora")
    if (
        not isinstance(corpora, list)
        or len(corpora) != 2
        or len(set(corpora)) != 2
        or any(corpus not in projects for corpus in corpora)
    ):
        raise EvidenceError("selection does not contain two registered corpora")
    model_keys = [item["key"] for item in design["models"]]
    model_order = selection.get("modelExecutionOrder")
    if not isinstance(model_order, list) or set(model_order) != set(model_keys) or len(model_order) != 3:
        raise EvidenceError("selection model order differs from the frozen models")
    pages = selection.get("selectedPages")
    if not isinstance(pages, dict) or set(pages) != set(corpora):
        raise EvidenceError("selection page groups differ")
    selected_revisions: dict[str, list[int]] = {}
    for corpus in corpora:
        records = pages[corpus]
        if not isinstance(records, list) or len(records) != 16:
            raise EvidenceError("selection corpus must contain exactly sixteen pages")
        revisions = [record.get("revid") if isinstance(record, dict) else None for record in records]
        if any(type(value) is not int or value < 1 for value in revisions) or len(set(revisions)) != 16:
            raise EvidenceError("selection revision identities are invalid")
        selected_revisions[corpus] = revisions
    return corpora, model_order, selected_revisions


def verify_worker_bindings(
    evidence_root: Path,
    *,
    private_manifest: dict[str, Any],
    selection: dict[str, Any],
    design: dict[str, Any],
    marker: dict[str, Any],
    model_order: list[str],
    raw_relative: str,
    container_relative: str,
    page_token_relative: str,
) -> tuple[set[str], str]:
    """Bind every producer child artifact to the sealed scientific inputs."""

    private_entries = {
        entry["path"]: entry for entry in private_manifest["files"]
    }
    model_specs = {item["key"]: item for item in design["models"]}
    expected_candidate = {
        key: design["candidate"][key]
        for key in (
            "backend",
            "groupSize",
            "transformBlockSize",
            "codeCompression",
            "scaleCompression",
            "signMode",
        )
    }
    required_paths: set[str] = set()
    raw_parts: list[bytes] = []
    container_parts: list[bytes] = []
    page_token_parts: list[bytes] = []
    commitments: list[dict[str, Any]] = []

    for model_key in model_order:
        if model_key not in model_specs:
            raise EvidenceError(f"worker model is absent from design: {model_key}")
        job_path = f"jobs/{model_key}.json"
        log_path = f"logs/{model_key}.log"
        supervisor_path = f"supervision/{model_key}.json"
        summary_path = f"workers/{model_key}/worker-summary.json"
        worker_raw_path = f"workers/{model_key}/raw-token-evidence.jsonl"
        worker_container_path = f"workers/{model_key}/container-evidence.jsonl"
        worker_page_token_path = f"workers/{model_key}/page-token-evidence.jsonl"
        required_paths.update(
            {
                job_path,
                log_path,
                supervisor_path,
                summary_path,
                worker_raw_path,
                worker_container_path,
                worker_page_token_path,
            }
        )

        job_raw = read_evidence_file(
            evidence_root, job_path, maximum_bytes=16 * 1024 * 1024
        )
        job = load_canonical_line(job_raw, label=f"worker job {model_key}")
        try:
            validate_worker_job(job)
        except (IndependentVerificationError, KeyError, TypeError, ValueError) as error:
            raise EvidenceError(f"worker job contract failed: {model_key}: {error}") from error
        specification = model_specs[model_key]
        if (
            job["suiteId"] != marker["suiteId"]
            or job["attemptId"] != marker["attemptId"]
            or job["countsTowardScientificVerdict"] is not True
            or job["model"]["key"] != model_key
            or job["selectedCorpora"] != selection["selectedCorpora"]
            or job["candidate"] != expected_candidate
            or job["seed"] != 0
        ):
            raise EvidenceError(f"worker job scientific binding differs: {model_key}")

        expected_files: dict[str, dict[str, Any]] = {}
        for filename in sorted(job["model"]["files"]):
            path = f"models/{model_key}/{filename}"
            entry = private_entries.get(path)
            if entry is None or entry["role"] != "model-asset":
                raise EvidenceError(f"worker model asset is not sealed: {path}")
            expected_files[filename] = {
                "path": path,
                "bytes": entry["bytes"],
                "sha256": entry["sha256"],
            }
        expected_model = {
            "key": model_key,
            "files": expected_files,
            "layers": specification["layers"],
            "vocabSize": specification["vocabSize"],
            "candidateBitsByLayer": specification["candidateBitsByLayer"],
        }
        if job["model"] != expected_model:
            raise EvidenceError(f"worker model commitments differ: {model_key}")

        expected_pages: dict[str, list[dict[str, Any]]] = {}
        for corpus in selection["selectedCorpora"]:
            pages: list[dict[str, Any]] = []
            for page_index, selected in enumerate(selection["selectedPages"][corpus]):
                revision = selected["revid"]
                path = f"records/{corpus}/{revision}.bin"
                entry = private_entries.get(path)
                if entry is None or entry["role"] != "eligible-corpus-record":
                    raise EvidenceError(f"worker corpus record is not sealed: {path}")
                pages.append(
                    {
                        "pageSelectionIndex": page_index,
                        "pageRevisionId": revision,
                        "recordPath": path,
                        "recordBytes": entry["bytes"],
                        "recordSHA256": entry["sha256"],
                    }
                )
            expected_pages[corpus] = pages
        if job["pages"] != expected_pages:
            raise EvidenceError(f"worker selected-page commitments differ: {model_key}")

        supervisor_raw = read_evidence_file(
            evidence_root, supervisor_path, maximum_bytes=128 * 1024
        )
        supervisor = load_canonical_line(
            supervisor_raw, label=f"worker supervisor receipt {model_key}"
        )
        supervisor_fields = {
            "schemaVersion",
            "role",
            "subject",
            "processGroupId",
            "startedAt",
            "completedAt",
            "durationNanoseconds",
            "exitCode",
            "peakAggregateRSSBytes",
            "maximumAggregateRSSBytes",
            "watchdogPollMilliseconds",
            "hardDeadline",
            "descendantsRemainingAtExit",
            "terminationApplied",
            "countsTowardScientificVerdict",
        }
        if not isinstance(supervisor, dict) or set(supervisor) != supervisor_fields:
            raise EvidenceError(f"worker supervisor receipt fields differ: {model_key}")
        if (
            supervisor["schemaVersion"]
            != "corelm-crossmodel-livewiki-v3-supervisor-receipt-v1"
            or supervisor["role"] != "model-worker"
            or supervisor["subject"] != model_key
            or supervisor["exitCode"] != 0
            or supervisor["maximumAggregateRSSBytes"]
            != design["execution"]["maximumWorkerRSSBytes"]
            or supervisor["watchdogPollMilliseconds"]
            != design["execution"]["watchdogPollMilliseconds"]
            or supervisor["hardDeadline"] != design["execution"]["hardDeadline"]
            or supervisor["descendantsRemainingAtExit"] is not False
            or supervisor["terminationApplied"] is not False
            or supervisor["countsTowardScientificVerdict"] is not True
        ):
            raise EvidenceError(f"worker supervisor binding differs: {model_key}")
        if (
            type(supervisor["processGroupId"]) is not int
            or supervisor["processGroupId"] < 1
            or type(supervisor["durationNanoseconds"]) is not int
            or supervisor["durationNanoseconds"] < 1
            or type(supervisor["peakAggregateRSSBytes"]) is not int
            or not 0 <= supervisor["peakAggregateRSSBytes"]
            <= supervisor["maximumAggregateRSSBytes"]
            or not isinstance(supervisor["startedAt"], str)
            or not isinstance(supervisor["completedAt"], str)
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                supervisor["startedAt"],
            )
            is None
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                supervisor["completedAt"],
            )
            is None
            or supervisor["completedAt"] < supervisor["startedAt"]
        ):
            raise EvidenceError(f"worker supervisor values are invalid: {model_key}")

        worker_raw = read_evidence_file(
            evidence_root, worker_raw_path, maximum_bytes=128 * 1024 * 1024
        )
        worker_container = read_evidence_file(
            evidence_root,
            worker_container_path,
            maximum_bytes=64 * 1024 * 1024,
        )
        worker_page_token = read_evidence_file(
            evidence_root,
            worker_page_token_path,
            maximum_bytes=16 * 1024 * 1024,
        )
        raw_records = load_canonical_jsonl_beneath(
            evidence_root, worker_raw_path, maximum_bytes=128 * 1024 * 1024
        )
        container_records = load_canonical_jsonl_beneath(
            evidence_root,
            worker_container_path,
            maximum_bytes=64 * 1024 * 1024,
        )
        page_token_records = load_canonical_jsonl_beneath(
            evidence_root,
            worker_page_token_path,
            maximum_bytes=16 * 1024 * 1024,
        )
        if len(raw_records) != 2 * 16 * 128:
            raise EvidenceError(f"worker raw-token record count differs: {model_key}")
        if len(container_records) != 2 * 16 * specification["layers"]:
            raise EvidenceError(f"worker container record count differs: {model_key}")
        if len(page_token_records) != 2 * 16:
            raise EvidenceError(f"worker page-token record count differs: {model_key}")
        for record in (*raw_records, *container_records, *page_token_records):
            if (
                record.get("suiteId") != marker["suiteId"]
                or record.get("attemptId") != marker["attemptId"]
                or record.get("modelKey") != model_key
            ):
                raise EvidenceError(f"worker evidence identity differs: {model_key}")
        raw_parts.append(worker_raw)
        container_parts.append(worker_container)
        page_token_parts.append(worker_page_token)

        summary_raw = read_evidence_file(
            evidence_root, summary_path, maximum_bytes=16 * 1024 * 1024
        )
        summary = load_canonical_line(
            summary_raw, label=f"worker summary {model_key}"
        )
        summary_fields = {
            "schemaVersion",
            "suiteId",
            "attemptId",
            "modelKey",
            "geometry",
            "pages",
            "rawTokenEvidence",
            "containerEvidence",
            "pageTokenEvidence",
            "durationNanoseconds",
            "networkUsed",
            "modelLoad",
            "countsTowardScientificVerdict",
        }
        if not isinstance(summary, dict) or set(summary) != summary_fields:
            raise EvidenceError(f"worker summary fields differ: {model_key}")
        expected_identity = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-worker-summary-v1",
            "suiteId": marker["suiteId"],
            "attemptId": marker["attemptId"],
            "modelKey": model_key,
            "networkUsed": False,
            "modelLoad": "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained",
            "countsTowardScientificVerdict": True,
        }
        for field, expected in expected_identity.items():
            if summary.get(field) != expected:
                raise EvidenceError(f"worker summary binding differs: {model_key}/{field}")
        if (
            type(summary["durationNanoseconds"]) is not int
            or summary["durationNanoseconds"] < 1
        ):
            raise EvidenceError(f"worker duration is invalid: {model_key}")
        expected_evidence = {
            "rawTokenEvidence": {
                "path": "raw-token-evidence.jsonl",
                "bytes": len(worker_raw),
                "sha256": hashlib.sha256(worker_raw).hexdigest(),
            },
            "containerEvidence": {
                "path": "container-evidence.jsonl",
                "bytes": len(worker_container),
                "sha256": hashlib.sha256(worker_container).hexdigest(),
            },
            "pageTokenEvidence": {
                "path": "page-token-evidence.jsonl",
                "bytes": len(worker_page_token),
                "sha256": hashlib.sha256(worker_page_token).hexdigest(),
            },
        }
        for field, expected in expected_evidence.items():
            if summary.get(field) != expected:
                raise EvidenceError(f"worker evidence receipt differs: {model_key}/{field}")

        geometry = summary["geometry"]
        geometry_fields = {
            "modelType",
            "attentionLayout",
            "layers",
            "attentionHeads",
            "kvHeads",
            "headDimension",
            "hiddenSize",
            "trajectoryWidth",
        }
        architecture_geometry = {
            "gpt-neo-mixed-global-local": ("gpt_neo", "mixed-global-local"),
            "llama-gqa": ("llama", "grouped-query"),
            "gpt-bigcode-mqa": ("gpt_bigcode", "multi-query"),
        }
        expected_type_layout = architecture_geometry.get(specification["architecture"])
        if not isinstance(geometry, dict) or set(geometry) != geometry_fields:
            raise EvidenceError(f"worker geometry fields differ: {model_key}")
        if expected_type_layout is None or (
            geometry["modelType"], geometry["attentionLayout"]
        ) != expected_type_layout:
            raise EvidenceError(f"worker architecture geometry differs: {model_key}")
        for field in (
            "layers",
            "attentionHeads",
            "kvHeads",
            "headDimension",
            "hiddenSize",
            "trajectoryWidth",
        ):
            if type(geometry[field]) is not int or geometry[field] < 1:
                raise EvidenceError(f"worker geometry value is invalid: {model_key}/{field}")
        if (
            geometry["layers"] != specification["layers"]
            or geometry["kvHeads"] != specification["kvHeads"]
            or geometry["hiddenSize"]
            != geometry["attentionHeads"] * geometry["headDimension"]
            or geometry["trajectoryWidth"]
            != 2 * geometry["kvHeads"] * geometry["headDimension"]
            or geometry["trajectoryWidth"] % 128
        ):
            raise EvidenceError(f"worker geometry commitment differs: {model_key}")

        raw_by_page: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for record in raw_records:
            raw_by_page.setdefault(
                (record["corpusProject"], record["pageSelectionIndex"]), []
            ).append(record)
        containers_by_page: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for record in container_records:
            containers_by_page.setdefault(
                (record["corpusProject"], record["pageSelectionIndex"]), []
            ).append(record)
        expected_summary_pages: list[dict[str, Any]] = []
        for corpus in selection["selectedCorpora"]:
            for page_index, selected in enumerate(selection["selectedPages"][corpus]):
                page_key = (corpus, page_index)
                page_raw = sorted(
                    raw_by_page.get(page_key, []),
                    key=lambda item: item["predictionIndex"],
                )
                page_containers = containers_by_page.get(page_key, [])
                if (
                    len(page_raw) != 128
                    or [item["predictionIndex"] for item in page_raw]
                    != list(range(128))
                    or len(page_containers) != specification["layers"]
                ):
                    raise EvidenceError(f"worker page evidence coverage differs: {model_key}")
                dense_bytes = sum(item["denseBF16Bytes"] for item in page_containers)
                container_bytes = sum(item["containerBytes"] for item in page_containers)
                delta = math.fsum(
                    decode_float32_bits(
                        item["candidateLossF32Bits"], label="candidate loss"
                    )
                    - decode_float32_bits(
                        item["baselineLossF32Bits"], label="baseline loss"
                    )
                    for item in page_raw
                ) / 128
                matches = sum(
                    item["baselineTop1TokenId"] == item["candidateTop1TokenId"]
                    for item in page_raw
                )
                expected_summary_pages.append(
                    {
                        "corpusProject": corpus,
                        "pageSelectionIndex": page_index,
                        "pageRevisionId": selected["revid"],
                        "denseBF16Bytes": dense_bytes,
                        "containerBytes": container_bytes,
                        "compressionRatioVsBF16": dense_bytes / container_bytes,
                        "deltaNLLNatPerToken": delta,
                        "top1ExactMatches": matches,
                    }
                )
        if summary["pages"] != expected_summary_pages:
            raise EvidenceError(f"worker page summary differs: {model_key}")
        commitments.append(
            {
                "modelKey": model_key,
                "jobSHA256": hashlib.sha256(job_raw).hexdigest(),
                "summarySHA256": hashlib.sha256(summary_raw).hexdigest(),
                "supervisorReceiptSHA256": hashlib.sha256(supervisor_raw).hexdigest(),
                "rawTokenEvidenceSHA256": hashlib.sha256(worker_raw).hexdigest(),
                "containerEvidenceSHA256": hashlib.sha256(worker_container).hexdigest(),
                "pageTokenEvidenceSHA256": hashlib.sha256(worker_page_token).hexdigest(),
            }
        )

    top_raw = read_evidence_file(
        evidence_root, raw_relative, maximum_bytes=128 * 1024 * 1024
    )
    top_containers = read_evidence_file(
        evidence_root, container_relative, maximum_bytes=64 * 1024 * 1024
    )
    top_page_tokens = read_evidence_file(
        evidence_root, page_token_relative, maximum_bytes=16 * 1024 * 1024
    )
    if top_raw != b"".join(raw_parts):
        raise EvidenceError("consolidated raw-token evidence differs from worker evidence")
    if top_containers != b"".join(container_parts):
        raise EvidenceError("consolidated container evidence differs from worker evidence")
    if top_page_tokens != b"".join(page_token_parts):
        raise EvidenceError("consolidated page-token evidence differs from worker evidence")
    return required_paths, hashlib.sha256(canonical_json_bytes(commitments)).hexdigest()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--codec-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--snapshot-registration", type=Path, required=True)
    parser.add_argument("--ledgers-root", type=Path, required=True)
    parser.add_argument("--nist-trust-manifest", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument(
        "--raw-tokens", type=Path, default=Path("raw-token-evidence.jsonl")
    )
    parser.add_argument(
        "--containers", type=Path, default=Path("container-evidence.jsonl")
    )
    parser.add_argument(
        "--page-tokens", type=Path, default=Path("page-token-evidence.jsonl")
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path("evidence-manifest.json")
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def verify_publication_inputs(
    private_root: Path,
    *,
    marker: dict[str, Any],
    design: dict[str, Any],
    design_path: Path,
    snapshot_path: Path,
    cryptographic_attestation_verifier: ReleaseAttestationCryptographicVerifier,
) -> tuple[str, str, dict[str, str]]:
    """Reverify both signed public releases from the sealed private inputs."""

    key_path = private_root / "publication" / "signing-key.pub"
    try:
        design_publication = verify_publication(
            private_root / "publication" / "design-receipt.json",
            private_root / "publication" / "design-assets",
            kind="design",
            tag=design["designRelease"]["tag"],
            deadline=design["designRelease"]["publishNoLaterThan"],
            signing_public_key_path=key_path,
            signing_key_fingerprint=design["designRelease"]["signingKeyFingerprint"],
            signing_public_key_sha256=design["designRelease"][
                "signingPublicKeySHA256"
            ],
            expected_role_paths={
                "asset-source-manifest": private_root
                / "bindings"
                / "model-assets-source.json",
                "design-registration": design_path,
                "development-control-report": private_root
                / "development"
                / "report.json",
                "development-control-archive-receipt": private_root
                / "development"
                / "archive"
                / "receipt.json",
                "freeze-manifest": private_root / "bindings" / "freeze-manifest.json",
                "full-asset-receipt": private_root / "bindings" / "asset-receipt.json",
                "github-gate-receipt": private_root
                / "bindings"
                / "github-gate-receipt.json",
                "linux-ci-artifact": private_root
                / "publication"
                / "design-assets"
                / "linux-ci-artifact.zip",
                "macos-arm64-ci-artifact": private_root
                / "publication"
                / "design-assets"
                / "macos-arm64-ci-artifact.zip",
                "runtime-manifest": private_root / "bindings" / "runtime-manifest.json",
                "sbom": private_root / "bindings" / "sbom.cdx.json",
                "sha256-manifest": private_root
                / "bindings"
                / "design-release-sha256-manifest.json",
            },
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
        require_frozen_lab_publication_source(
            design_publication,
            design,
            kind="design",
        )
        design_package = verify_design_release_package(
            private_root / "publication" / "design-assets",
            signing_public_key_path=key_path,
        )
        snapshot_publication = verify_publication(
            private_root / "publication" / "snapshot-receipt.json",
            private_root / "publication" / "snapshot-assets",
            kind="snapshot",
            tag=design["snapshotRelease"]["tag"],
            deadline=design["snapshotRelease"]["publishNoLaterThan"],
            signing_public_key_path=key_path,
            signing_key_fingerprint=design["snapshotRelease"][
                "signingKeyFingerprint"
            ],
            signing_public_key_sha256=design["snapshotRelease"][
                "signingPublicKeySHA256"
            ],
            expected_role_paths={
                "attribution": private_root
                / "publication"
                / "snapshot-assets"
                / "attribution.json",
                "corpus-bytes": private_root
                / "publication"
                / "snapshot-assets"
                / "corpus-bytes.zip",
                "design-publication-receipt": private_root
                / "publication"
                / "design-receipt.json",
                "sha256-manifest": private_root
                / "publication"
                / "snapshot-assets"
                / "sha256-manifest.json",
                "snapshot-registration": snapshot_path,
            },
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
        require_frozen_lab_publication_source(
            snapshot_publication,
            design,
            kind="snapshot",
        )
    except (DesignReleaseError, PublicationError) as error:
        raise EvidenceError(f"signed publication verification failed: {error}") from error
    if (
        design_publication.receipt_sha256
        != marker["designPublicationReceiptSHA256"]
        or snapshot_publication.receipt_sha256
        != marker["snapshotPublicationReceiptSHA256"]
    ):
        raise EvidenceError("attempt marker publication-receipt binding differs")
    snapshot_raw = read_external_file(snapshot_path, maximum_bytes=16 * 1024 * 1024)
    snapshot = load_json_strict_bytes(snapshot_raw, label="snapshot registration")
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("designPublicationReceiptSHA256")
        != design_publication.receipt_sha256
    ):
        raise EvidenceError("snapshot does not bind the verified design publication")
    return (
        design_publication.receipt_sha256,
        snapshot_publication.receipt_sha256,
        {
            item.role: item.archive_sha256
            for item in design_package.ci_artifacts
        },
    )


def beneath(root: Path, value: Path) -> Path:
    if value.is_absolute():
        raise EvidenceError("evidence file arguments must be relative to evidence-root")
    if not value.parts or ".." in value.parts:
        raise EvidenceError("evidence file argument escapes evidence-root")
    return root / value


def relative_argument(value: Path, *, label: str) -> str:
    if value.is_absolute() or not value.parts or ".." in value.parts:
        raise EvidenceError(f"{label} escapes evidence-root")
    text = value.as_posix()
    if text in {"", "."} or "\\" in text:
        raise EvidenceError(f"{label} is not a canonical relative POSIX path")
    return text


def load_canonical_line(raw: bytes, *, label: str) -> Any:
    if not raw.endswith(b"\n"):
        raise EvidenceError(f"{label} must end with one canonical LF")
    value = load_json_strict_bytes(raw, label=label)
    if canonical_json_bytes(value) + b"\n" != raw:
        raise EvidenceError(f"{label} is not canonical JSON plus LF")
    return value


def verify_attempt_reservation(
    evidence_root: Path,
    marker: dict[str, Any],
    design: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Independently validate and bind the durable pre-marker reservation."""

    raw = read_evidence_file(
        evidence_root,
        RESERVATION_FILENAME,
        maximum_bytes=1024 * 1024,
    )
    reservation = load_canonical_line(raw, label="attempt reservation")
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise EvidenceError(
            "locked independent-verifier runtime lacks jsonschema"
        ) from error
    schema_raw = read_evidence_file(
        V3_ROOT,
        "schemas/attempt-reservation.schema.json",
        maximum_bytes=2 * 1024 * 1024,
    )
    schema = load_json_strict_bytes(
        schema_raw, label="canonical attempt-reservation schema"
    )
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(reservation),
        key=lambda item: list(item.path),
    )
    if schema_errors:
        first = schema_errors[0]
        location = "$" + "".join(f"[{part!r}]" for part in first.path)
        raise EvidenceError(
            "attempt-reservation.schema.json validation failed at "
            f"{location}: {first.message}"
        )
    if not isinstance(reservation, dict):
        raise EvidenceError("attempt reservation must contain an object")
    unsigned = dict(reservation)
    content_digest = unsigned.pop("reservationContentSHA256")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != content_digest:
        raise EvidenceError("attempt reservation self-digest mismatch")
    for field in RESERVATION_MARKER_BINDING_FIELDS:
        if reservation[field] != marker[field]:
            raise EvidenceError(
                f"attempt marker differs from its durable reservation: {field}"
            )

    execution = design.get("execution")
    beacon = design.get("beacon")
    if not isinstance(execution, dict) or not isinstance(beacon, dict):
        raise EvidenceError("frozen attempt window or beacon binding is absent")

    def parse_utc_second(value: Any, *, label: str) -> datetime:
        if not isinstance(value, str):
            raise EvidenceError(f"{label} is absent")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as error:
            raise EvidenceError(f"{label} is not canonical UTC") from error

    created = parse_utc_second(
        reservation["createdAt"], label="attempt reservation createdAt"
    )
    lower = parse_utc_second(
        execution.get("oneShotNotBefore"), label="one-shot lower bound"
    )
    upper = parse_utc_second(
        execution.get("hardDeadline"), label="one-shot hard deadline"
    )
    if not lower <= created < upper:
        raise EvidenceError("attempt reservation is outside the frozen one-shot window")
    if reservation["targetPulseTimestamp"] != beacon.get("targetTimestamp"):
        raise EvidenceError("attempt reservation target pulse differs from frozen design")
    return reservation, hashlib.sha256(raw).hexdigest()


def verify_nist_evidence(
    evidence_root: Path,
    trust_manifest: Path,
    *,
    expected_trust_manifest_sha256: str,
    expected_root_der_sha256: list[str],
) -> tuple[dict[str, Any], str]:
    request_uri = read_evidence_file(
        evidence_root, NIST_REQUEST_URI_PATH, maximum_bytes=4096
    )
    if request_uri != TARGET_ENDPOINT.encode("ascii") + b"\n":
        raise EvidenceError("archived NIST request URI differs from the frozen endpoint")
    response_headers = read_evidence_file(
        evidence_root, NIST_RESPONSE_HEADERS_PATH, maximum_bytes=1024 * 1024
    )
    response_body = read_evidence_file(
        evidence_root, NIST_RESPONSE_BODY_PATH, maximum_bytes=32 * 1024 * 1024
    )
    trust_manifest_raw = read_external_file(
        trust_manifest, maximum_bytes=16 * 1024 * 1024
    )
    if hashlib.sha256(trust_manifest_raw).hexdigest() != expected_trust_manifest_sha256:
        raise EvidenceError("offline NIST trust manifest differs from the frozen design")
    # Certificate parsing, chain verification, pulse serialization, RSA
    # verification, and output construction all execute in the second
    # implementation.  Only the already-sealed bytes cross this boundary.
    expected_seconds, expected_milliseconds = divmod(
        TARGET_UNIX_MILLISECONDS, 1000
    )
    expected_time = datetime.fromtimestamp(
        expected_seconds, tz=timezone.utc
    ) + timedelta(milliseconds=expected_milliseconds)
    trust_bundle = load_independent_trust_bundle(
        trust_manifest,
        expected_time=expected_time,
        expected_manifest_sha256=expected_trust_manifest_sha256,
        expected_root_der_sha256=expected_root_der_sha256,
        allow_known_answer_fixture=False,
    )
    recomputed = verify_nist_response(
        request_uri=TARGET_ENDPOINT,
        response_headers=response_headers,
        response_body=response_body,
        trust_bundle=trust_bundle,
        expected_unix_milliseconds=TARGET_UNIX_MILLISECONDS,
        allow_known_answer_fixture=False,
    )
    stored_raw = read_evidence_file(
        evidence_root, NIST_VERIFICATION_PATH, maximum_bytes=128 * 1024
    )
    stored = load_canonical_line(stored_raw, label="NIST verification record")
    if not isinstance(stored, dict) or stored != recomputed:
        raise EvidenceError("stored NIST verification differs from independent replay")
    if canonical_nist_verification_bytes(recomputed) + b"\n" != stored_raw:
        raise EvidenceError("stored NIST verification bytes differ from recomputation")
    return recomputed, hashlib.sha256(stored_raw).hexdigest()


def verify_external_attempt_time_anchor(
    verification: dict[str, Any], design: dict[str, Any]
) -> str:
    """Independently enforce the registered NIST HTTPS-Date start anchor."""

    execution = design.get("execution")
    response_date = verification.get("responseDate")
    if not isinstance(execution, dict) or not isinstance(response_date, str):
        raise EvidenceError("attempt start time authority is absent")

    def parse(value: Any, *, label: str) -> datetime:
        if not isinstance(value, str):
            raise EvidenceError(f"{label} is absent")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError as error:
            raise EvidenceError(f"{label} is not canonical UTC") from error

    observed = parse(response_date, label="NIST HTTPS Date")
    lower = parse(execution.get("oneShotNotBefore"), label="one-shot lower bound")
    upper = parse(execution.get("hardDeadline"), label="one-shot hard deadline")
    if not lower <= observed < upper:
        raise EvidenceError(
            "verified NIST HTTPS Date is outside the registered one-shot window"
        )
    return response_date


def recompute_selection(
    *,
    evidence_root: Path,
    snapshot_registration: Path,
    ledgers_root: Path,
    design: dict[str, Any],
    marker: dict[str, Any],
    nist_verification: dict[str, Any],
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    snapshot_bytes = read_external_file(
        snapshot_registration, maximum_bytes=16 * 1024 * 1024
    )
    if hashlib.sha256(snapshot_bytes).hexdigest() != marker["snapshotRegistrationSHA256"]:
        raise EvidenceError("snapshot registration bytes differ from the attempt marker")
    snapshot = load_json_strict_bytes(
        snapshot_bytes, label="snapshot registration"
    )
    if not isinstance(snapshot, dict):
        raise EvidenceError("snapshot registration must contain an object")
    for snapshot_field, marker_field in (
        (
            "modelAssetSourceManifestSHA256",
            "modelAssetSourceManifestSHA256",
        ),
        ("fullAssetReceiptSHA256", "fullAssetReceiptSHA256"),
        ("corpusManifestSHA256", "corpusManifestSHA256"),
    ):
        if snapshot.get(snapshot_field) != marker.get(marker_field):
            raise EvidenceError(
                f"snapshot {snapshot_field} differs from the attempt marker"
            )
    root = Path(os.path.abspath(os.fspath(ledgers_root)))
    try:
        metadata = os.lstat(root)
    except OSError as error:
        raise EvidenceError("ledger root is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("ledger root must be a real directory")
    projects = design["futureCorpus"]["projects"]
    ledgers = {
        project: read_evidence_file(
            root, f"{project}.json", maximum_bytes=64 * 1024 * 1024
        )
        for project in projects
    }
    full_ledgers: dict[str, Any] = {}
    for project, raw in ledgers.items():
        parsed = load_json_strict_bytes(raw, label=f"full ledger {project}")
        if canonical_json_bytes(parsed) != raw:
            raise EvidenceError(f"full ledger is not canonical JSON: {project}")
        full_ledgers[project] = parsed
    recomputed = derive_selection(
        snapshot_bytes,
        nist_verification["outputValue"],
        projects=projects,
        models=[item["key"] for item in design["models"]],
        ledgers=ledgers,
        allow_known_answer_fixture=False,
    )
    stored_raw = read_evidence_file(
        evidence_root, SELECTION_PATH, maximum_bytes=16 * 1024 * 1024
    )
    stored = load_canonical_line(stored_raw, label="selection")
    if stored != recomputed or canonical_json_bytes(recomputed) + b"\n" != stored_raw:
        raise EvidenceError("stored selection differs from independent NIST derivation")
    return recomputed, hashlib.sha256(stored_raw).hexdigest(), full_ledgers


def canonical_scientific_result(
    verification: dict[str, Any],
    *,
    selection_sha256: str,
    pulse_verification_sha256: str,
) -> dict[str, Any]:
    cell_fields = (
        "modelKey",
        "corpusProject",
        "pages",
        "predictions",
        "denseBF16Bytes",
        "containerBytes",
        "compressionRatioVsBF16",
        "deltaNLLNatPerToken",
        "top1Agreement",
        "structuralReplay",
        "pass",
    )
    cells = [
        {key: cell[key] for key in cell_fields}
        for cell in verification["cells"]
    ]
    aggregates = []
    for aggregate in verification["modelAggregates"]:
        aggregates.append(
            {
                "modelKey": aggregate["modelKey"],
                "pages": aggregate["blocks"],
                "predictions": aggregate["predictions"],
                "deltaUpper": aggregate["deltaUpper"],
                "top1Lower": aggregate["top1Lower"],
                "wilsonLower": aggregate["wilsonLower"],
                "pass": aggregate["pass"],
            }
        )
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-result-v1",
        "suiteId": verification["suiteId"],
        "attemptId": verification["attemptId"],
        "selectionSHA256": selection_sha256,
        "pulseVerificationSHA256": pulse_verification_sha256,
        "cells": cells,
        "modelAggregates": aggregates,
        "suitePass": verification["verdict"] == "PASS",
        "countsTowardScientificVerdict": True,
    }


def main() -> int:
    install_network_denial()
    arguments = parse_arguments()
    evidence_root = arguments.evidence_root
    design_raw = read_external_file(arguments.design, maximum_bytes=16 * 1024 * 1024)
    design = load_json_strict_bytes(design_raw, label="frozen design")
    validate_frozen_design(design)
    try:
        marker = load_attempt_marker(evidence_root)
    except StateMachineError as error:
        raise EvidenceError(f"invalid durable attempt state: {error}") from error
    if marker is None:
        raise EvidenceError("evidence root has no durable attempt marker")
    _reservation, reservation_digest = verify_attempt_reservation(
        evidence_root, marker, design
    )
    if marker["suiteId"] != design["suiteId"]:
        raise EvidenceError("attempt marker suite differs from frozen design")
    design_digest = hashlib.sha256(design_raw).hexdigest()
    if marker["designSHA256"] != design_digest:
        raise EvidenceError("attempt marker is not bound to exact design bytes")
    validate_marker_design_bindings(marker, design)
    private_manifest = verify_private_snapshot_manifest(
        evidence_root, marker, design
    )
    cryptographic_attestation_verifier = (
        PinnedCosignReleaseAttestationVerifier(
            arguments.private_root / "tools" / "cosign"
        )
    )
    github_gate_receipt_digest = verify_github_gate_binding(
        arguments.private_root,
        private_manifest,
        marker=marker,
        design=design,
    )
    (
        design_publication_receipt_digest,
        snapshot_publication_receipt_digest,
        design_ci_artifact_digests,
    ) = verify_publication_inputs(
        arguments.private_root,
        marker=marker,
        design=design,
        design_path=arguments.design,
        snapshot_path=arguments.snapshot_registration,
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    host_environment = verify_host_environment(
        evidence_root, marker=marker, design=design
    )
    provenance_digests = verify_runtime_asset_sbom_bindings(
        arguments.private_root,
        private_manifest,
        marker=marker,
        design=design,
        host_environment=host_environment,
    )
    lab_source_files_digest = verify_manifested_source_tree(
        PROJECT_ROOT,
        private_manifest,
        prefix="lab",
        role="lab-source",
    )
    registered_ci_workflow_digest = verify_registered_ci_workflow_bytes(
        PROJECT_ROOT,
        design,
    )
    codec_source_files_digest = verify_manifested_source_tree(
        arguments.codec_root,
        private_manifest,
        prefix="codec",
        role="codec-source",
    )
    lab_source_manifest_digest = verify_git_source_identity(
        PROJECT_ROOT,
        private_manifest,
        prefix="lab",
        manifest_field="labSourceManifestSHA256",
        commit_field="labCommit",
        tree_field="labTree",
    )
    codec_source_manifest_digest = verify_git_source_identity(
        arguments.codec_root,
        private_manifest,
        prefix="codec",
        manifest_field="codecSourceManifestSHA256",
        commit_field="codecCommit",
        tree_field="codecTree",
    )
    codec_required_files_digest = verify_codec_required_files(
        arguments.codec_root, design
    )
    nist_verification, pulse_verification_digest = verify_nist_evidence(
        evidence_root,
        arguments.nist_trust_manifest,
        expected_trust_manifest_sha256=design["beacon"]["offlineTrustBundleSHA256"],
        expected_root_der_sha256=design["beacon"]["nistTrustRootDERsSHA256"],
    )
    external_attempt_time = verify_external_attempt_time_anchor(
        nist_verification, design
    )
    selection, selection_digest, full_ledgers = recompute_selection(
        evidence_root=evidence_root,
        snapshot_registration=arguments.snapshot_registration,
        ledgers_root=arguments.ledgers_root,
        design=design,
        marker=marker,
        nist_verification=nist_verification,
    )
    corpora, model_order, selected_revisions = validate_selection(
        selection, design, marker["snapshotRegistrationSHA256"]
    )
    manifest_path = beneath(evidence_root, arguments.manifest)
    manifest, manifest_digest = verify_sha256_manifest(evidence_root, manifest_path)
    raw_relative = relative_argument(arguments.raw_tokens, label="raw-token evidence")
    container_relative = relative_argument(
        arguments.containers, label="container evidence"
    )
    page_token_relative = relative_argument(
        arguments.page_tokens, label="page-token evidence"
    )
    worker_manifest_paths, worker_bindings_digest = verify_worker_bindings(
        evidence_root,
        private_manifest=private_manifest,
        selection=selection,
        design=design,
        marker=marker,
        model_order=model_order,
        raw_relative=raw_relative,
        container_relative=container_relative,
        page_token_relative=page_token_relative,
    )
    raw_tokens = load_canonical_jsonl_beneath(
        evidence_root, raw_relative, maximum_bytes=128 * 1024 * 1024
    )
    containers = load_canonical_jsonl_beneath(
        evidence_root, container_relative, maximum_bytes=64 * 1024 * 1024
    )
    page_tokens = load_canonical_jsonl_beneath(
        evidence_root, page_token_relative, maximum_bytes=16 * 1024 * 1024
    )
    model_specs = {item["key"]: item for item in design["models"]}
    vocabulary_sizes = {
        key: model_specs[key]["vocabSize"] for key in model_specs
    }
    ledger_commitments = extract_ledger_token_commitments(
        {corpus: full_ledgers[corpus] for corpus in corpora},
        models=[item["key"] for item in design["models"]],
        vocabulary_sizes=vocabulary_sizes,
        selected_revisions=selected_revisions,
    )
    page_token_verification = verify_page_token_bindings(
        page_tokens,
        raw_tokens,
        suite_id=design["suiteId"],
        attempt_id=marker["attemptId"],
        models=model_order,
        corpora=corpora,
        vocabulary_sizes=vocabulary_sizes,
        selected_revisions=selected_revisions,
        ledger_token_commitments=ledger_commitments,
    )
    try:
        model_replay_summary = run_independent_model_replay(
            evidence_root=evidence_root,
            private_root=arguments.private_root,
            design=design,
            selection=selection,
            marker=marker,
            private_manifest=private_manifest,
        )
    except IndependentModelReplayError as error:
        raise EvidenceError(f"independent real-model replay failed: {error}") from error
    model_replay_digest = validate_model_replay_summary(
        model_replay_summary,
        marker=marker,
        design=design,
        selection=selection,
    )
    result = evaluate_evidence(
        raw_tokens,
        containers,
        suite_id=design["suiteId"],
        attempt_id=marker["attemptId"],
        models=model_order,
        corpora=corpora,
        layer_counts={key: model_specs[key]["layers"] for key in model_order},
        bits_by_model={
            key: model_specs[key]["candidateBitsByLayer"] for key in model_order
        },
        selected_revisions=selected_revisions,
        counts_toward_scientific_verdict=True,
        evidence_root=evidence_root,
        codec_root=arguments.codec_root,
    )
    required_manifest_paths = {
        RESERVATION_FILENAME,
        ATTEMPT_FILENAME,
        SELECTION_PATH,
        NIST_REQUEST_URI_PATH,
        NIST_RESPONSE_HEADERS_PATH,
        NIST_RESPONSE_BODY_PATH,
        NIST_VERIFICATION_PATH,
        PRIVATE_SNAPSHOT_MANIFEST_PATH,
        HOST_ENVIRONMENT_PATH,
        raw_relative,
        container_relative,
        page_token_relative,
        *worker_manifest_paths,
        *(record["relativePath"] for record in containers),
    }
    require_manifest_paths(manifest, required_manifest_paths)
    scientific_result = canonical_scientific_result(
        result,
        selection_sha256=selection_digest,
        pulse_verification_sha256=pulse_verification_digest,
    )
    producer_raw = read_external_file(arguments.result, maximum_bytes=16 * 1024 * 1024)
    producer_result = load_canonical_line(producer_raw, label="producer result")
    if producer_result != scientific_result:
        raise EvidenceError("producer result differs from independent recomputation")
    producer_digest = hashlib.sha256(producer_raw).hexdigest()
    result.update(
        {
            "designFileSHA256": design_digest,
            "snapshotRegistrationSHA256": marker["snapshotRegistrationSHA256"],
            "designPublicationReceiptSHA256": design_publication_receipt_digest,
            "snapshotPublicationReceiptSHA256": snapshot_publication_receipt_digest,
            "githubGateReceiptSHA256": github_gate_receipt_digest,
            "selectionSHA256": selection_digest,
            "pulseVerificationSHA256": pulse_verification_digest,
            "attemptStartExternalTime": external_attempt_time,
            "evidenceManifestSHA256": manifest_digest,
            "attemptMarkerFileSHA256": hashlib.sha256(
                canonical_json_bytes(marker) + b"\n"
            ).hexdigest(),
            "attemptReservationFileSHA256": reservation_digest,
            "producerResultSHA256": producer_digest,
            "producerResultExactMatch": True,
            "codecRequiredFilesSHA256": codec_required_files_digest,
            "codecSourceFilesSHA256": codec_source_files_digest,
            "labSourceFilesSHA256": lab_source_files_digest,
            "codecSourceManifestSHA256": codec_source_manifest_digest,
            "labSourceManifestSHA256": lab_source_manifest_digest,
            "registeredCIWorkflowSHA256": registered_ci_workflow_digest,
            "designCIArtifactSHA256": design_ci_artifact_digests,
            **provenance_digests,
            "workerBindingsSHA256": worker_bindings_digest,
            "pageTokenBindingsSHA256": page_token_verification["bindingSHA256"],
            "modelReplaySummary": model_replay_summary,
            "modelReplaySummarySHA256": model_replay_digest,
        }
    )
    raw = canonical_json_bytes(result) + b"\n"
    if arguments.output is None:
        sys.stdout.buffer.write(raw)
    else:
        flags = "xb"
        with arguments.output.open(flags) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
