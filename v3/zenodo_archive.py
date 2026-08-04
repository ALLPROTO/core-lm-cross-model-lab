#!/usr/bin/env python3
"""Deterministic Zenodo deposit manifests and fail-closed offline receipts.

The manifest commits the complete local deposit payload except for the
manifest itself.  The receipt separately commits the manifest bytes and checks
that the three archived Zenodo API bodies consistently describe exactly the
manifested files plus that manifest.  The archived responses are not signed by
Zenodo: offline replay proves structural consistency, not Zenodo origin or
authoritative server time.  Zenodo currently exposes MD5 in its file metadata;
this module therefore checks the observed size/MD5 twice (deposition and record
APIs) while independently checking every local byte count/SHA-256 against the
manifest.

No function in this module performs network access or publishes a record.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from v3.protocol import load_json_strict_bytes
from v3.github_gate_receipt import (
    REQUIRED_WORKFLOW_NAME,
    REQUIRED_WORKFLOW_PATH,
    GitHubGateReceiptError,
    verify_github_gate_receipt,
)
from v3.github_release_attestation import (
    ReleaseAttestationError,
    verify_attestation_record,
)
from v3.release_receipt import (
    REQUIRED_ASSET_ROLES,
    ReleaseAttestationCryptographicVerifier,
    ReleaseReceiptError,
    VerifiedReleaseReceipt,
    verify_release_receipt,
)
from v3.release_attestation_crypto import (
    ReleaseAttestationCryptoError,
    validate_known_answer_result,
)
from v3.reproducibility import canonical_json_bytes, write_new_bytes
from v3.source_archive import SourceArchiveError, verify_source_archive


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
MANIFEST_SCHEMA_VERSION = "corelm-zenodo-deposit-manifest-v1"
RECEIPT_SCHEMA_VERSION = "corelm-zenodo-deposit-receipt-v1"
MANIFEST_FILE_NAME = "zenodo-deposit-manifest.json"
API_PROFILE = "production-authenticated-read-only-v1"
EVIDENCE_BOUNDARY = (
    "DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_ZENODO_RESPONSE_SIGNATURE;"
    "OFFLINE_STRUCTURAL_CONSISTENCY_ONLY"
)
ZENODO_HOST = "zenodo.org"
ZENODO_API_BASE = "https://zenodo.org/api"
KINDS = frozenset(("design", "snapshot", "evidence", "closeout"))
FILE_ROLES = frozenset(
    (
        "github-release-asset",
        "github-release-receipt",
        "github-gate-receipt",
        "release-specific-citation",
        "rights-metadata",
        "license-material",
        "notice",
        "sbom",
        "signed-tag-verification",
        "linux-ci-artifact",
        "macos-arm64-ci-artifact",
        "lab-source-archive",
        "codec-source-archive",
        "other-provenance",
    )
)
REQUIRED_SUPERSET_ROLES = frozenset(
    (
        "github-release-receipt",
        "github-gate-receipt",
        "release-specific-citation",
        "rights-metadata",
        "license-material",
        "notice",
        "sbom",
        "signed-tag-verification",
        "linux-ci-artifact",
        "macos-arm64-ci-artifact",
        "lab-source-archive",
        "codec-source-archive",
    )
)
API_ROLES = ("deposition", "deposition-files", "record")
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MD5 = re.compile(r"[0-9a-f]{32}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
RIGHTS_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
GITHUB_ASSET_ROLE = re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z")
MEDIA_TYPE = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")
DOI = re.compile(r"10\.5281/zenodo\.([1-9][0-9]*)\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MAXIMUM_MANIFEST_BYTES = 16 * 1024 * 1024
MAXIMUM_RECEIPT_BYTES = 64 * 1024 * 1024
MAXIMUM_API_BODY_BYTES = 16 * 1024 * 1024
MAXIMUM_HEADER_BYTES = 256 * 1024
MAXIMUM_FILE_BYTES = 50_000_000_000
MAXIMUM_FILE_COUNT = 100
READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_SEMANTIC_FILE_BYTES = 2 * 1024 * 1024 * 1024
RIGHTS_METADATA_SCHEMA_VERSION = "corelm-zenodo-rights-metadata-v1"
SIGNED_TAG_PROJECTION_SCHEMA_VERSION = "corelm-signed-tag-verification-v1"
CI_PAYLOADS = {
    "linux-ci-artifact": {
        "system": "Linux",
        "machine": "x86_64",
        "files": {
            "v3-preflight-linux.json",
            "v3-runtime-linux.json",
            "v3-zero-skip-linux.log",
            "v3-design-check-linux.json",
            "v3-release-attestation-known-answer-linux.json",
        },
        "suffix": "linux",
        "cosignPlatform": "linux/amd64",
    },
    "macos-arm64-ci-artifact": {
        "system": "Darwin",
        "machine": "arm64",
        "files": {
            "v3-preflight-macos.json",
            "v3-runtime-macos.json",
            "v3-zero-skip-macos.log",
            "v3-design-check-macos.json",
            "v3-release-attestation-known-answer-macos.json",
        },
        "suffix": "macos",
        "cosignPlatform": "darwin/arm64",
    },
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


class ZenodoArchiveError(ValueError):
    """A deposit manifest or archived Zenodo receipt is inconsistent."""


@dataclass(frozen=True)
class HTTPSCapture:
    status_code: int
    response_headers: bytes
    response_body: bytes
    captured_at: str


@dataclass(frozen=True)
class VerifiedZenodoReceipt:
    deposition_id: int
    record_id: int
    doi: str
    release_kind: str
    manifest_sha256: str
    receipt_sha256: str
    file_sha256: tuple[tuple[str, str], ...]


ReleaseReceiptVerifier = Callable[..., VerifiedReleaseReceipt]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ZenodoArchiveError(f"{label} fields differ from the canonical contract")
    return value


def _positive_integer(value: Any, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ZenodoArchiveError(f"{label} must be a positive integer")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ZenodoArchiveError(f"{label} must be lowercase SHA-256")
    return value


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise ZenodoArchiveError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ZenodoArchiveError(f"{label} is not a real timestamp") from error


def _date(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or DATE.fullmatch(value) is None:
        raise ZenodoArchiveError(f"{label} must be an ISO calendar date")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as error:
        raise ZenodoArchiveError(f"{label} is not a real date") from error
    return value


def _relative_path(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 512
        or "\\" in value
        or "\0" in value
        or value.startswith("/")
        or value.endswith("/")
    ):
        raise ZenodoArchiveError(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != value:
        raise ZenodoArchiveError(f"{label} is not a normalized relative path")
    for character in value:
        if not (character.isascii() and (character.isalnum() or character in "._/+ -")):
            raise ZenodoArchiveError(f"{label} contains a non-portable character")
    if not value[0].isalnum():
        raise ZenodoArchiveError(f"{label} must begin with an ASCII alphanumeric")
    return value


def _safe_regular_hashes(path: Path, *, maximum_bytes: int = MAXIMUM_FILE_BYTES) -> dict[str, Any]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ZenodoArchiveError(f"not a readable no-follow file: {absolute}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 <= before.st_size <= maximum_bytes
        ):
            raise ZenodoArchiveError(f"file type or byte count is invalid: {absolute}")
        sha = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ZenodoArchiveError(f"file exceeds byte limit: {absolute}")
            sha.update(chunk)
            md5.update(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or observed != before.st_size
        ):
            raise ZenodoArchiveError(f"file changed while hashing: {absolute}")
        return {"bytes": observed, "sha256": sha.hexdigest(), "md5": md5.hexdigest()}
    finally:
        os.close(descriptor)


def _safe_root(root: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(root)))
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        raise ZenodoArchiveError("deposit root is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ZenodoArchiveError("deposit root must be a non-symlink directory")
    return absolute


def _inventory_root(root: Path) -> dict[str, dict[str, Any]]:
    root = _safe_root(root)
    result: dict[str, dict[str, Any]] = {}
    stack: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath())]
    while stack:
        directory, relative_directory = stack.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda child: os.fsencode(child.name))
        for child in children:
            relative = relative_directory / child.name
            normalized = _relative_path(relative.as_posix(), label="deposit file path")
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ZenodoArchiveError(f"deposit tree contains a symlink: {normalized}")
            if stat.S_ISDIR(metadata.st_mode):
                stack.append((Path(child.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                result[normalized] = _safe_regular_hashes(Path(child.path))
            else:
                raise ZenodoArchiveError(
                    f"deposit tree contains an unsupported entry: {normalized}"
                )
    if not 2 <= len(result) <= MAXIMUM_FILE_COUNT - 1:
        raise ZenodoArchiveError("deposit payload must contain 2..99 regular files")
    return result


def _canonical_document(raw: bytes, *, label: str, maximum_bytes: int) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= maximum_bytes
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ZenodoArchiveError(f"{label} must be bounded and end in exactly one LF")
    try:
        value = load_json_strict_bytes(raw[:-1], label=label)
    except ValueError as error:
        raise ZenodoArchiveError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict) or raw != canonical_json_bytes(value) + b"\n":
        raise ZenodoArchiveError(f"{label} bytes are not canonical JSON")
    return value


def _read_canonical(path: Path, *, label: str, maximum_bytes: int) -> tuple[bytes, dict[str, Any]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ZenodoArchiveError(f"{label} is not a readable no-follow file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            raise ZenodoArchiveError(f"{label} type or byte count is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ZenodoArchiveError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or observed != before.st_size
        ):
            raise ZenodoArchiveError(f"{label} changed while reading")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    return raw, _canonical_document(raw, label=label, maximum_bytes=maximum_bytes)


def _read_stable_bytes(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = MAXIMUM_SEMANTIC_FILE_BYTES,
) -> bytes:
    """Read one stable no-follow regular file without trusting its suffix."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ZenodoArchiveError(f"{label} is not a readable no-follow file") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ZenodoArchiveError(
                f"{label} must be a unique bounded regular file"
            )
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ZenodoArchiveError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_mode,
                before.st_nlink,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_mode,
                after.st_nlink,
            )
            or observed != before.st_size
        ):
            raise ZenodoArchiveError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise ZenodoArchiveError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise ZenodoArchiveError(f"{label} must contain one JSON object")
    return value


def _verify_self_digest(value: Mapping[str, Any], *, label: str) -> None:
    digest = _digest(value.get("contentSHA256"), label=f"{label} contentSHA256")
    unsigned = dict(value)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != digest:
        raise ZenodoArchiveError(f"{label} contentSHA256 differs")


def _archive_path(value: str, *, label: str) -> str:
    if value.endswith("/"):
        value = value[:-1]
    return _relative_path(value, label=label)


def _tar_inventory(
    raw: bytes,
    *,
    label: str,
) -> dict[str, tuple[int, bytes]]:
    """Read an uncompressed tar in memory, rejecting links and path tricks."""

    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except (OSError, tarfile.TarError) as error:
        raise ZenodoArchiveError(f"{label} is not a valid uncompressed tar") from error
    files: dict[str, tuple[int, bytes]] = {}
    directories: set[str] = set()
    total = 0
    try:
        for member in archive:
            name = _archive_path(member.name, label=f"{label} member")
            if member.isdev() or member.issym() or member.islnk() or member.isfifo():
                raise ZenodoArchiveError(f"{label} contains a linked or special member")
            if member.isdir():
                if name in directories or name in files:
                    raise ZenodoArchiveError(f"{label} contains duplicate members")
                directories.add(name)
                continue
            if not member.isreg() or name in files or name in directories:
                raise ZenodoArchiveError(f"{label} contains an unsupported or duplicate member")
            if member.size < 0 or member.size > MAXIMUM_SEMANTIC_FILE_BYTES:
                raise ZenodoArchiveError(f"{label} member exceeds its byte bound")
            source = archive.extractfile(member)
            if source is None:
                raise ZenodoArchiveError(f"{label} member bytes are unavailable")
            payload = source.read(member.size + 1)
            if len(payload) != member.size:
                raise ZenodoArchiveError(f"{label} member byte count differs")
            total += len(payload)
            if total > MAXIMUM_SEMANTIC_FILE_BYTES:
                raise ZenodoArchiveError(f"{label} expanded bytes exceed their bound")
            files[name] = (member.mode, payload)
    except (OSError, tarfile.TarError) as error:
        raise ZenodoArchiveError(f"{label} cannot be read safely") from error
    finally:
        archive.close()
    if not files:
        raise ZenodoArchiveError(f"{label} contains no regular files")
    return files


def _verify_source_archive_role(
    path: Path,
    *,
    label: str,
    expected_commit: str,
    expected_tree: str,
) -> None:
    try:
        report = verify_source_archive(
            path,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            maximum_archive_bytes=MAXIMUM_SEMANTIC_FILE_BYTES,
        )
    except (SourceArchiveError, OSError, ValueError) as error:
        raise ZenodoArchiveError(
            f"{label} is not the canonical source-manifest/ustar archive"
        ) from error
    if report.commit != expected_commit or report.tree != expected_tree:
        raise ZenodoArchiveError(f"{label} source identity differs")


def _component_tree(component: Mapping[str, Any], *, label: str) -> str:
    properties = component.get("properties")
    if not isinstance(properties, list):
        raise ZenodoArchiveError(f"{label} lacks CycloneDX properties")
    values = [
        item.get("value")
        for item in properties
        if isinstance(item, dict) and item.get("name") == "corelm:git-tree"
    ]
    if len(values) != 1 or not isinstance(values[0], str) or GIT_OID.fullmatch(values[0]) is None:
        raise ZenodoArchiveError(f"{label} Git tree property differs")
    return values[0]


def _verify_sbom(
    raw: bytes,
    *,
    repository: str,
    lab_commit: str,
    lab_tree: str,
    codec_commit: str | None,
    codec_tree: str | None,
) -> tuple[str, str]:
    sbom = _json_object(raw, label="CycloneDX SBOM")
    if (
        sbom.get("$schema") != "http://cyclonedx.org/schema/bom-1.5.schema.json"
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.5"
        or sbom.get("version") != 1
    ):
        raise ZenodoArchiveError("SBOM is not the canonical CycloneDX 1.5 profile")
    metadata = sbom.get("metadata")
    lab = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(lab, dict):
        raise ZenodoArchiveError("SBOM lacks the laboratory component")
    expected_purl = f"pkg:github/{repository}@{lab_commit}"
    if lab.get("version") != lab_commit or lab.get("purl") != expected_purl:
        raise ZenodoArchiveError("SBOM laboratory source identity differs")
    if _component_tree(lab, label="SBOM laboratory component") != lab_tree:
        raise ZenodoArchiveError("SBOM laboratory tree differs")
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ZenodoArchiveError("SBOM component list is absent")
    codecs = [
        component
        for component in components
        if isinstance(component, dict)
        and component.get("name") == "VoidToken codec"
        and isinstance(component.get("purl"), str)
        and component["purl"].startswith("pkg:github/ALLPROTO/core-lm-benchmark@")
    ]
    if len(codecs) != 1:
        raise ZenodoArchiveError("SBOM must contain exactly one VoidToken component")
    codec = codecs[0]
    observed_commit = codec.get("version")
    observed_tree = _component_tree(codec, label="SBOM VoidToken component")
    if (
        not isinstance(observed_commit, str)
        or GIT_OID.fullmatch(observed_commit) is None
        or (codec_commit is not None and observed_commit != codec_commit)
        or (codec_tree is not None and observed_tree != codec_tree)
    ):
        raise ZenodoArchiveError("SBOM VoidToken source identity differs")
    return observed_commit, observed_tree


def _github_release_summary(
    raw: bytes,
    receipt_path: str,
    *,
    inventory: Mapping[str, Mapping[str, Any]],
    github_asset_directory: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    receipt = _canonical_document(
        raw, label="GitHub release receipt", maximum_bytes=MAXIMUM_RECEIPT_BYTES
    )
    required_root = {
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
    if set(receipt) != required_root:
        raise ZenodoArchiveError("GitHub receipt root differs from the canonical release contract")
    if (
        receipt.get("schemaVersion") != "corelm-github-release-receipt-v2"
        or receipt.get("suiteId") != SUITE_ID
    ):
        raise ZenodoArchiveError("GitHub receipt schema or suite differs")
    content_digest = _digest(receipt.get("contentSHA256"), label="GitHub receipt content digest")
    unsigned = dict(receipt)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != content_digest:
        raise ZenodoArchiveError("GitHub receipt content digest differs")
    repository = receipt.get("repository")
    release = receipt.get("release")
    source = receipt.get("source")
    if (
        not isinstance(repository, dict)
        or not isinstance(release, dict)
        or not isinstance(source, dict)
    ):
        raise ZenodoArchiveError("GitHub receipt identity records are malformed")
    kind = receipt.get("kind")
    if kind not in KINDS:
        raise ZenodoArchiveError("GitHub release kind is unsupported")
    commit, tree = source.get("commit"), source.get("tree")
    if not isinstance(commit, str) or GIT_OID.fullmatch(commit) is None:
        raise ZenodoArchiveError("GitHub release commit is malformed")
    if not isinstance(tree, str) or GIT_OID.fullmatch(tree) is None:
        raise ZenodoArchiveError("GitHub release tree is malformed")
    published_at = release.get("publishedAt")
    _utc(published_at, label="GitHub release publication time")
    release_id = _positive_integer(release.get("id"), label="GitHub release ID")
    slug, tag = repository.get("slug"), receipt.get("tag")
    if not isinstance(slug, str) or slug.count("/") != 1 or not isinstance(tag, str) or not tag:
        raise ZenodoArchiveError("GitHub repository or tag is malformed")
    assets = receipt.get("requiredAssets")
    if not isinstance(assets, list) or not assets:
        raise ZenodoArchiveError("GitHub release has no required assets")
    role_by_path: dict[str, str] = {}
    observed_roles: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != {
            "role",
            "assetId",
            "name",
            "apiURL",
            "downloadURL",
            "bytes",
            "sha256",
        }:
            raise ZenodoArchiveError("GitHub asset record is malformed")
        role, name = asset.get("role"), asset.get("name")
        if not isinstance(role, str) or GITHUB_ASSET_ROLE.fullmatch(role) is None:
            raise ZenodoArchiveError("GitHub asset role is malformed")
        if not isinstance(name, str) or "/" in name or "\\" in name:
            raise ZenodoArchiveError("GitHub asset name is malformed")
        path = _relative_path(f"{github_asset_directory}/{name}", label="GitHub asset path")
        if path in role_by_path:
            raise ZenodoArchiveError("duplicate GitHub release asset name")
        observed = inventory.get(path)
        if observed is None:
            raise ZenodoArchiveError(f"GitHub release asset is absent from deposit: {path}")
        if observed["bytes"] != asset.get("bytes") or observed["sha256"] != asset.get("sha256"):
            raise ZenodoArchiveError(f"GitHub release asset bytes differ: {path}")
        role_by_path[path] = role
        observed_roles.append(role)
    if tuple(observed_roles) != REQUIRED_ASSET_ROLES[kind]:
        raise ZenodoArchiveError("GitHub receipt required asset roles differ")
    deadline = release.get("deadline")
    receipt_created_at = receipt.get("receiptCreatedAt")
    _utc(deadline, label="GitHub release deadline")
    _utc(receipt_created_at, label="GitHub receipt creation time")
    try:
        attestation = verify_attestation_record(
            receipt.get("githubReleaseAttestation"),
            expected_repository=slug,
            expected_release_id=release_id,
            expected_tag=tag,
            expected_commit=commit,
            expected_assets=tuple(
                (asset["name"], asset["sha256"]) for asset in assets
            ),
            expected_published_at=published_at,
            expected_receipt_created_at=receipt_created_at,
            expected_deadline=deadline,
            expected_attestation_relation="STRICTLY_BEFORE_DEADLINE",
        )
    except ReleaseAttestationError as error:
        raise ZenodoArchiveError(
            "GitHub immutable-release attestation differs"
        ) from error
    receipt_hashes = inventory.get(receipt_path)
    if (
        receipt_hashes is None
        or receipt_hashes["bytes"] != len(raw)
        or receipt_hashes["sha256"] != _sha256(raw)
    ):
        raise ZenodoArchiveError("GitHub release receipt bytes differ inside deposit")
    return (
        {
            "repository": slug,
            "kind": kind,
            "tag": tag,
            "releaseId": release_id,
            "commit": commit,
            "tree": tree,
            "publishedAt": published_at,
            "attestedAt": attestation.attested_at,
            "releaseAttestationBundleSHA256": attestation.bundle_sha256,
            "releaseAttestationOutputSHA256": attestation.raw_output_sha256,
            "receiptPath": receipt_path,
            "receiptBytes": len(raw),
            "receiptSHA256": _sha256(raw),
            "receiptContentSHA256": content_digest,
        },
        role_by_path,
    )


def _verify_deposited_github_release_receipt(
    raw: bytes,
    *,
    asset_root: Path,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ),
    release_receipt_verifier: ReleaseReceiptVerifier,
) -> VerifiedReleaseReceipt:
    """Replay the complete SSH + Cosign release contract over deposited assets."""

    if cryptographic_attestation_verifier is None or not hasattr(
        cryptographic_attestation_verifier, "verify"
    ):
        raise ZenodoArchiveError(
            "pinned cryptographic release-attestation verifier is required"
        )
    if not callable(release_receipt_verifier):
        raise ZenodoArchiveError("full GitHub release-receipt verifier is required")
    receipt = _canonical_document(
        raw,
        label="GitHub release receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    repository = receipt.get("repository")
    release = receipt.get("release")
    source = receipt.get("source")
    signature = receipt.get("signatureVerification")
    if not all(
        isinstance(value, dict)
        for value in (repository, release, source, signature)
    ):
        raise ZenodoArchiveError(
            "GitHub release receipt lacks complete cryptographic bindings"
        )
    expected = {
        "repository": repository.get("slug"),
        "kind": receipt.get("kind"),
        "tag": receipt.get("tag"),
        "commit": source.get("commit"),
        "tree": source.get("tree"),
        "deadline": release.get("deadline"),
        "signature_type": signature.get("signatureType"),
        "key_fingerprint": signature.get("keyFingerprint"),
        "public_key_sha256": signature.get("publicKeySHA256"),
    }
    try:
        verified = release_receipt_verifier(
            raw,
            asset_root,
            expected_repository=expected["repository"],
            expected_kind=expected["kind"],
            expected_tag=expected["tag"],
            expected_commit=expected["commit"],
            expected_tree=expected["tree"],
            expected_deadline=expected["deadline"],
            expected_signature_type=expected["signature_type"],
            expected_key_fingerprint=expected["key_fingerprint"],
            expected_public_key_sha256=expected["public_key_sha256"],
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
    except (ReleaseReceiptError, OSError, ValueError) as error:
        raise ZenodoArchiveError(
            "deposited GitHub release receipt failed full SSH/Cosign verification"
        ) from error
    for field, attribute in (
        ("repository", "repository"),
        ("kind", "kind"),
        ("tag", "tag"),
        ("commit", "commit"),
        ("tree", "tree"),
        ("signature_type", "signature_type"),
        ("key_fingerprint", "key_fingerprint"),
        ("public_key_sha256", "public_key_sha256"),
    ):
        if getattr(verified, attribute, None) != expected[field]:
            raise ZenodoArchiveError(
                "full GitHub release-receipt verifier returned another identity"
            )
    return verified


def _development_control_archive_summary(raw: bytes) -> dict[str, Any]:
    """Project the independently timestamped development-control release."""

    receipt = _canonical_document(
        raw,
        label="development-control release receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    required_root = {
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
    if set(receipt) != required_root:
        raise ZenodoArchiveError(
            "development-control receipt root differs from the canonical contract"
        )
    if (
        receipt.get("schemaVersion") != "corelm-github-release-receipt-v2"
        or receipt.get("suiteId") != SUITE_ID
        or receipt.get("kind") != "development-control"
    ):
        raise ZenodoArchiveError("development-control receipt identity differs")
    content_digest = _digest(
        receipt.get("contentSHA256"),
        label="development-control receipt content digest",
    )
    unsigned = dict(receipt)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != content_digest:
        raise ZenodoArchiveError("development-control receipt digest differs")

    repository = receipt.get("repository")
    release = receipt.get("release")
    source = receipt.get("source")
    if not all(isinstance(value, dict) for value in (repository, release, source)):
        raise ZenodoArchiveError("development-control receipt records are malformed")
    slug = repository.get("slug")
    tag = receipt.get("tag")
    commit = source.get("commit")
    tree = source.get("tree")
    if (
        not isinstance(slug, str)
        or slug.count("/") != 1
        or not isinstance(tag, str)
        or not tag
        or not isinstance(commit, str)
        or GIT_OID.fullmatch(commit) is None
        or not isinstance(tree, str)
        or GIT_OID.fullmatch(tree) is None
    ):
        raise ZenodoArchiveError("development-control source identity is malformed")
    release_id = _positive_integer(
        release.get("id"), label="development-control release ID"
    )
    published_at = release.get("publishedAt")
    deadline = release.get("deadline")
    receipt_created_at = receipt.get("receiptCreatedAt")
    _utc(published_at, label="development-control publishedAt")
    _utc(deadline, label="development-control deadline")
    _utc(receipt_created_at, label="development-control receiptCreatedAt")

    assets = receipt.get("requiredAssets")
    if not isinstance(assets, list) or len(assets) != len(
        REQUIRED_ASSET_ROLES["development-control"]
    ):
        raise ZenodoArchiveError("development-control asset inventory differs")
    observed_roles: list[str] = []
    expected_assets: list[tuple[str, str]] = []
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) != {
            "role",
            "assetId",
            "name",
            "apiURL",
            "downloadURL",
            "bytes",
            "sha256",
        }:
            raise ZenodoArchiveError("development-control asset record is malformed")
        role = asset.get("role")
        name = asset.get("name")
        digest = asset.get("sha256")
        if (
            not isinstance(role, str)
            or not isinstance(name, str)
            or not name
            or "/" in name
            or "\\" in name
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise ZenodoArchiveError("development-control asset identity is malformed")
        observed_roles.append(role)
        expected_assets.append((name, digest))
    if tuple(observed_roles) != REQUIRED_ASSET_ROLES["development-control"]:
        raise ZenodoArchiveError("development-control asset roles differ")
    try:
        attestation = verify_attestation_record(
            receipt.get("githubReleaseAttestation"),
            expected_repository=slug,
            expected_release_id=release_id,
            expected_tag=tag,
            expected_commit=commit,
            expected_assets=tuple(expected_assets),
            expected_published_at=published_at,
            expected_receipt_created_at=receipt_created_at,
            expected_deadline=deadline,
            expected_attestation_relation="STRICTLY_BEFORE_DEADLINE",
        )
    except ReleaseAttestationError as error:
        raise ZenodoArchiveError(
            "development-control immutable-release attestation differs"
        ) from error
    return {
        "repository": slug,
        "tag": tag,
        "releaseId": release_id,
        "commit": commit,
        "tree": tree,
        "publishedAt": published_at,
        "deadline": deadline,
        "archiveAttestedAt": attestation.attested_at,
        "releaseAttestationBundleSHA256": attestation.bundle_sha256,
        "releaseAttestationOutputSHA256": attestation.raw_output_sha256,
        "receiptSHA256": _sha256(raw),
        "receiptContentSHA256": content_digest,
    }


def _validate_rights_declarations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ZenodoArchiveError("rights declarations must contain 1..32 entries")
    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, raw in enumerate(value):
        item = _mapping(
            raw,
            {"rightsId", "title", "uri", "zenodoIdentifier"},
            label=f"rights declaration {index}",
        )
        rights_id = item["rightsId"]
        if not isinstance(rights_id, str) or RIGHTS_ID.fullmatch(rights_id) is None:
            raise ZenodoArchiveError("rightsId is malformed")
        if rights_id in identifiers:
            raise ZenodoArchiveError("duplicate rightsId")
        identifiers.add(rights_id)
        title, uri, zenodo_identifier = item["title"], item["uri"], item["zenodoIdentifier"]
        if not isinstance(title, str) or not 1 <= len(title) <= 512:
            raise ZenodoArchiveError("rights title is malformed")
        if (
            not isinstance(uri, str)
            or not uri.startswith("https://")
            or any(ch.isspace() for ch in uri)
        ):
            raise ZenodoArchiveError("rights URI must be an absolute HTTPS URL")
        if zenodo_identifier is not None and (
            not isinstance(zenodo_identifier, str) or not 1 <= len(zenodo_identifier) <= 128
        ):
            raise ZenodoArchiveError("Zenodo rights identifier is malformed")
        result.append(dict(item))
    result.sort(key=lambda item: item["rightsId"].encode("ascii"))
    return result


def _zenodo_reservation(value: Any) -> dict[str, Any]:
    item = _mapping(
        value,
        {"depositionId", "recordId", "doi"},
        label="Zenodo reservation",
    )
    deposition_id = _positive_integer(item["depositionId"], label="deposition ID")
    record_id = _positive_integer(item["recordId"], label="record ID")
    doi = item["doi"]
    match = DOI.fullmatch(doi) if isinstance(doi, str) else None
    if match is None or int(match.group(1)) != record_id:
        raise ZenodoArchiveError("reservation DOI is not a production version DOI")
    return {"depositionId": deposition_id, "recordId": record_id, "doi": doi}


def _github_gate_summary(
    raw: bytes,
    *,
    receipt_path: str,
    expected_implementation_commit: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    gate = _canonical_document(
        raw, label="GitHub gate receipt", maximum_bytes=MAXIMUM_RECEIPT_BYTES
    )
    repository = gate.get("repository")
    author_verification = gate.get("authorVerification")
    ci = gate.get("ciGate")
    if (
        not isinstance(repository, dict)
        or not isinstance(author_verification, dict)
        or not isinstance(ci, dict)
    ):
        raise ZenodoArchiveError("GitHub gate identity records are malformed")
    try:
        verified = verify_github_gate_receipt(
            raw,
            expected_repository=repository.get("slug"),
            expected_pull_request_number=gate.get("pullRequestNumber"),
            expected_implementation_commit=expected_implementation_commit,
            expected_workflow_run_id=ci.get("runId"),
            expected_workflow_name=REQUIRED_WORKFLOW_NAME,
            expected_workflow_path=REQUIRED_WORKFLOW_PATH,
        )
    except (GitHubGateReceiptError, TypeError, ValueError) as error:
        raise ZenodoArchiveError(
            "GitHub gate receipt failed canonical offline verification"
        ) from error
    artifacts = dict(verified.artifact_sha256)
    linux = [name for name in artifacts if name.startswith("author-v3-linux-development-")]
    macos = [name for name in artifacts if name.startswith("author-v3-macos-development-")]
    if len(artifacts) != 2 or len(linux) != 1 or len(macos) != 1:
        raise ZenodoArchiveError("GitHub gate must bind one Linux and one macOS artifact")
    return (
        {
            "receiptPath": receipt_path,
            "receiptBytes": len(raw),
            "receiptSHA256": _sha256(raw),
            "implementationCommit": verified.implementation_commit,
            "workflowRunId": verified.workflow_run_id,
            "artifactCount": len(artifacts),
        },
        artifacts,
    )


def _zip_inventory(raw: bytes, *, label: str) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), mode="r")
    except (OSError, zipfile.BadZipFile) as error:
        raise ZenodoArchiveError(f"{label} is not a valid ZIP archive") from error
    result: dict[str, bytes] = {}
    total = 0
    try:
        for member in archive.infolist():
            name = _archive_path(member.filename, label=f"{label} member")
            unix_type = (member.external_attr >> 16) & 0o170000
            if (
                member.is_dir()
                or member.flag_bits & 0x1
                or unix_type == stat.S_IFLNK
                or name in result
                or member.file_size > MAXIMUM_SEMANTIC_FILE_BYTES
            ):
                raise ZenodoArchiveError(f"{label} contains an unsafe ZIP member")
            try:
                payload = archive.read(member)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise ZenodoArchiveError(f"{label} ZIP member cannot be verified") from error
            if len(payload) != member.file_size:
                raise ZenodoArchiveError(f"{label} ZIP member byte count differs")
            total += len(payload)
            if total > MAXIMUM_SEMANTIC_FILE_BYTES:
                raise ZenodoArchiveError(f"{label} expanded bytes exceed their bound")
            result[name] = payload
    finally:
        archive.close()
    return result


def _source_identity(
    value: Any,
    *,
    label: str,
    commit: str,
    tree: str,
    repository: str,
) -> None:
    expected_origin = f"https://github.com/{repository}"
    origin = value.get("origin") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value)
        != {"commit", "tree", "origin", "worktreeClean", "worktreeStatusSHA256"}
        or value.get("commit") != commit
        or value.get("tree") != tree
        or not isinstance(origin, str)
        or origin.removesuffix(".git") != expected_origin
        or value.get("worktreeClean") is not True
        or value.get("worktreeStatusSHA256") != _sha256(b"")
    ):
        raise ZenodoArchiveError(f"{label} source identity differs")


def _verify_runtime_manifest(
    raw: bytes,
    *,
    label: str,
    system: str,
    machine: str,
    lab_commit: str,
    lab_tree: str,
    codec_commit: str,
    codec_tree: str,
    lab_repository: str,
    codec_repository: str = "ALLPROTO/core-lm-benchmark",
) -> dict[str, Any]:
    runtime = _json_object(raw, label=label)
    _verify_self_digest(runtime, label=label)
    python = runtime.get("python")
    host = runtime.get("host")
    executable = python.get("executable") if isinstance(python, dict) else None
    environment = runtime.get("environment")
    locks = runtime.get("requirementsLocks")
    distributions = runtime.get("installedDistributions")
    platform_pattern = (
        r"linux-[A-Za-z0-9_.-]*x86_64"
        if system == "Linux"
        else r"macosx-[A-Za-z0-9_.-]+-arm64"
    )
    if (
        set(runtime) != RUNTIME_MANIFEST_FIELDS
        or runtime.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v3-runtime-manifest-v1"
        or runtime.get("status") != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
        or runtime.get("countsTowardScientificVerdict") is not False
        or runtime.get("networkUsed") is not False
        or runtime.get("modelInferenceUsed") is not False
        or not isinstance(python, dict)
        or python.get("registeredVersion") != "3.12.10"
        or python.get("version") != "3.12.10"
        or not isinstance(python.get("platformTag"), str)
        or re.fullmatch(platform_pattern, python["platformTag"]) is None
        or not isinstance(executable, dict)
        or type(executable.get("bytes")) is not int
        or executable["bytes"] <= 0
        or SHA256.fullmatch(str(executable.get("sha256"))) is None
        or not isinstance(host, dict)
        or set(host)
        != {"system", "release", "version", "machine", "processor", "macVersion"}
        or host.get("system") != system
        or host.get("machine") != machine
        or not isinstance(host.get("release"), str)
        or not host["release"]
        or not isinstance(host.get("version"), str)
        or not host["version"]
        or not isinstance(host.get("processor"), str)
        or (system == "Darwin" and not isinstance(host.get("macVersion"), str))
        or (system == "Linux" and host.get("macVersion") is not None)
        or not isinstance(environment, dict)
        or set(environment) != RUNTIME_ENVIRONMENT_KEYS
        or any(
            value is not None and not isinstance(value, str)
            for value in environment.values()
        )
        or not isinstance(locks, list)
        or not locks
        or not isinstance(distributions, list)
        or not distributions
        or runtime.get("installedDistributionCount") != len(distributions)
        or type(runtime.get("basePythonDistinctFromRuntime")) is not bool
    ):
        raise ZenodoArchiveError(f"{label} runtime/profile identity differs")
    for lock in locks:
        if (
            not isinstance(lock, dict)
            or set(lock) != {"name", "bytes", "sha256"}
            or not isinstance(lock.get("name"), str)
            or not lock["name"]
            or type(lock.get("bytes")) is not int
            or lock["bytes"] <= 0
            or SHA256.fullmatch(str(lock.get("sha256"))) is None
        ):
            raise ZenodoArchiveError(f"{label} requirements-lock inventory differs")
    for field in ("runtimeTree", "basePythonTree"):
        tree_inventory = runtime.get(field)
        if (
            not isinstance(tree_inventory, dict)
            or set(tree_inventory)
            != {"entries", "entryCount", "regularFileBytes", "treeSHA256"}
            or not isinstance(tree_inventory.get("entries"), list)
            or not tree_inventory["entries"]
            or tree_inventory.get("entryCount") != len(tree_inventory["entries"])
            or type(tree_inventory.get("regularFileBytes")) is not int
            or tree_inventory["regularFileBytes"] <= 0
            or SHA256.fullmatch(str(tree_inventory.get("treeSHA256"))) is None
        ):
            raise ZenodoArchiveError(f"{label} {field} inventory differs")
    _source_identity(
        runtime.get("labSource"),
        label=f"{label} lab",
        commit=lab_commit,
        tree=lab_tree,
        repository=lab_repository,
    )
    _source_identity(
        runtime.get("codecSource"),
        label=f"{label} codec",
        commit=codec_commit,
        tree=codec_tree,
        repository=codec_repository,
    )
    return runtime


def _verify_ci_payload(
    raw: bytes,
    *,
    role: str,
    lab_commit: str,
    lab_tree: str,
    codec_commit: str,
    codec_tree: str,
    lab_repository: str,
) -> None:
    profile = CI_PAYLOADS[role]
    suffix = profile["suffix"]
    payloads = _zip_inventory(raw, label=role)
    if set(payloads) != profile["files"]:
        raise ZenodoArchiveError(f"{role} must contain the exact five CI payloads")
    _verify_runtime_manifest(
        payloads[f"v3-runtime-{suffix}.json"],
        label=f"{role} runtime manifest",
        system=profile["system"],
        machine=profile["machine"],
        lab_commit=lab_commit,
        lab_tree=lab_tree,
        codec_commit=codec_commit,
        codec_tree=codec_tree,
        lab_repository=lab_repository,
    )
    preflight = _json_object(
        payloads[f"v3-preflight-{suffix}.json"], label=f"{role} preflight"
    )
    platform = preflight.get("platformSafety")
    codec = preflight.get("codec")
    if (
        preflight.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-preflight-v1"
        or preflight.get("status") != "DEVELOPMENT_PREFLIGHT_ONLY"
        or preflight.get("countsTowardScientificVerdict") is not False
        or preflight.get("networkUsed") is not False
        or preflight.get("modelInferenceUsed") is not False
        or preflight.get("corpusOpened") is not False
        or preflight.get("attemptMarkerCreated") is not False
        or not isinstance(platform, dict)
        or platform.get("system") != profile["system"]
        or platform.get("machine") != profile["machine"]
        or not isinstance(codec, dict)
        or codec.get("commit") != codec_commit
        or codec.get("tree") != codec_tree
    ):
        raise ZenodoArchiveError(f"{role} preflight does not prove the expected controls")
    check = _json_object(
        payloads[f"v3-design-check-{suffix}.json"], label=f"{role} design check"
    )
    if (
        check.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-design-check-v1"
        or check.get("status") != "DRAFT_VERIFIED_NOT_PREREGISTERED"
        or check.get("countsTowardScientificVerdict") is not False
        or check.get("networkUsed") is not False
        or check.get("modelInferenceUsed") is not False
        or check.get("corpusOpened") is not False
    ):
        raise ZenodoArchiveError(f"{role} design check does not prove offline validation")
    known_answer = _json_object(
        payloads[f"v3-release-attestation-known-answer-{suffix}.json"],
        label=f"{role} release-attestation known answer",
    )
    try:
        validate_known_answer_result(
            known_answer,
            expected_platform=profile["cosignPlatform"],
        )
    except ReleaseAttestationCryptoError as error:
        raise ZenodoArchiveError(
            f"{role} release-attestation known answer differs"
        ) from error
    try:
        log = payloads[f"v3-zero-skip-{suffix}.log"].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ZenodoArchiveError(f"{role} zero-skip log is not UTF-8") from error
    matches = re.findall(r"(?m)^ZERO-SKIP POLICY PASS: ([1-9][0-9]*) tests, 0 skipped$", log)
    if len(matches) != 1 or "ZERO-SKIP POLICY FAIL:" in log or "FAILED (" in log:
        raise ZenodoArchiveError(f"{role} does not contain one terminal zero-skip PASS")


def _verify_citation(
    raw: bytes,
    *,
    repository: str,
    tag: str,
    doi: str,
    published_at: str,
) -> None:
    """Validate the release CFF encoded as deterministic JSON/YAML 1.2 bytes."""

    citation = _canonical_document(
        raw, label="release-specific CITATION.cff", maximum_bytes=4 * 1024 * 1024
    )
    repository_url = f"https://github.com/{repository}"
    authors = citation.get("authors")
    identifiers = citation.get("identifiers")
    if (
        citation.get("cff-version") != "1.2.0"
        or citation.get("type") != "software"
        or citation.get("version") != tag
        or citation.get("date-released") != published_at[:10]
        or citation.get("repository-code") != repository_url
        or not isinstance(authors, list)
        or sum(
            isinstance(author, dict)
            and author.get("family-names") == "Tyshchenko"
            and author.get("given-names") == "Ivan"
            and author.get("orcid") == "https://orcid.org/0009-0000-7935-6090"
            for author in authors
        )
        != 1
        or not isinstance(identifiers, list)
        or sum(
            isinstance(identifier, dict)
            and identifier.get("type") == "doi"
            and identifier.get("value") == doi
            for identifier in identifiers
        )
        != 1
    ):
        raise ZenodoArchiveError("release-specific CITATION.cff identity differs")


def _verify_rights_metadata(
    raw: bytes,
    *,
    release_kind: str,
    doi: str,
    rights: Sequence[Mapping[str, Any]],
    files: Sequence[Mapping[str, Any]],
    manifest_rights: Sequence[str],
) -> None:
    metadata = _canonical_document(
        raw, label="rights metadata", maximum_bytes=16 * 1024 * 1024
    )
    _mapping(
        metadata,
        {
            "schemaVersion",
            "suiteId",
            "releaseKind",
            "doi",
            "rightsDeclarations",
            "fileRights",
            "contentSHA256",
        },
        label="rights metadata",
    )
    _verify_self_digest(metadata, label="rights metadata")
    expected_file_rights = [
        {"path": item["path"], "rightsIds": item["rightsIds"]} for item in files
    ] + [{"path": MANIFEST_FILE_NAME, "rightsIds": list(manifest_rights)}]
    expected_file_rights.sort(key=lambda item: item["path"].encode("utf-8"))
    if (
        metadata["schemaVersion"] != RIGHTS_METADATA_SCHEMA_VERSION
        or metadata["suiteId"] != SUITE_ID
        or metadata["releaseKind"] != release_kind
        or metadata["doi"] != doi
        or metadata["rightsDeclarations"] != list(rights)
        or metadata["fileRights"] != expected_file_rights
    ):
        raise ZenodoArchiveError("rights metadata does not bind the exact deposit")


def _verify_notice(
    raw: bytes,
    *,
    repository: str,
    doi: str,
    rights: Sequence[Mapping[str, Any]],
) -> None:
    try:
        notice = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ZenodoArchiveError("NOTICE is not strict UTF-8") from error
    required = [doi, repository]
    required.extend(item["rightsId"] for item in rights)
    if not raw.endswith(b"\n") or any(value not in notice for value in required):
        raise ZenodoArchiveError("NOTICE omits DOI, repository, or declared rights")


def _verify_license_material(raw: bytes, *, codec_commit: str) -> None:
    files = _tar_inventory(raw, label="LICENSES archive")
    if all(path.startswith("LICENSES/") for path in files):
        files = {path[len("LICENSES/") :]: value for path, value in files.items()}
    if not {"ASSET_LICENSES.md", "README.md", "source-evidence.json"}.issubset(files):
        raise ZenodoArchiveError("LICENSES archive omits its matrix or source evidence")
    evidence = _json_object(files["source-evidence.json"][1], label="license source evidence")
    sources = evidence.get("sources")
    if (
        evidence.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v2-license-source-evidence-v1"
        or evidence.get("status") != "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED"
        or not isinstance(sources, list)
        or not sources
    ):
        raise ZenodoArchiveError("license source evidence identity differs")
    codec_sources = 0
    for source in sources:
        if not isinstance(source, dict):
            raise ZenodoArchiveError("license source evidence record is malformed")
        path = source.get("archivedPath")
        if not isinstance(path, str) or path not in files:
            raise ZenodoArchiveError("license source evidence bytes are absent")
        stored = files[path][1]
        encoding = source.get("archivedEncoding")
        if encoding == "identity":
            payload = stored
        elif encoding == "base64":
            try:
                compact = b"".join(stored.split())
                payload = base64.b64decode(compact, validate=True)
            except ValueError as error:
                raise ZenodoArchiveError("license evidence base64 is invalid") from error
        else:
            raise ZenodoArchiveError("license source evidence encoding is unsupported")
        if source.get("bytes") != len(payload) or source.get("sha256") != _sha256(payload):
            raise ZenodoArchiveError("license source evidence digest differs")
        if source.get("repository") == "ALLPROTO/core-lm-benchmark":
            codec_sources += 1
            if source.get("revision") != codec_commit:
                raise ZenodoArchiveError("codec license evidence revision differs")
    if codec_sources != 1:
        raise ZenodoArchiveError("LICENSES archive must bind one codec license source")


def _verify_signed_tag_projection(
    raw: bytes,
    *,
    release_receipt_raw: bytes,
    release_receipt: Mapping[str, Any],
    github_release: Mapping[str, Any],
) -> None:
    projection = _canonical_document(
        raw, label="signed-tag verification projection", maximum_bytes=16 * 1024 * 1024
    )
    _mapping(
        projection,
        {
            "schemaVersion",
            "suiteId",
            "status",
            "repository",
            "tag",
            "commit",
            "tree",
            "signatureType",
            "keyFingerprint",
            "publicKeySHA256",
            "tagObjectOID",
            "verifiedAt",
            "attestedAt",
            "releaseAttestationBundleSHA256",
            "releaseAttestationOutputSHA256",
            "releaseReceiptSHA256",
            "transcriptSHA256",
            "contentSHA256",
        },
        label="signed-tag verification projection",
    )
    _verify_self_digest(projection, label="signed-tag verification projection")
    signature = release_receipt.get("signatureVerification")
    tag = release_receipt.get("annotatedTag")
    if not isinstance(signature, dict) or not isinstance(tag, dict):
        raise ZenodoArchiveError("GitHub receipt lacks signed-tag evidence")
    transcript = _archived_bytes(
        signature.get("transcript"),
        label="GitHub signature transcript",
        maximum_bytes=MAXIMUM_API_BODY_BYTES,
    )
    expected = {
        "schemaVersion": SIGNED_TAG_PROJECTION_SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "status": "VERIFIED",
        "repository": github_release["repository"],
        "tag": github_release["tag"],
        "commit": github_release["commit"],
        "tree": github_release["tree"],
        "signatureType": signature.get("signatureType"),
        "keyFingerprint": signature.get("keyFingerprint"),
        "publicKeySHA256": signature.get("publicKeySHA256"),
        "tagObjectOID": tag.get("objectOID"),
        "verifiedAt": signature.get("verifiedAt"),
        "attestedAt": github_release["attestedAt"],
        "releaseAttestationBundleSHA256": github_release[
            "releaseAttestationBundleSHA256"
        ],
        "releaseAttestationOutputSHA256": github_release[
            "releaseAttestationOutputSHA256"
        ],
        "releaseReceiptSHA256": _sha256(release_receipt_raw),
        "transcriptSHA256": _sha256(transcript),
    }
    unsigned = dict(projection)
    unsigned.pop("contentSHA256", None)
    if unsigned != expected:
        raise ZenodoArchiveError("signed-tag projection differs from the GitHub receipt")


def _git_object_oid(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _verify_github_signed_tag_receipt(
    receipt: Mapping[str, Any],
    *,
    github_release: Mapping[str, Any],
) -> Mapping[str, Any]:
    source = _mapping(
        receipt.get("source"),
        {"commit", "tree", "commitObject"},
        label="GitHub release source",
    )
    commit_object = _mapping(
        source["commitObject"],
        {"oid", "rawPayload"},
        label="GitHub commit object",
    )
    commit_payload = _archived_bytes(
        commit_object["rawPayload"],
        label="GitHub raw commit object",
        maximum_bytes=MAXIMUM_API_BODY_BYTES,
    )
    expected_tree_line = f"tree {github_release['tree']}\n".encode("ascii")
    if (
        source["commit"] != github_release["commit"]
        or source["tree"] != github_release["tree"]
        or commit_object["oid"] != github_release["commit"]
        or _git_object_oid("commit", commit_payload) != github_release["commit"]
        or not commit_payload.startswith(expected_tree_line)
        or b"\n\n" not in commit_payload
    ):
        raise ZenodoArchiveError("GitHub raw commit object does not bind the release tree")

    tag = _mapping(
        receipt.get("annotatedTag"),
        {"objectOID", "targetType", "targetCommit", "rawPayload"},
        label="GitHub annotated tag",
    )
    tag_payload = _archived_bytes(
        tag["rawPayload"],
        label="GitHub raw annotated tag",
        maximum_bytes=MAXIMUM_API_BODY_BYTES,
    )
    required_tag_header = (
        f"object {github_release['commit']}\n"
        "type commit\n"
        f"tag {github_release['tag']}\n"
    ).encode("utf-8")
    signature = _mapping(
        receipt.get("signatureVerification"),
        {
            "status",
            "signatureType",
            "method",
            "toolVersion",
            "exitCode",
            "trustPolicy",
            "keyFingerprint",
            "publicKeySHA256",
            "tagObjectOID",
            "targetCommit",
            "verifiedAt",
            "transcript",
        },
        label="GitHub signature verification",
    )
    signature_type = signature["signatureType"]
    signature_marker = b"-----BEGIN SSH SIGNATURE-----"
    transcript = _archived_bytes(
        signature["transcript"],
        label="GitHub signature transcript",
        maximum_bytes=MAXIMUM_API_BODY_BYTES,
    )
    if (
        tag["targetType"] != "commit"
        or tag["targetCommit"] != github_release["commit"]
        or _git_object_oid("tag", tag_payload) != tag["objectOID"]
        or not tag_payload.startswith(required_tag_header)
        or signature_type != "SSH"
        or signature_marker not in tag_payload
        or signature["status"] != "VERIFIED"
        or signature["method"] != "git verify-tag"
        or signature["exitCode"] != 0
        or signature["trustPolicy"] != "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH"
        or signature["tagObjectOID"] != tag["objectOID"]
        or signature["targetCommit"] != github_release["commit"]
        or not isinstance(signature["toolVersion"], str)
        or not signature["toolVersion"]
        or not transcript
    ):
        raise ZenodoArchiveError("GitHub signed annotated tag evidence differs")
    verified = _utc(signature["verifiedAt"], label="signature verifiedAt")
    created = _utc(receipt.get("receiptCreatedAt"), label="GitHub receiptCreatedAt")
    if verified > created:
        raise ZenodoArchiveError("GitHub signature was verified after receipt creation")
    return signature


def _validate_archival_semantics(
    deposit_root: Path,
    *,
    files: Sequence[Mapping[str, Any]],
    github_release: Mapping[str, Any],
    release_receipt_raw: bytes,
    rights: Sequence[Mapping[str, Any]],
    manifest_rights: Sequence[str],
    reservation: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Prove that mandatory archival roles contain their claimed evidence."""

    by_role: dict[str, list[Mapping[str, Any]]] = {}
    github_assets: dict[str, Mapping[str, Any]] = {}
    for item in files:
        by_role.setdefault(item["role"], []).append(item)
        if item["role"] == "github-release-asset":
            github_assets[item["githubAssetRole"]] = item
    for role in REQUIRED_SUPERSET_ROLES:
        if len(by_role.get(role, ())) != 1:
            raise ZenodoArchiveError(
                f"deposit must contain exactly one semantic artifact for role {role}"
            )

    root = _safe_root(deposit_root)

    def role_path(role: str) -> Path:
        return root / PurePosixPath(by_role[role][0]["path"])

    def role_bytes(role: str) -> bytes:
        return _read_stable_bytes(
            role_path(role), label=f"{role} payload"
        )

    def github_asset_bytes(role: str) -> bytes:
        item = github_assets.get(role)
        if item is None:
            raise ZenodoArchiveError(f"GitHub release omits required semantic asset {role}")
        return _read_stable_bytes(
            root / PurePosixPath(item["path"]), label=f"GitHub {role} asset"
        )

    release_receipt = _canonical_document(
        release_receipt_raw,
        label="GitHub release receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    signature = _verify_github_signed_tag_receipt(
        release_receipt, github_release=github_release
    )
    repository = github_release["repository"]
    lab_commit = github_release["commit"]
    lab_tree = github_release["tree"]
    codec_commit: str | None = None
    codec_tree: str | None = None
    development_control_archive: dict[str, Any] | None = None

    external_gate_raw = role_bytes("github-gate-receipt")
    external_sbom_raw = role_bytes("sbom")
    if github_release["kind"] == "design":
        if external_gate_raw != github_asset_bytes("github-gate-receipt"):
            raise ZenodoArchiveError(
                "external GitHub gate receipt differs from the design release asset"
            )
        for ci_role in CI_PAYLOADS:
            if role_bytes(ci_role) != github_asset_bytes(ci_role):
                raise ZenodoArchiveError(
                    f"external {ci_role} differs from the design release asset"
                )
        design_raw = github_asset_bytes("design-registration")
        design = _canonical_document(
            design_raw,
            label="frozen design registration",
            maximum_bytes=MAXIMUM_RECEIPT_BYTES,
        )
        lab = design.get("labSource")
        codec = design.get("codecSource")
        ci = design.get("continuousIntegration")
        development_controls = design.get("developmentControls")
        development_gate = (
            development_controls.get("realDataE2EFreezeGate")
            if isinstance(development_controls, dict)
            else None
        )
        release_plan = design.get("designRelease")
        release_record = release_receipt.get("release")
        if (
            design.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-design-v1"
            or design.get("status") != "PUBLIC_DESIGN_FROZEN"
            or design.get("readyToFreeze") is not True
            or design.get("countsTowardScientificVerdict") is not False
            or design.get("freezeBlockers") != []
            or not isinstance(lab, dict)
            or lab.get("status") != "FROZEN_BOUND"
            or lab.get("commit") != lab_commit
            or lab.get("tree") != lab_tree
            or not isinstance(codec, dict)
            or not isinstance(codec.get("commit"), str)
            or GIT_OID.fullmatch(codec["commit"]) is None
            or not isinstance(codec.get("tree"), str)
            or GIT_OID.fullmatch(codec["tree"]) is None
            or not isinstance(ci, dict)
            or ci.get("ciArtifactBytesMustBeArchivedSeparately") is not True
            or not isinstance(development_gate, dict)
            or not isinstance(release_plan, dict)
            or release_plan.get("tag") != github_release["tag"]
            or release_plan.get("serverTimestampRequired") is not True
            or release_plan.get("immutableReleaseRequired") is not True
            or release_plan.get("signedAnnotatedTagRequired") is not True
            or release_plan.get("signatureType") != signature["signatureType"]
            or release_plan.get("signingKeyFingerprint")
            != signature["keyFingerprint"]
            or release_plan.get("signingPublicKeySHA256")
            != signature["publicKeySHA256"]
            or not isinstance(release_record, dict)
            or release_record.get("deadline")
            != release_plan.get("publishNoLaterThan")
        ):
            raise ZenodoArchiveError(
                "frozen design does not bind the release source, codec, and CI bytes"
            )
        if _utc(
            github_release["attestedAt"], label="design release attestation time"
        ) >= _utc(
            release_plan["publishNoLaterThan"], label="design release deadline"
        ):
            raise ZenodoArchiveError("design release was not attested before its deadline")
        development_control_archive = _development_control_archive_summary(
            github_asset_bytes("development-control-archive-receipt")
        )
        if (
            development_control_archive["repository"] != repository
            or development_control_archive["commit"] != lab_commit
            or development_control_archive["tree"] != lab_tree
            or development_control_archive["tag"]
            != development_gate.get("archiveTag")
            or development_control_archive["deadline"]
            != development_gate.get("completeNoLaterThan")
            or development_control_archive["receiptSHA256"]
            != development_gate.get("archiveReceiptSHA256")
            or development_control_archive["publishedAt"]
            != development_gate.get("archivePublishedAt")
            or development_control_archive["archiveAttestedAt"]
            != development_gate.get("archiveAttestedAt")
            or development_control_archive[
                "releaseAttestationBundleSHA256"
            ]
            != development_gate.get("releaseAttestationBundleSHA256")
            or development_control_archive[
                "releaseAttestationOutputSHA256"
            ]
            != development_gate.get("releaseAttestationOutputSHA256")
            or _utc(
                development_control_archive["archiveAttestedAt"],
                label="development-control archive attestation time",
            )
            > _utc(
                github_release["attestedAt"],
                label="design release attestation time",
            )
        ):
            raise ZenodoArchiveError(
                "frozen design development-control release binding differs"
            )
        codec_commit, codec_tree = codec["commit"], codec["tree"]
        runtime_raw = github_asset_bytes("runtime-manifest")
        design_runtime = design.get("runtime")
        if (
            not isinstance(design_runtime, dict)
            or design_runtime.get("primaryPlatform") != "macOS-arm64-local-offline"
        ):
            raise ZenodoArchiveError("frozen design primary runtime profile differs")
        _verify_runtime_manifest(
            runtime_raw,
            label="design runtime manifest",
            system="Darwin",
            machine="arm64",
            lab_commit=lab_commit,
            lab_tree=lab_tree,
            codec_commit=codec_commit,
            codec_tree=codec_tree,
            lab_repository=repository,
        )
        if (
            design_runtime.get("runtimeManifestSHA256") != _sha256(runtime_raw)
        ):
            raise ZenodoArchiveError("frozen design runtime digest differs")
        if external_sbom_raw != github_asset_bytes("sbom"):
            raise ZenodoArchiveError("external SBOM differs from the design release asset")

    observed_codec_commit, observed_codec_tree = _verify_sbom(
        external_sbom_raw,
        repository=repository,
        lab_commit=lab_commit,
        lab_tree=lab_tree,
        codec_commit=codec_commit,
        codec_tree=codec_tree,
    )
    codec_commit = observed_codec_commit
    codec_tree = observed_codec_tree

    _verify_source_archive_role(
        role_path("lab-source-archive"),
        label="laboratory source archive",
        expected_commit=lab_commit,
        expected_tree=lab_tree,
    )
    _verify_source_archive_role(
        role_path("codec-source-archive"),
        label="codec source archive",
        expected_commit=codec_commit,
        expected_tree=codec_tree,
    )
    for role in CI_PAYLOADS:
        _verify_ci_payload(
            role_bytes(role),
            role=role,
            lab_commit=lab_commit,
            lab_tree=lab_tree,
            codec_commit=codec_commit,
            codec_tree=codec_tree,
            lab_repository=repository,
        )
    _verify_citation(
        role_bytes("release-specific-citation"),
        repository=repository,
        tag=github_release["tag"],
        doi=reservation["doi"],
        published_at=github_release["publishedAt"],
    )
    _verify_rights_metadata(
        role_bytes("rights-metadata"),
        release_kind=github_release["kind"],
        doi=reservation["doi"],
        rights=rights,
        files=files,
        manifest_rights=manifest_rights,
    )
    _verify_notice(
        role_bytes("notice"),
        repository=repository,
        doi=reservation["doi"],
        rights=rights,
    )
    _verify_license_material(role_bytes("license-material"), codec_commit=codec_commit)
    _verify_signed_tag_projection(
        role_bytes("signed-tag-verification"),
        release_receipt_raw=release_receipt_raw,
        release_receipt=release_receipt,
        github_release=github_release,
    )
    return development_control_archive


def build_deposit_manifest(
    deposit_root: Path,
    plan: Mapping[str, Any],
    *,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
    release_receipt_verifier: ReleaseReceiptVerifier = verify_release_receipt,
) -> dict[str, Any]:
    """Build a deterministic manifest from an exact declarative file plan."""

    plan = _mapping(
        plan,
        {
            "schemaVersion",
            "releaseKind",
            "githubReleaseReceiptPath",
            "githubReleaseAssetsDirectory",
            "zenodoReservation",
            "rightsDeclarations",
            "manifestRightsIds",
            "files",
        },
        label="Zenodo manifest plan",
    )
    if plan["schemaVersion"] != "corelm-zenodo-deposit-plan-v1":
        raise ZenodoArchiveError("Zenodo manifest plan schema differs")
    release_kind = plan["releaseKind"]
    if release_kind not in KINDS:
        raise ZenodoArchiveError("Zenodo release kind is unsupported")
    reservation = _zenodo_reservation(plan["zenodoReservation"])
    receipt_path = _relative_path(
        plan["githubReleaseReceiptPath"], label="GitHub receipt path"
    )
    asset_directory = _relative_path(
        plan["githubReleaseAssetsDirectory"], label="GitHub asset directory"
    )
    if "/" in asset_directory or asset_directory == receipt_path:
        raise ZenodoArchiveError("GitHub asset directory must be one top-level directory")
    inventory = _inventory_root(deposit_root)
    receipt_file = _safe_root(deposit_root) / PurePosixPath(receipt_path)
    receipt_raw, _receipt_value = _read_canonical(
        receipt_file,
        label="GitHub release receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    github_release, github_roles = _github_release_summary(
        receipt_raw,
        receipt_path,
        inventory=inventory,
        github_asset_directory=asset_directory,
    )
    _verify_deposited_github_release_receipt(
        receipt_raw,
        asset_root=_safe_root(deposit_root) / PurePosixPath(asset_directory),
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        release_receipt_verifier=release_receipt_verifier,
    )
    if github_release["kind"] != release_kind:
        raise ZenodoArchiveError("Zenodo and GitHub release kinds differ")
    rights = _validate_rights_declarations(plan["rightsDeclarations"])
    known_rights = {item["rightsId"] for item in rights}
    manifest_rights = plan["manifestRightsIds"]
    if (
        not isinstance(manifest_rights, list)
        or not manifest_rights
        or any(not isinstance(right, str) for right in manifest_rights)
        or len(manifest_rights) != len(set(manifest_rights))
        or any(right not in known_rights for right in manifest_rights)
    ):
        raise ZenodoArchiveError("manifest rightsIds are empty, duplicate, or undeclared")
    file_plan = plan["files"]
    if not isinstance(file_plan, list) or len(file_plan) != len(inventory):
        raise ZenodoArchiveError("file plan must describe the exact deposit root")
    planned: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(file_plan):
        item = _mapping(
            raw,
            {
                "path",
                "role",
                "githubAssetRole",
                "githubActionsArtifactName",
                "mediaType",
                "rightsIds",
            },
            label=f"file plan entry {index}",
        )
        path = _relative_path(item["path"], label="file plan path")
        if path == MANIFEST_FILE_NAME or path in planned:
            raise ZenodoArchiveError("duplicate or reserved file plan path")
        role = item["role"]
        if role not in FILE_ROLES:
            raise ZenodoArchiveError("file role is unsupported")
        media_type = item["mediaType"]
        if not isinstance(media_type, str) or MEDIA_TYPE.fullmatch(media_type) is None:
            raise ZenodoArchiveError("media type is malformed")
        rights_ids = item["rightsIds"]
        if (
            not isinstance(rights_ids, list)
            or not rights_ids
            or any(not isinstance(right, str) for right in rights_ids)
            or len(rights_ids) != len(set(rights_ids))
            or any(right not in known_rights for right in rights_ids)
        ):
            raise ZenodoArchiveError("file rightsIds are empty, duplicate, or undeclared")
        github_role = item["githubAssetRole"]
        actions_name = item["githubActionsArtifactName"]
        expected_github_role = github_roles.get(path)
        if expected_github_role is not None:
            if role != "github-release-asset" or github_role != expected_github_role:
                raise ZenodoArchiveError("GitHub release asset role binding differs")
        elif role == "github-release-asset" or github_role is not None:
            raise ZenodoArchiveError("non-GitHub file claims a GitHub asset binding")
        if role == "linux-ci-artifact":
            if not isinstance(actions_name, str) or not actions_name.startswith(
                "author-v3-linux-development-"
            ):
                raise ZenodoArchiveError("Linux CI artifact name binding is malformed")
        elif role == "macos-arm64-ci-artifact":
            if not isinstance(actions_name, str) or not actions_name.startswith(
                "author-v3-macos-development-"
            ):
                raise ZenodoArchiveError("macOS CI artifact name binding is malformed")
        elif actions_name is not None:
            raise ZenodoArchiveError("non-CI file claims a GitHub Actions artifact")
        if path == receipt_path and role != "github-release-receipt":
            raise ZenodoArchiveError("GitHub receipt path has the wrong role")
        if role == "github-release-receipt" and path != receipt_path:
            raise ZenodoArchiveError("duplicate GitHub receipt role")
        planned[path] = {
            "path": path,
            "role": role,
            "githubAssetRole": github_role,
            "githubActionsArtifactName": actions_name,
            "mediaType": media_type,
            "rightsIds": sorted(rights_ids, key=lambda value: value.encode("ascii")),
            "bytes": inventory[path]["bytes"] if path in inventory else None,
            "sha256": inventory[path]["sha256"] if path in inventory else None,
        }
    if set(planned) != set(inventory):
        raise ZenodoArchiveError("file plan and deposit root paths differ")
    if sum(item["role"] == "github-release-receipt" for item in planned.values()) != 1:
        raise ZenodoArchiveError("deposit must contain exactly one GitHub release receipt")
    gate_entries = [
        item for item in planned.values() if item["role"] == "github-gate-receipt"
    ]
    if len(gate_entries) != 1:
        raise ZenodoArchiveError("deposit must contain exactly one GitHub gate receipt")
    observed_roles = {item["role"] for item in planned.values()}
    if not REQUIRED_SUPERSET_ROLES.issubset(observed_roles):
        missing = ", ".join(sorted(REQUIRED_SUPERSET_ROLES - observed_roles))
        raise ZenodoArchiveError(f"deposit omits required archival roles: {missing}")
    gate_path = gate_entries[0]["path"]
    gate_raw, _gate = _read_canonical(
        _safe_root(deposit_root) / PurePosixPath(gate_path),
        label="GitHub gate receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    github_gate, action_artifacts = _github_gate_summary(
        gate_raw,
        receipt_path=gate_path,
        expected_implementation_commit=github_release["commit"],
    )
    ci_entries = [
        item
        for item in planned.values()
        if item["role"] in {"linux-ci-artifact", "macos-arm64-ci-artifact"}
    ]
    if len(ci_entries) != 2 or {
        item["githubActionsArtifactName"] for item in ci_entries
    } != set(action_artifacts):
        raise ZenodoArchiveError("manifest CI artifacts differ from GitHub gate inventory")
    for item in ci_entries:
        if item["sha256"] != action_artifacts[item["githubActionsArtifactName"]]:
            raise ZenodoArchiveError("CI artifact bytes differ from GitHub gate digest")
    files = [planned[path] for path in sorted(planned, key=lambda value: value.encode("utf-8"))]
    development_control_archive = _validate_archival_semantics(
        deposit_root,
        files=files,
        github_release=github_release,
        release_receipt_raw=receipt_raw,
        rights=rights,
        manifest_rights=sorted(manifest_rights, key=lambda value: value.encode("ascii")),
        reservation=reservation,
    )
    if _inventory_root(deposit_root) != inventory:
        raise ZenodoArchiveError("deposit changed during manifest construction")
    total_bytes = sum(item["bytes"] for item in files)
    if total_bytes > MAXIMUM_FILE_BYTES:
        raise ZenodoArchiveError("deposit payload exceeds Zenodo's 50 GB limit")
    manifest: dict[str, Any] = {
        "schemaVersion": MANIFEST_SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "releaseKind": release_kind,
        "manifestFileName": MANIFEST_FILE_NAME,
        "fileSetPolicy": "EXACT_MANIFESTED_SUPERSET_PLUS_THIS_MANIFEST",
        "githubRelease": github_release,
        "developmentControlArchive": development_control_archive,
        "githubGate": github_gate,
        "zenodoReservation": reservation,
        "rightsDeclarations": rights,
        "manifestRightsIds": sorted(
            manifest_rights, key=lambda value: value.encode("ascii")
        ),
        "files": files,
        "fileCount": len(files),
        "totalBytes": total_bytes,
        "githubReleaseAssetCount": len(github_roles),
    }
    manifest["contentSHA256"] = _sha256(canonical_json_bytes(manifest))
    serialized_bytes = len(canonical_json_bytes(manifest)) + 1
    if serialized_bytes > MAXIMUM_MANIFEST_BYTES:
        raise ZenodoArchiveError("Zenodo deposit manifest exceeds its byte limit")
    if total_bytes + serialized_bytes > MAXIMUM_FILE_BYTES:
        raise ZenodoArchiveError("deposit plus manifest exceeds Zenodo's 50 GB limit")
    return manifest


def build_deposit_manifest_to_path(
    deposit_root: Path,
    plan: Mapping[str, Any],
    output_path: Path,
    *,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
    release_receipt_verifier: ReleaseReceiptVerifier = verify_release_receipt,
) -> dict[str, Any]:
    root = _safe_root(deposit_root)
    output = Path(os.path.abspath(os.fspath(output_path)))
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise ZenodoArchiveError("deposit manifest output must remain outside deposit root")
    manifest = build_deposit_manifest(
        root,
        plan,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        release_receipt_verifier=release_receipt_verifier,
    )
    write_new_bytes(output, canonical_json_bytes(manifest) + b"\n")
    return manifest


def _validate_manifest(
    raw: bytes,
    deposit_root: Path,
    *,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ),
    release_receipt_verifier: ReleaseReceiptVerifier,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest = _canonical_document(
        raw, label="Zenodo deposit manifest", maximum_bytes=MAXIMUM_MANIFEST_BYTES
    )
    root = _mapping(
        manifest,
        {
            "schemaVersion",
            "suiteId",
            "releaseKind",
            "manifestFileName",
            "fileSetPolicy",
            "githubRelease",
            "developmentControlArchive",
            "githubGate",
            "zenodoReservation",
            "rightsDeclarations",
            "manifestRightsIds",
            "files",
            "fileCount",
            "totalBytes",
            "githubReleaseAssetCount",
            "contentSHA256",
        },
        label="Zenodo deposit manifest",
    )
    if (
        root["schemaVersion"] != MANIFEST_SCHEMA_VERSION
        or root["suiteId"] != SUITE_ID
        or root["releaseKind"] not in KINDS
        or root["manifestFileName"] != MANIFEST_FILE_NAME
        or root["fileSetPolicy"] != "EXACT_MANIFESTED_SUPERSET_PLUS_THIS_MANIFEST"
    ):
        raise ZenodoArchiveError("Zenodo deposit manifest identity/policy differs")
    reservation = _zenodo_reservation(root["zenodoReservation"])
    if root["zenodoReservation"] != reservation:
        raise ZenodoArchiveError("Zenodo reservation binding is not canonical")
    content_digest = _digest(root["contentSHA256"], label="manifest content digest")
    unsigned = dict(root)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != content_digest:
        raise ZenodoArchiveError("Zenodo deposit manifest content digest differs")
    rights = _validate_rights_declarations(root["rightsDeclarations"])
    if root["rightsDeclarations"] != rights:
        raise ZenodoArchiveError("rights declarations are not canonical-sorted")
    known_rights = {item["rightsId"] for item in rights}
    manifest_rights = root["manifestRightsIds"]
    if (
        not isinstance(manifest_rights, list)
        or not manifest_rights
        or any(not isinstance(right, str) for right in manifest_rights)
        or manifest_rights
        != sorted(manifest_rights, key=lambda value: value.encode("ascii"))
        or len(manifest_rights) != len(set(manifest_rights))
        or any(right not in known_rights for right in manifest_rights)
    ):
        raise ZenodoArchiveError("manifest's own rights binding differs")
    inventory = _inventory_root(deposit_root)
    files = root["files"]
    if not isinstance(files, list) or not 2 <= len(files) <= 99:
        raise ZenodoArchiveError("manifest file list length is invalid")
    expected_paths: list[str] = []
    github_roles: set[str] = set()
    receipt_count = 0
    total = 0
    for index, raw_file in enumerate(files):
        item = _mapping(
            raw_file,
            {
                "path",
                "role",
                "githubAssetRole",
                "githubActionsArtifactName",
                "mediaType",
                "rightsIds",
                "bytes",
                "sha256",
            },
            label=f"manifest file {index}",
        )
        path = _relative_path(item["path"], label="manifest file path")
        if path == MANIFEST_FILE_NAME:
            raise ZenodoArchiveError("manifest cannot list itself as a payload file")
        role = item["role"]
        if role not in FILE_ROLES:
            raise ZenodoArchiveError("manifest file role is unsupported")
        github_role = item["githubAssetRole"]
        if role == "github-release-asset":
            if not isinstance(github_role, str) or GITHUB_ASSET_ROLE.fullmatch(github_role) is None:
                raise ZenodoArchiveError("GitHub asset role is missing or malformed")
            if github_role in github_roles:
                raise ZenodoArchiveError("duplicate GitHub asset role")
            github_roles.add(github_role)
        elif github_role is not None:
            raise ZenodoArchiveError("non-GitHub file has a GitHub asset role")
        actions_name = item["githubActionsArtifactName"]
        if role == "linux-ci-artifact":
            if not isinstance(actions_name, str) or not actions_name.startswith(
                "author-v3-linux-development-"
            ):
                raise ZenodoArchiveError("manifest Linux CI artifact name differs")
        elif role == "macos-arm64-ci-artifact":
            if not isinstance(actions_name, str) or not actions_name.startswith(
                "author-v3-macos-development-"
            ):
                raise ZenodoArchiveError("manifest macOS CI artifact name differs")
        elif actions_name is not None:
            raise ZenodoArchiveError("manifest non-CI file claims an Actions artifact")
        if role == "github-release-receipt":
            receipt_count += 1
        media_type = item["mediaType"]
        if not isinstance(media_type, str) or MEDIA_TYPE.fullmatch(media_type) is None:
            raise ZenodoArchiveError("manifest media type is malformed")
        rights_ids = item["rightsIds"]
        if (
            not isinstance(rights_ids, list)
            or not rights_ids
            or any(not isinstance(right, str) for right in rights_ids)
            or rights_ids != sorted(rights_ids, key=lambda value: value.encode("ascii"))
            or len(rights_ids) != len(set(rights_ids))
            or any(right not in known_rights for right in rights_ids)
        ):
            raise ZenodoArchiveError("manifest rights binding differs")
        if type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAXIMUM_FILE_BYTES:
            raise ZenodoArchiveError("manifest file byte count is invalid")
        digest = _digest(item["sha256"], label="manifest file digest")
        observed = inventory.get(path)
        if observed is None or observed["bytes"] != item["bytes"] or observed["sha256"] != digest:
            raise ZenodoArchiveError(f"local deposit file differs from manifest: {path}")
        expected_paths.append(path)
        total += item["bytes"]
    if expected_paths != sorted(expected_paths, key=lambda value: value.encode("utf-8")):
        raise ZenodoArchiveError("manifest file paths are not canonical-sorted")
    if len(expected_paths) != len(set(expected_paths)) or set(expected_paths) != set(inventory):
        raise ZenodoArchiveError("manifest file set differs from local deposit root")
    if receipt_count != 1:
        raise ZenodoArchiveError("manifest must contain one GitHub release receipt")
    observed_roles = {item["role"] for item in files}
    if not REQUIRED_SUPERSET_ROLES.issubset(observed_roles):
        raise ZenodoArchiveError("manifest omits one or more required archival roles")
    if (
        root["fileCount"] != len(files)
        or root["totalBytes"] != total
        or total > MAXIMUM_FILE_BYTES
        or total + len(raw) > MAXIMUM_FILE_BYTES
        or root["githubReleaseAssetCount"] != len(github_roles)
    ):
        raise ZenodoArchiveError("manifest aggregate counts differ")
    github = root["githubRelease"]
    if not isinstance(github, dict) or github.get("kind") != root["releaseKind"]:
        raise ZenodoArchiveError("manifest GitHub release binding differs")
    receipt_path = github.get("receiptPath")
    receipt_entry = next((item for item in files if item["role"] == "github-release-receipt"), None)
    if (
        not isinstance(receipt_path, str)
        or receipt_entry is None
        or receipt_entry["path"] != receipt_path
    ):
        raise ZenodoArchiveError("manifest GitHub receipt path differs")
    receipt_bytes, _receipt = _read_canonical(
        _safe_root(deposit_root) / PurePosixPath(receipt_path),
        label="GitHub release receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    asset_paths = [item["path"] for item in files if item["role"] == "github-release-asset"]
    asset_directories = {path.split("/", 1)[0] for path in asset_paths if "/" in path}
    if len(asset_directories) != 1:
        raise ZenodoArchiveError("GitHub assets must share one top-level directory")
    github_summary, github_path_roles = _github_release_summary(
        receipt_bytes,
        receipt_path,
        inventory=inventory,
        github_asset_directory=next(iter(asset_directories)),
    )
    _verify_deposited_github_release_receipt(
        receipt_bytes,
        asset_root=(
            _safe_root(deposit_root)
            / PurePosixPath(next(iter(asset_directories)))
        ),
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        release_receipt_verifier=release_receipt_verifier,
    )
    if github_summary != github:
        raise ZenodoArchiveError("manifest GitHub release summary differs from receipt")
    for item in files:
        if (
            item["role"] == "github-release-asset"
            and github_path_roles.get(item["path"]) != item["githubAssetRole"]
        ):
            raise ZenodoArchiveError("manifest GitHub asset binding differs from receipt")
    gate_entries = [item for item in files if item["role"] == "github-gate-receipt"]
    if len(gate_entries) != 1:
        raise ZenodoArchiveError("manifest must contain one GitHub gate receipt")
    gate_path = gate_entries[0]["path"]
    gate_raw, _gate = _read_canonical(
        _safe_root(deposit_root) / PurePosixPath(gate_path),
        label="GitHub gate receipt",
        maximum_bytes=MAXIMUM_RECEIPT_BYTES,
    )
    github_gate, action_artifacts = _github_gate_summary(
        gate_raw,
        receipt_path=gate_path,
        expected_implementation_commit=github["commit"],
    )
    if root["githubGate"] != github_gate:
        raise ZenodoArchiveError("manifest GitHub gate summary differs from receipt")
    ci_entries = [
        item
        for item in files
        if item["role"] in {"linux-ci-artifact", "macos-arm64-ci-artifact"}
    ]
    if len(ci_entries) != 2 or {
        item["githubActionsArtifactName"] for item in ci_entries
    } != set(action_artifacts):
        raise ZenodoArchiveError("manifest CI artifact inventory differs")
    for item in ci_entries:
        if item["sha256"] != action_artifacts[item["githubActionsArtifactName"]]:
            raise ZenodoArchiveError("manifest CI artifact digest differs from GitHub gate")
    development_control_archive = _validate_archival_semantics(
        deposit_root,
        files=files,
        github_release=github,
        release_receipt_raw=receipt_bytes,
        rights=rights,
        manifest_rights=manifest_rights,
        reservation=reservation,
    )
    if root["developmentControlArchive"] != development_control_archive:
        raise ZenodoArchiveError(
            "manifest development-control archive projection differs"
        )
    if _inventory_root(deposit_root) != inventory:
        raise ZenodoArchiveError("deposit changed during manifest verification")
    return dict(root), inventory


def _archived_bytes(value: Any, *, label: str, maximum_bytes: int) -> bytes:
    record = _mapping(value, {"encoding", "bytes", "sha256", "dataBase64"}, label=label)
    if record["encoding"] != "base64":
        raise ZenodoArchiveError(f"{label} encoding must be base64")
    size = record["bytes"]
    if type(size) is not int or not 0 <= size <= maximum_bytes:
        raise ZenodoArchiveError(f"{label} byte count is invalid")
    digest = _digest(record["sha256"], label=f"{label} digest")
    encoded = record["dataBase64"]
    if not isinstance(encoded, str) or len(encoded) > ((maximum_bytes + 2) // 3) * 4:
        raise ZenodoArchiveError(f"{label} base64 is invalid")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ZenodoArchiveError(f"{label} base64 is invalid") from error
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ZenodoArchiveError(f"{label} base64 is not canonical")
    if len(raw) != size or _sha256(raw) != digest:
        raise ZenodoArchiveError(f"{label} archived bytes differ")
    return raw


def archive_bytes(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _strict_json(raw: bytes, *, label: str) -> Any:
    try:
        return load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise ZenodoArchiveError(f"{label} is not strict JSON") from error


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            key.casefold() in {"access_token", "authorization"}
            or _contains_secret_key(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_key(child) for child in value)
    return False


def _parse_response_headers(
    raw: bytes, *, expected_status: int, entity_bytes: int | None = None
) -> datetime:
    if not raw.endswith(b"\r\n\r\n") or len(raw) > MAXIMUM_HEADER_BYTES:
        raise ZenodoArchiveError("Zenodo response headers are malformed")
    lines = raw[:-4].split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.1 ([0-9]{3})(?: [^\r\n]*)?", lines[0])
    if match is None or int(match.group(1)) != expected_status:
        raise ZenodoArchiveError("Zenodo archived HTTP status differs")
    fields: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line or line[:1] in b" \t" or b":" not in line:
            raise ZenodoArchiveError("Zenodo response header line is invalid")
        name, value = line.split(b":", 1)
        if HEADER_NAME.fullmatch(name) is None:
            raise ZenodoArchiveError("Zenodo response header name is invalid")
        try:
            decoded = value.strip(b" \t").decode("latin-1")
        except UnicodeDecodeError as error:  # pragma: no cover - latin-1 is total
            raise ZenodoArchiveError("Zenodo response header is invalid") from error
        fields.setdefault(name.decode("ascii").casefold(), []).append(decoded)
    if "authorization" in fields or any(
        "access_token" in value.casefold()
        for values in fields.values()
        for value in values
    ):
        raise ZenodoArchiveError("authorization material appeared in archived headers")
    dates = fields.get("date", [])
    content_types = fields.get("content-type", [])
    if (
        len(dates) != 1
        or len(content_types) != 1
        or not content_types[0].casefold().startswith("application/json")
    ):
        raise ZenodoArchiveError("Zenodo Date or JSON Content-Type header differs")
    encodings = fields.get("content-encoding", ["identity"])
    if len(encodings) != 1 or encodings[0].casefold() not in {"", "identity"}:
        raise ZenodoArchiveError("Zenodo archived response is unexpectedly encoded")
    transfers = fields.get("transfer-encoding", [])
    lengths = fields.get("content-length", [])
    if transfers and lengths:
        raise ZenodoArchiveError("Zenodo archived body framing is ambiguous")
    if transfers and (len(transfers) != 1 or transfers[0].casefold() != "chunked"):
        raise ZenodoArchiveError("Zenodo archived transfer encoding is unsupported")
    if lengths:
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise ZenodoArchiveError("Zenodo archived Content-Length is invalid")
        if entity_bytes is not None and int(lengths[0]) != entity_bytes:
            raise ZenodoArchiveError("Zenodo archived Content-Length differs from body")
    try:
        server_date = parsedate_to_datetime(dates[0])
    except (TypeError, ValueError) as error:
        raise ZenodoArchiveError("Zenodo Date header is invalid") from error
    if server_date.tzinfo is None:
        raise ZenodoArchiveError("Zenodo Date header lacks a timezone")
    return server_date.astimezone(timezone.utc).replace(microsecond=0)


def _normalize_rights(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    values: list[Any] = []
    if "rights" in metadata:
        rights = metadata["rights"]
        if not isinstance(rights, list):
            raise ZenodoArchiveError("Zenodo metadata.rights is not a list")
        values.extend(rights)
    if "license" in metadata:
        license_value = metadata["license"]
        values.extend(license_value if isinstance(license_value, list) else [license_value])
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()
    for raw in values:
        if isinstance(raw, str):
            identifier, title, uri = raw, None, None
        elif isinstance(raw, dict):
            identifier = raw.get("id") or raw.get("identifier")
            title = raw.get("title")
            uri = raw.get("link") or raw.get("url")
        else:
            raise ZenodoArchiveError("Zenodo rights metadata entry is malformed")
        for value, maximum, label in (
            (identifier, 128, "identifier"),
            (title, 512, "title"),
            (uri, 2048, "URI"),
        ):
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= maximum):
                raise ZenodoArchiveError(f"Zenodo rights {label} is malformed")
        key = (identifier, title, uri)
        if key not in seen:
            normalized.append({"identifier": identifier, "title": title, "uri": uri})
            seen.add(key)
    if not normalized:
        raise ZenodoArchiveError("Zenodo record has no rights metadata")
    normalized.sort(
        key=lambda item: (
            (item["identifier"] or "").encode("utf-8"),
            (item["title"] or "").encode("utf-8"),
            (item["uri"] or "").encode("utf-8"),
        )
    )
    return normalized


def _verify_expected_rights(
    expected: Sequence[Mapping[str, Any]], observed: Sequence[Mapping[str, Any]]
) -> None:
    for right in expected:
        identifier = right["zenodoIdentifier"]
        if identifier is not None:
            matched = any(item["identifier"] == identifier for item in observed)
        else:
            matched = any(
                item["title"] == right["title"] and item["uri"] == right["uri"]
                for item in observed
            )
        if not matched:
            raise ZenodoArchiveError(f"Zenodo rights metadata omits {right['rightsId']}")


def _zenodo_file_map(
    value: Any,
    *,
    source: str,
) -> dict[str, tuple[int, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAXIMUM_FILE_COUNT:
        raise ZenodoArchiveError(f"{source} file list is invalid")
    result: dict[str, tuple[int, str]] = {}
    for raw in value:
        if not isinstance(raw, dict):
            raise ZenodoArchiveError(f"{source} file entry is malformed")
        if source == "deposition":
            path, size = raw.get("filename"), raw.get("filesize")
        else:
            path, size = raw.get("key"), raw.get("size")
        path = _relative_path(path, label=f"{source} file path")
        checksum = raw.get("checksum")
        if type(size) is not int or not 0 <= size <= MAXIMUM_FILE_BYTES:
            raise ZenodoArchiveError(f"{source} file byte count is invalid")
        if (
            not isinstance(checksum, str)
            or not checksum.startswith("md5:")
            or MD5.fullmatch(checksum[4:]) is None
        ):
            raise ZenodoArchiveError(f"{source} file checksum is not lowercase MD5")
        if path in result:
            raise ZenodoArchiveError(f"{source} file names are not unique")
        result[path] = (size, checksum[4:])
    return result


def _expected_local_files(
    manifest: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    manifest_raw: bytes,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in manifest["files"]:
        observed = inventory[item["path"]]
        result[item["path"]] = {
            "bytes": observed["bytes"],
            "sha256": observed["sha256"],
            "md5": observed["md5"],
        }
    result[MANIFEST_FILE_NAME] = {
        "bytes": len(manifest_raw),
        "sha256": _sha256(manifest_raw),
        "md5": hashlib.md5(manifest_raw, usedforsecurity=False).hexdigest(),
    }
    return result


def _api_response_map(
    value: Any,
    *,
    deposition_id: int,
    record_id: int,
    receipt_created: datetime,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 3:
        raise ZenodoArchiveError("Zenodo receipt must contain exactly three API responses")
    expected_targets = {
        "deposition": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}",
        "deposition-files": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}/files",
        "record": f"{ZENODO_API_BASE}/records/{record_id}",
    }
    result: dict[str, dict[str, Any]] = {}
    capture_times: list[datetime] = []
    for index, raw in enumerate(value):
        item = _mapping(
            raw,
            {
                "role",
                "method",
                "requestTarget",
                "authentication",
                "statusCode",
                "serverDate",
                "capturedAt",
                "responseHeaders",
                "responseBody",
            },
            label=f"Zenodo API response {index}",
        )
        role = item["role"]
        if index >= len(API_ROLES) or role != API_ROLES[index] or role in result:
            raise ZenodoArchiveError("Zenodo API response order/role differs")
        if (
            item["method"] != "GET"
            or item["requestTarget"] != expected_targets[role]
            or item["authentication"] != "BEARER_HEADER_USED_NOT_ARCHIVED"
            or item["statusCode"] != 200
        ):
            raise ZenodoArchiveError("Zenodo API request target or read-only policy differs")
        captured = _utc(item["capturedAt"], label="Zenodo capture time")
        if captured > receipt_created:
            raise ZenodoArchiveError("Zenodo response was captured after receipt creation")
        raw_headers = _archived_bytes(
            item["responseHeaders"],
            label="Zenodo response headers",
            maximum_bytes=MAXIMUM_HEADER_BYTES,
        )
        body = _archived_bytes(
            item["responseBody"], label="Zenodo response body", maximum_bytes=MAXIMUM_API_BODY_BYTES
        )
        server_date = _parse_response_headers(
            raw_headers, expected_status=200, entity_bytes=len(body)
        )
        declared_server_date = _utc(item["serverDate"], label="Zenodo server date")
        if server_date != declared_server_date or abs(
            server_date - captured
        ) > timedelta(minutes=10):
            raise ZenodoArchiveError("Zenodo server/capture time differs")
        parsed_body = _strict_json(body, label=f"Zenodo {role} body")
        if _contains_secret_key(parsed_body):
            raise ZenodoArchiveError("authorization material appeared in Zenodo body")
        result[role] = {"body": parsed_body}
        capture_times.append(captured)
    if capture_times != sorted(capture_times) or (
        capture_times[-1] - capture_times[0] > timedelta(minutes=10)
    ):
        raise ZenodoArchiveError("Zenodo response capture window differs")
    return result


def _verify_record_identity(
    deposition: Any,
    record: Any,
    *,
    deposition_id: int,
    record_id: int,
    doi: str,
) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(deposition, dict) or not isinstance(record, dict):
        raise ZenodoArchiveError("Zenodo deposition/record body is not an object")
    expected_record_api = f"{ZENODO_API_BASE}/records/{record_id}"
    expected_record_html = f"https://zenodo.org/records/{record_id}"
    expected_doi_url = f"https://doi.org/{doi}"
    if (
        deposition.get("id") != deposition_id
        or deposition.get("record_id") != record_id
        or deposition.get("doi") != doi
        or deposition.get("doi_url") != expected_doi_url
        or deposition.get("record_url") != expected_record_api
        or deposition.get("state") != "done"
        or deposition.get("submitted") is not True
    ):
        raise ZenodoArchiveError("Zenodo published deposition identity/state differs")
    links = record.get("links")
    metadata = record.get("metadata")
    if not isinstance(links, dict) or not isinstance(metadata, dict):
        raise ZenodoArchiveError("Zenodo record links/metadata is malformed")
    if (
        record.get("id") != record_id
        or str(record.get("recid")) != str(record_id)
        or record.get("doi") != doi
        or record.get("doi_url") != expected_doi_url
        or metadata.get("doi") != doi
        or record.get("state") != "done"
        or record.get("status") != "published"
        or record.get("submitted") is not True
        or links.get("self") != expected_record_api
        or links.get("self_html") != expected_record_html
        or links.get("doi") != expected_doi_url
    ):
        raise ZenodoArchiveError("Zenodo public record identity/state differs")
    publication_date = _date(metadata.get("publication_date"), label="Zenodo publication date")
    return publication_date, _normalize_rights(metadata)


def build_zenodo_receipt(
    *,
    manifest_path: Path,
    deposit_root: Path,
    deposition_id: int,
    record_id: int,
    doi: str,
    captures: Mapping[str, HTTPSCapture],
    receipt_created_at: str,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
    release_receipt_verifier: ReleaseReceiptVerifier = verify_release_receipt,
) -> dict[str, Any]:
    """Normalize three already captured read-only API responses into a receipt."""

    _positive_integer(deposition_id, label="deposition ID")
    _positive_integer(record_id, label="record ID")
    doi_match = DOI.fullmatch(doi) if isinstance(doi, str) else None
    if doi_match is None or int(doi_match.group(1)) != record_id:
        raise ZenodoArchiveError("DOI must be a real production version DOI for record ID")
    receipt_created = _utc(receipt_created_at, label="receipt creation time")
    manifest_raw, _manifest_value = _read_canonical(
        manifest_path, label="Zenodo deposit manifest", maximum_bytes=MAXIMUM_MANIFEST_BYTES
    )
    manifest, inventory = _validate_manifest(
        manifest_raw,
        deposit_root,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        release_receipt_verifier=release_receipt_verifier,
    )
    if manifest["zenodoReservation"] != {
        "depositionId": deposition_id,
        "recordId": record_id,
        "doi": doi,
    }:
        raise ZenodoArchiveError("collector identity differs from manifest reservation")
    if set(captures) != set(API_ROLES):
        raise ZenodoArchiveError("collector captures differ from the exact API role set")
    responses: list[dict[str, Any]] = []
    expected_targets = {
        "deposition": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}",
        "deposition-files": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}/files",
        "record": f"{ZENODO_API_BASE}/records/{record_id}",
    }
    for role in API_ROLES:
        capture = captures[role]
        if capture.status_code != 200:
            raise ZenodoArchiveError("Zenodo read-only API returned non-200")
        server_date = _parse_response_headers(
            capture.response_headers,
            expected_status=200,
            entity_bytes=len(capture.response_body),
        )
        _utc(capture.captured_at, label="Zenodo capture time")
        _strict_json(capture.response_body, label=f"Zenodo {role} body")
        responses.append(
            {
                "role": role,
                "method": "GET",
                "requestTarget": expected_targets[role],
                "authentication": "BEARER_HEADER_USED_NOT_ARCHIVED",
                "statusCode": capture.status_code,
                "serverDate": server_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "capturedAt": capture.captured_at,
                "responseHeaders": archive_bytes(capture.response_headers),
                "responseBody": archive_bytes(capture.response_body),
            }
        )
    response_map = _api_response_map(
        responses,
        deposition_id=deposition_id,
        record_id=record_id,
        receipt_created=receipt_created,
    )
    deposition = response_map["deposition"]["body"]
    record = response_map["record"]["body"]
    publication_date, observed_rights = _verify_record_identity(
        deposition,
        record,
        deposition_id=deposition_id,
        record_id=record_id,
        doi=doi,
    )
    _verify_expected_rights(manifest["rightsDeclarations"], observed_rights)
    expected_files = _expected_local_files(manifest, inventory, manifest_raw)
    deposition_files = _zenodo_file_map(
        response_map["deposition-files"]["body"], source="deposition"
    )
    deposition_inline_files = _zenodo_file_map(deposition.get("files"), source="deposition")
    record_files = _zenodo_file_map(record.get("files"), source="record")
    expected_md5 = {path: (item["bytes"], item["md5"]) for path, item in expected_files.items()}
    if (
        deposition_files != expected_md5
        or deposition_inline_files != expected_md5
        or record_files != expected_md5
    ):
        raise ZenodoArchiveError("Zenodo file metadata differs from the exact manifested set")
    normalized_files = [
        {
            "path": path,
            "bytes": expected_files[path]["bytes"],
            "localSHA256": expected_files[path]["sha256"],
            "localMD5": expected_files[path]["md5"],
            "zenodoChecksumAlgorithm": "md5",
            "zenodoChecksum": expected_files[path]["md5"],
        }
        for path in sorted(expected_files, key=lambda value: value.encode("utf-8"))
    ]
    receipt: dict[str, Any] = {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "zenodoAPIProfile": API_PROFILE,
        "evidenceBoundary": EVIDENCE_BOUNDARY,
        "environment": "production",
        "depositionId": deposition_id,
        "recordId": record_id,
        "doi": doi,
        "recordURL": f"https://zenodo.org/records/{record_id}",
        "recordAPIURL": f"{ZENODO_API_BASE}/records/{record_id}",
        "publication": {
            "state": "done",
            "status": "published",
            "submitted": True,
            "publicationDate": publication_date,
        },
        "manifest": {
            "name": MANIFEST_FILE_NAME,
            "bytes": len(manifest_raw),
            "sha256": _sha256(manifest_raw),
            "contentSHA256": manifest["contentSHA256"],
        },
        "files": normalized_files,
        "expectedRights": manifest["rightsDeclarations"],
        "observedRights": observed_rights,
        "apiResponses": responses,
        "receiptCreatedAt": receipt_created_at,
    }
    receipt["contentSHA256"] = _sha256(canonical_json_bytes(receipt))
    if _inventory_root(deposit_root) != inventory:
        raise ZenodoArchiveError("deposit changed during Zenodo receipt construction")
    return receipt


def verify_zenodo_receipt(
    raw_receipt: bytes,
    *,
    manifest_path: Path,
    deposit_root: Path,
    expected_deposition_id: int,
    expected_record_id: int,
    expected_doi: str,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
    release_receipt_verifier: ReleaseReceiptVerifier = verify_release_receipt,
) -> VerifiedZenodoReceipt:
    receipt = _canonical_document(
        raw_receipt, label="Zenodo deposit receipt", maximum_bytes=MAXIMUM_RECEIPT_BYTES
    )
    root = _mapping(
        receipt,
        {
            "schemaVersion",
            "suiteId",
            "zenodoAPIProfile",
            "evidenceBoundary",
            "environment",
            "depositionId",
            "recordId",
            "doi",
            "recordURL",
            "recordAPIURL",
            "publication",
            "manifest",
            "files",
            "expectedRights",
            "observedRights",
            "apiResponses",
            "receiptCreatedAt",
            "contentSHA256",
        },
        label="Zenodo deposit receipt",
    )
    if (
        root["schemaVersion"] != RECEIPT_SCHEMA_VERSION
        or root["suiteId"] != SUITE_ID
        or root["zenodoAPIProfile"] != API_PROFILE
        or root["evidenceBoundary"] != EVIDENCE_BOUNDARY
        or root["environment"] != "production"
    ):
        raise ZenodoArchiveError(
            "Zenodo receipt schema/suite/environment/evidence boundary differs"
        )
    digest = _digest(root["contentSHA256"], label="Zenodo receipt content digest")
    unsigned = dict(root)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != digest:
        raise ZenodoArchiveError("Zenodo receipt content digest differs")
    deposition_id = _positive_integer(root["depositionId"], label="receipt deposition ID")
    record_id = _positive_integer(root["recordId"], label="receipt record ID")
    if (
        deposition_id != expected_deposition_id
        or record_id != expected_record_id
        or root["doi"] != expected_doi
    ):
        raise ZenodoArchiveError("Zenodo receipt expected identity differs")
    doi_match = DOI.fullmatch(expected_doi) if isinstance(expected_doi, str) else None
    if doi_match is None or int(doi_match.group(1)) != record_id:
        raise ZenodoArchiveError("Zenodo receipt DOI is not a production version DOI")
    if (
        root["recordURL"] != f"https://zenodo.org/records/{record_id}"
        or root["recordAPIURL"] != f"{ZENODO_API_BASE}/records/{record_id}"
    ):
        raise ZenodoArchiveError("Zenodo receipt record URLs differ")
    receipt_created = _utc(root["receiptCreatedAt"], label="Zenodo receipt creation time")
    manifest_raw, _manifest_value = _read_canonical(
        manifest_path, label="Zenodo deposit manifest", maximum_bytes=MAXIMUM_MANIFEST_BYTES
    )
    manifest, inventory = _validate_manifest(
        manifest_raw,
        deposit_root,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
        release_receipt_verifier=release_receipt_verifier,
    )
    if manifest["zenodoReservation"] != {
        "depositionId": deposition_id,
        "recordId": record_id,
        "doi": expected_doi,
    }:
        raise ZenodoArchiveError("receipt identity differs from manifest reservation")
    manifest_record = _mapping(
        root["manifest"],
        {"name", "bytes", "sha256", "contentSHA256"},
        label="manifest receipt binding",
    )
    if (
        manifest_record["name"] != MANIFEST_FILE_NAME
        or manifest_record["bytes"] != len(manifest_raw)
        or manifest_record["sha256"] != _sha256(manifest_raw)
        or manifest_record["contentSHA256"] != manifest["contentSHA256"]
    ):
        raise ZenodoArchiveError("Zenodo receipt manifest binding differs")
    expected_rights = _validate_rights_declarations(root["expectedRights"])
    if (
        root["expectedRights"] != expected_rights
        or expected_rights != manifest["rightsDeclarations"]
    ):
        raise ZenodoArchiveError("Zenodo receipt expected rights differ from manifest")
    responses = _api_response_map(
        root["apiResponses"],
        deposition_id=deposition_id,
        record_id=record_id,
        receipt_created=receipt_created,
    )
    deposition = responses["deposition"]["body"]
    record = responses["record"]["body"]
    publication_date, observed_rights = _verify_record_identity(
        deposition,
        record,
        deposition_id=deposition_id,
        record_id=record_id,
        doi=expected_doi,
    )
    publication = _mapping(
        root["publication"],
        {"state", "status", "submitted", "publicationDate"},
        label="publication",
    )
    if publication != {
        "state": "done",
        "status": "published",
        "submitted": True,
        "publicationDate": publication_date,
    }:
        raise ZenodoArchiveError("Zenodo receipt publication state differs")
    if root["observedRights"] != observed_rights:
        raise ZenodoArchiveError("Zenodo normalized rights receipt differs")
    _verify_expected_rights(expected_rights, observed_rights)
    expected_files = _expected_local_files(manifest, inventory, manifest_raw)
    expected_md5 = {path: (item["bytes"], item["md5"]) for path, item in expected_files.items()}
    if (
        _zenodo_file_map(responses["deposition-files"]["body"], source="deposition") != expected_md5
        or _zenodo_file_map(deposition.get("files"), source="deposition") != expected_md5
        or _zenodo_file_map(record.get("files"), source="record") != expected_md5
    ):
        raise ZenodoArchiveError("Zenodo published file set differs from local manifested bytes")
    normalized_files = [
        {
            "path": path,
            "bytes": expected_files[path]["bytes"],
            "localSHA256": expected_files[path]["sha256"],
            "localMD5": expected_files[path]["md5"],
            "zenodoChecksumAlgorithm": "md5",
            "zenodoChecksum": expected_files[path]["md5"],
        }
        for path in sorted(expected_files, key=lambda value: value.encode("utf-8"))
    ]
    if root["files"] != normalized_files:
        raise ZenodoArchiveError("Zenodo normalized file receipt differs")
    if _inventory_root(deposit_root) != inventory:
        raise ZenodoArchiveError("deposit changed during Zenodo receipt verification")
    return VerifiedZenodoReceipt(
        deposition_id=deposition_id,
        record_id=record_id,
        doi=expected_doi,
        release_kind=manifest["releaseKind"],
        manifest_sha256=_sha256(manifest_raw),
        receipt_sha256=_sha256(raw_receipt),
        file_sha256=tuple(
            (path, expected_files[path]["sha256"])
            for path in sorted(expected_files)
        ),
    )


def write_zenodo_receipt_to_path(
    receipt: Mapping[str, Any],
    output_path: Path,
) -> bytes:
    raw = canonical_json_bytes(receipt) + b"\n"
    write_new_bytes(output_path, raw)
    return raw
