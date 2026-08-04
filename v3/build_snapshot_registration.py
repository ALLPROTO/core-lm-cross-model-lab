#!/usr/bin/env python3
"""Build the pre-publication blind-v3 snapshot registration offline.

The builder accepts only already-existing commitments.  It performs no
transport, tokenizer/model import, inference, selection, or attempt-state
mutation.  The resulting file is canonical JSON plus one LF and is created
exclusively; an existing destination is never replaced.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.mediawiki_snapshot import verify_corpus_snapshot  # noqa: E402
from v3.collect_snapshot import (  # noqa: E402
    default_tokenizer_factory,
    verify_assets_and_load_tokenizer_bytes,
)
from v3.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict_bytes,
    sha256_bytes,
    validate_frozen_design_registration,
    validate_model_asset_manifest,
    validate_snapshot_registration,
)
from v3.publication import PublicationError, verify_publication  # noqa: E402
from v3.release_attestation_crypto import (  # noqa: E402
    PinnedCosignReleaseAttestationVerifier,
)
from v3.release_receipt import (  # noqa: E402
    API_ROLES,
    GITHUB_API_VERSION,
    REQUIRED_ASSET_ROLES,
    ReleaseAttestationCryptographicVerifier,
    SCHEMA_VERSION as RELEASE_RECEIPT_SCHEMA,
)
from v3.reproducibility import verify_content_digest, write_new_bytes  # noqa: E402


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
SNAPSHOT_SCHEMA = "corelm-crossmodel-livewiki-v3-snapshot-registration-v1"
CORPUS_SCHEMA = "corelm-crossmodel-livewiki-v3-corpus-manifest-v1"
ASSET_RECEIPT_SCHEMA = "corelm-crossmodel-livewiki-v3-asset-receipt-v1"
REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_JSON_BYTES = 64 * 1024 * 1024
MAXIMUM_LEDGER_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
ASSET_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,190}[A-Za-z0-9])?\Z")


class SnapshotRegistrationBuildError(ValueError):
    """An input is mutable, noncanonical, unverified, or cross-bound wrongly."""


def _open_directory_no_symlinks(path: Path, *, label: str) -> tuple[int, Path]:
    """Open an absolute directory one no-follow component at a time."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as error:
        raise SnapshotRegistrationBuildError(
            f"{label} filesystem anchor cannot be opened"
        ) from error
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise SnapshotRegistrationBuildError(
                    f"{label} parent component is not a directory"
                )
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise SnapshotRegistrationBuildError(
            f"{label} path contains a symlink or invalid parent component"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute


def _assert_directory_no_symlinks(path: Path, *, label: str) -> Path:
    descriptor, absolute = _open_directory_no_symlinks(path, label=label)
    os.close(descriptor)
    return absolute


def _read_regular(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent_descriptor, _parent = _open_directory_no_symlinks(
        absolute.parent, label=f"{label} parent"
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
    except OSError as error:
        os.close(parent_descriptor)
        raise SnapshotRegistrationBuildError(
            f"{label} is not a no-follow regular file"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise SnapshotRegistrationBuildError(f"{label} size/type is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise SnapshotRegistrationBuildError(f"{label} exceeds its byte bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
        )
        if identity(before) != identity(after) or observed != before.st_size:
            raise SnapshotRegistrationBuildError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def _load_json(raw: bytes, *, label: str, canonical_lf: bool | None) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise SnapshotRegistrationBuildError(str(error)) from error
    if not isinstance(value, dict):
        raise SnapshotRegistrationBuildError(f"{label} must be a JSON object")
    if canonical_lf is True and raw != canonical_json_bytes(value) + b"\n":
        raise SnapshotRegistrationBuildError(f"{label} is not canonical JSON plus LF")
    if canonical_lf is False and raw != canonical_json_bytes(value):
        raise SnapshotRegistrationBuildError(f"{label} is not canonical JSON without LF")
    return value


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise SnapshotRegistrationBuildError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise SnapshotRegistrationBuildError(f"{label} is not a real timestamp") from error


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise SnapshotRegistrationBuildError(f"{label} is not a lowercase SHA-256")
    return value


def _safe_relative(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SnapshotRegistrationBuildError(f"{label} is not a safe relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SnapshotRegistrationBuildError(f"{label} is not a safe relative path")
    return value


def _validate_asset_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    manifest_raw: bytes,
) -> None:
    fields = {
        "schemaVersion",
        "status",
        "countsTowardScientificVerdict",
        "networkUsed",
        "modelInferenceUsed",
        "manifestFile",
        "manifestSchemaVersion",
        "manifestDeclaredStatus",
        "manifestDeclaredFullSafetensorsBytesLocallyVerified",
        "manifestFileBytes",
        "manifestFileSHA256",
        "assetLayout",
        "fileCount",
        "totalBytes",
        "fullSafetensorsBytesLocallyVerified",
        "fullSafetensorsBytes",
        "models",
        "contentSHA256",
    }
    if set(receipt) != fields:
        raise SnapshotRegistrationBuildError("full asset receipt fields differ")
    try:
        verify_content_digest(dict(receipt))
    except ValueError as error:
        raise SnapshotRegistrationBuildError("full asset receipt self-digest differs") from error
    if (
        receipt["schemaVersion"] != ASSET_RECEIPT_SCHEMA
        or receipt["status"] != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED"
        or receipt["countsTowardScientificVerdict"] is not False
        or receipt["networkUsed"] is not False
        or receipt["modelInferenceUsed"] is not False
        or receipt["fullSafetensorsBytesLocallyVerified"] is not True
        or receipt["manifestFile"] != "model-assets.draft.json"
        or receipt["manifestSchemaVersion"] != manifest["schemaVersion"]
        or receipt["manifestDeclaredStatus"] != manifest["status"]
        or receipt["manifestDeclaredFullSafetensorsBytesLocallyVerified"]
        != manifest["fullSafetensorsBytesLocallyVerified"]
        or receipt["manifestFileBytes"] != len(manifest_raw)
        or receipt["manifestFileSHA256"] != sha256_bytes(manifest_raw)
        or receipt["assetLayout"]
        != "<asset-root>/<model-key>/<manifest-relative-file>"
    ):
        raise SnapshotRegistrationBuildError("full asset receipt boundary differs")
    models = receipt["models"]
    source_models = manifest["models"]
    if not isinstance(models, dict) or tuple(models) != tuple(source_models):
        raise SnapshotRegistrationBuildError("full asset receipt model order/set differs")
    file_count = total_bytes = weight_bytes = 0
    for model_key, source in source_models.items():
        observed = models.get(model_key)
        if not isinstance(observed, dict) or set(observed) != {
            "repository", "revision", "license", "licenseURL", "files"
        }:
            raise SnapshotRegistrationBuildError(f"asset receipt model differs: {model_key}")
        for field in ("repository", "revision", "license", "licenseURL"):
            if observed[field] != source[field]:
                raise SnapshotRegistrationBuildError(
                    f"asset receipt source field differs: {model_key}/{field}"
                )
        files = observed["files"]
        if not isinstance(files, dict) or tuple(files) != tuple(source["files"]):
            raise SnapshotRegistrationBuildError(f"asset receipt files differ: {model_key}")
        for filename, specification in source["files"].items():
            expected = {"bytes": specification["bytes"], "sha256": specification["sha256"]}
            if files[filename] != expected:
                raise SnapshotRegistrationBuildError(
                    f"asset receipt commitment differs: {model_key}/{filename}"
                )
            file_count += 1
            total_bytes += specification["bytes"]
            if filename == "model.safetensors":
                weight_bytes += specification["bytes"]
    if (
        receipt["fileCount"] != file_count
        or receipt["totalBytes"] != total_bytes
        or receipt["fullSafetensorsBytes"] != weight_bytes
    ):
        raise SnapshotRegistrationBuildError("full asset receipt totals differ")


def _validate_design_receipt(
    receipt: Mapping[str, Any],
    *,
    design: Mapping[str, Any],
    design_raw: bytes,
    asset_manifest_raw: bytes,
    asset_receipt_raw: bytes,
) -> None:
    fields = {
        "schemaVersion", "suiteId", "githubAPIVersion", "repository", "kind",
        "tag", "release", "source", "annotatedTag", "signatureVerification",
        "githubReleaseAttestation", "requiredAssets", "githubAPIResponses",
        "receiptCreatedAt", "contentSHA256",
    }
    if set(receipt) != fields:
        raise SnapshotRegistrationBuildError("design publication receipt fields differ")
    try:
        verify_content_digest(dict(receipt))
    except ValueError as error:
        raise SnapshotRegistrationBuildError(
            "design publication receipt self-digest differs"
        ) from error
    release_plan = design["designRelease"]
    repository = receipt["repository"]
    if (
        receipt["schemaVersion"] != RELEASE_RECEIPT_SCHEMA
        or receipt["suiteId"] != SUITE_ID
        or receipt["githubAPIVersion"] != GITHUB_API_VERSION
        or repository
        != {
            "slug": REPOSITORY,
            "htmlURL": f"https://github.com/{REPOSITORY}",
            "apiURL": f"https://api.github.com/repos/{REPOSITORY}",
        }
        or receipt["kind"] != "design"
        or receipt["tag"] != release_plan["tag"]
    ):
        raise SnapshotRegistrationBuildError("design publication receipt identity differs")
    release = receipt["release"]
    if not isinstance(release, dict) or set(release) != {
        "id", "apiURL", "htmlURL", "publishedAt", "deadline"
    }:
        raise SnapshotRegistrationBuildError("design publication release fields differ")
    if (
        type(release["id"]) is not int
        or release["id"] < 1
        or release["deadline"] != release_plan["publishNoLaterThan"]
        or _utc(release["publishedAt"], label="design publishedAt")
        >= _utc(release["deadline"], label="design deadline")
    ):
        raise SnapshotRegistrationBuildError("design publication release timing differs")
    source = receipt["source"]
    annotated = receipt["annotatedTag"]
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "tree", "commitObject"}
        or source["commit"] != design["labSource"]["commit"]
        or source["tree"] != design["labSource"]["tree"]
        or not isinstance(annotated, dict)
        or annotated.get("targetType") != "commit"
        or annotated.get("targetCommit") != source["commit"]
    ):
        raise SnapshotRegistrationBuildError("design publication source binding differs")
    signature = receipt["signatureVerification"]
    if (
        not isinstance(signature, dict)
        or signature.get("status") != "VERIFIED"
        or signature.get("signatureType") != release_plan["signatureType"]
        or signature.get("keyFingerprint") != release_plan["signingKeyFingerprint"]
        or signature.get("publicKeySHA256") != release_plan["signingPublicKeySHA256"]
        or signature.get("targetCommit") != source["commit"]
        or signature.get("exitCode") != 0
    ):
        raise SnapshotRegistrationBuildError("design publication signature binding differs")
    assets = receipt["requiredAssets"]
    if not isinstance(assets, list) or tuple(
        item.get("role") if isinstance(item, dict) else None for item in assets
    ) != REQUIRED_ASSET_ROLES["design"]:
        raise SnapshotRegistrationBuildError("design publication asset roles differ")
    by_role: dict[str, Mapping[str, Any]] = {}
    for item in assets:
        if set(item) != {
            "role", "assetId", "name", "apiURL", "downloadURL", "bytes", "sha256"
        }:
            raise SnapshotRegistrationBuildError("design publication asset fields differ")
        if (
            type(item["assetId"]) is not int
            or item["assetId"] < 1
            or type(item["bytes"]) is not int
            or item["bytes"] < 1
            or not isinstance(item["name"], str)
            or ASSET_NAME.fullmatch(item["name"]) is None
        ):
            raise SnapshotRegistrationBuildError("design publication asset record is invalid")
        _digest(item["sha256"], label=f"design asset {item['role']}")
        by_role[item["role"]] = item
    expected_inputs = {
        "design-registration": design_raw,
        "asset-source-manifest": asset_manifest_raw,
        "full-asset-receipt": asset_receipt_raw,
    }
    for role, raw in expected_inputs.items():
        if by_role[role]["bytes"] != len(raw) or by_role[role]["sha256"] != sha256_bytes(raw):
            raise SnapshotRegistrationBuildError(
                f"design publication receipt binds another {role}"
            )
    responses = receipt["githubAPIResponses"]
    if not isinstance(responses, list) or tuple(
        item.get("role") if isinstance(item, dict) else None for item in responses
    ) != API_ROLES:
        raise SnapshotRegistrationBuildError("design publication API response roles differ")


def _verify_design_publication(
    *,
    receipt_path: Path,
    receipt_raw: bytes,
    receipt: Mapping[str, Any],
    design: Mapping[str, Any],
    design_release_asset_root: Path,
    signing_public_key_path: Path,
    cryptographic_attestation_verifier: ReleaseAttestationCryptographicVerifier,
) -> None:
    """Run the complete archived GitHub/tag/signature/asset verifier offline."""

    asset_root = _assert_directory_no_symlinks(
        design_release_asset_root, label="design release asset root"
    )
    key_before = _read_regular(
        signing_public_key_path,
        label="release signing public key",
        maximum_bytes=64 * 1024,
    )
    release = design["designRelease"]
    if sha256_bytes(key_before) != release["signingPublicKeySHA256"]:
        raise SnapshotRegistrationBuildError(
            "release signing public key differs from the frozen design"
        )
    expected_role_paths = {
        item["role"]: asset_root / item["name"]
        for item in receipt["requiredAssets"]
    }
    if tuple(expected_role_paths) != REQUIRED_ASSET_ROLES["design"]:
        raise SnapshotRegistrationBuildError("design release role paths differ")
    try:
        verified = verify_publication(
            receipt_path,
            asset_root,
            kind="design",
            tag=release["tag"],
            deadline=release["publishNoLaterThan"],
            signing_public_key_path=signing_public_key_path,
            signing_key_fingerprint=release["signingKeyFingerprint"],
            signing_public_key_sha256=release["signingPublicKeySHA256"],
            expected_role_paths=expected_role_paths,
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
    except (OSError, ValueError, PublicationError) as error:
        raise SnapshotRegistrationBuildError(
            "design publication failed complete offline verification"
        ) from error
    if (
        verified.receipt_sha256 != sha256_bytes(receipt_raw)
        or verified.source_commit != design["labSource"]["commit"]
        or verified.source_tree != design["labSource"]["tree"]
        or dict(verified.role_sha256)
        != {
            item["role"]: item["sha256"]
            for item in sorted(receipt["requiredAssets"], key=lambda item: item["role"])
        }
    ):
        raise SnapshotRegistrationBuildError(
            "verified design publication differs from the frozen inputs"
        )
    if _read_regular(
        receipt_path,
        label="design publication receipt after verification",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    ) != receipt_raw:
        raise SnapshotRegistrationBuildError(
            "design publication receipt changed during verification"
        )
    if _read_regular(
        signing_public_key_path,
        label="release signing public key after verification",
        maximum_bytes=64 * 1024,
    ) != key_before:
        raise SnapshotRegistrationBuildError(
            "release signing public key changed during verification"
        )


def _load_verified_tokenizers(
    *,
    asset_root: Path,
    asset_manifest_path: Path,
    asset_manifest_raw: bytes,
    asset_manifest: Mapping[str, Any],
    asset_receipt: Mapping[str, Any],
    model_order: list[str],
) -> dict[str, Any]:
    """Reopen owned tokenizer bytes through the collector's no-symlink reader."""

    try:
        verified = verify_assets_and_load_tokenizer_bytes(
            manifest_path=asset_manifest_path,
            expected_manifest_sha256=sha256_bytes(asset_manifest_raw),
            asset_root=asset_root,
        )
    except (OSError, ValueError) as error:
        raise SnapshotRegistrationBuildError(
            "registered local asset bytes failed verification"
        ) from error
    if (
        verified.manifest_sha256 != sha256_bytes(asset_manifest_raw)
        or verified.file_count != asset_receipt["fileCount"]
        or verified.total_bytes != asset_receipt["totalBytes"]
        or list(verified.tokenizer_bytes) != model_order
    ):
        raise SnapshotRegistrationBuildError(
            "verified local assets differ from the full asset receipt"
        )
    tokenizers: dict[str, Any] = {}
    for model_key in model_order:
        raw = verified.tokenizer_bytes[model_key]
        source = asset_manifest["models"][model_key]["files"]["tokenizer.json"]
        receipt = asset_receipt["models"][model_key]["files"]["tokenizer.json"]
        if (
            receipt != {"bytes": source["bytes"], "sha256": source["sha256"]}
            or len(raw) != source["bytes"]
            or sha256_bytes(raw) != source["sha256"]
        ):
            raise SnapshotRegistrationBuildError(
                f"owned tokenizer bytes differ: {model_key}"
            )
        try:
            tokenizers[model_key] = default_tokenizer_factory(model_key, raw)
        except (OSError, ValueError) as error:
            raise SnapshotRegistrationBuildError(
                f"cannot construct registered tokenizer: {model_key}"
            ) from error
    return tokenizers


def build_snapshot_registration(
    *,
    frozen_design_path: Path,
    corpus_root: Path,
    asset_root: Path,
    design_release_asset_root: Path,
    signing_public_key_path: Path,
    design_publication_receipt_path: Path,
    asset_source_manifest_path: Path,
    full_asset_receipt_path: Path,
    created_at: str,
    cryptographic_attestation_verifier: ReleaseAttestationCryptographicVerifier,
) -> bytes:
    """Return canonical registration bytes after replaying all committed corpus bytes."""

    design_raw = _read_regular(
        frozen_design_path, label="frozen design", maximum_bytes=MAXIMUM_JSON_BYTES
    )
    design = _load_json(design_raw, label="frozen design", canonical_lf=True)
    try:
        validate_frozen_design_registration(design)
    except ValueError as error:
        raise SnapshotRegistrationBuildError("frozen design is invalid") from error

    asset_manifest_raw = _read_regular(
        asset_source_manifest_path,
        label="asset source manifest",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    )
    asset_manifest = _load_json(
        asset_manifest_raw, label="asset source manifest", canonical_lf=None
    )
    try:
        validate_model_asset_manifest(asset_manifest, design)
    except ValueError as error:
        raise SnapshotRegistrationBuildError("asset source manifest is invalid") from error

    asset_receipt_raw = _read_regular(
        full_asset_receipt_path,
        label="full asset receipt",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    )
    asset_receipt = _load_json(
        asset_receipt_raw, label="full asset receipt", canonical_lf=True
    )
    _validate_asset_receipt(
        asset_receipt, manifest=asset_manifest, manifest_raw=asset_manifest_raw
    )

    design_receipt_raw = _read_regular(
        design_publication_receipt_path,
        label="design publication receipt",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    )
    design_receipt = _load_json(
        design_receipt_raw,
        label="design publication receipt",
        canonical_lf=True,
    )
    _validate_design_receipt(
        design_receipt,
        design=design,
        design_raw=design_raw,
        asset_manifest_raw=asset_manifest_raw,
        asset_receipt_raw=asset_receipt_raw,
    )
    created = _utc(created_at, label="snapshot createdAt")
    not_before = _utc(
        design["futureCorpus"]["secondCrawlNotBefore"],
        label="second crawl not-before",
    )
    deadline = _utc(
        design["snapshotRelease"]["publishNoLaterThan"],
        label="snapshot release deadline",
    )
    if created < not_before or created >= deadline:
        raise SnapshotRegistrationBuildError(
            "snapshot createdAt is outside the pre-publication window"
        )

    _verify_design_publication(
        receipt_path=design_publication_receipt_path,
        receipt_raw=design_receipt_raw,
        receipt=design_receipt,
        design=design,
        design_release_asset_root=design_release_asset_root,
        signing_public_key_path=signing_public_key_path,
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )

    models = [model["key"] for model in design["models"]]
    tokenizers = _load_verified_tokenizers(
        asset_root=asset_root,
        asset_manifest_path=asset_source_manifest_path,
        asset_manifest_raw=asset_manifest_raw,
        asset_manifest=asset_manifest,
        asset_receipt=asset_receipt,
        model_order=models,
    )

    safe_corpus_root = _assert_directory_no_symlinks(
        corpus_root, label="corpus root"
    )
    corpus_manifest_path = safe_corpus_root / "corpus-manifest.json"
    manifest_before = _read_regular(
        corpus_manifest_path,
        label="corpus manifest",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    )
    try:
        verification = verify_corpus_snapshot(
            safe_corpus_root, tokenizers=tokenizers
        )
    except (OSError, ValueError) as error:
        raise SnapshotRegistrationBuildError("corpus replay failed") from error
    if (
        verification.get("status") != "VERIFIED_SNAPSHOT_BYTES"
        or verification.get("readyForFreeze") is not True
        or verification.get("tokenCommitmentsRecomputed") is not True
        or verification.get("modelInferenceUsed") is not False
        or verification.get("manifestSHA256") != sha256_bytes(manifest_before)
    ):
        raise SnapshotRegistrationBuildError("corpus replay is not freeze-ready")
    manifest_after = _read_regular(
        corpus_manifest_path,
        label="corpus manifest after replay",
        maximum_bytes=MAXIMUM_JSON_BYTES,
    )
    if manifest_after != manifest_before:
        raise SnapshotRegistrationBuildError("corpus manifest changed during replay")
    corpus_manifest = _load_json(
        manifest_after, label="corpus manifest", canonical_lf=False
    )
    projects = list(design["futureCorpus"]["projects"])
    if (
        set(corpus_manifest) != {
            "schemaVersion", "suiteId", "status",
            "countsTowardScientificVerdict", "projects",
        }
        or corpus_manifest["schemaVersion"] != CORPUS_SCHEMA
        or corpus_manifest["suiteId"] != SUITE_ID
        or corpus_manifest["status"] != "SNAPSHOT_READY_FOR_FREEZE"
        or corpus_manifest["countsTowardScientificVerdict"] is not False
        or not isinstance(corpus_manifest["projects"], dict)
        or list(corpus_manifest["projects"]) != projects
    ):
        raise SnapshotRegistrationBuildError("corpus manifest registration boundary differs")

    ledgers: dict[str, str] = {}
    for project in projects:
        entry = corpus_manifest["projects"][project]
        commitment = entry.get("ledger") if isinstance(entry, dict) else None
        if not isinstance(commitment, dict) or set(commitment) != {
            "relativePath", "bytes", "sha256"
        }:
            raise SnapshotRegistrationBuildError(f"ledger commitment differs: {project}")
        relative = _safe_relative(
            commitment["relativePath"], label=f"ledger path {project}"
        )
        if type(commitment["bytes"]) is not int or commitment["bytes"] < 1:
            raise SnapshotRegistrationBuildError(f"ledger byte count differs: {project}")
        digest = _digest(commitment["sha256"], label=f"ledger SHA-256 {project}")
        ledger_raw = _read_regular(
            safe_corpus_root / relative,
            label=f"ledger {project}",
            maximum_bytes=MAXIMUM_LEDGER_BYTES,
        )
        if len(ledger_raw) != commitment["bytes"] or sha256_bytes(ledger_raw) != digest:
            raise SnapshotRegistrationBuildError(f"ledger bytes differ: {project}")
        ledgers[project] = digest

    release = design["snapshotRelease"]
    snapshot = {
        "schemaVersion": SNAPSHOT_SCHEMA,
        "suiteId": design["suiteId"],
        "status": "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION",
        "designPublicationReceiptSHA256": sha256_bytes(design_receipt_raw),
        "snapshotReleasePlan": {
            key: release[key]
            for key in (
                "tag",
                "publishNoLaterThan",
                "serverTimestampRequired",
                "immutableReleaseRequired",
                "signedAnnotatedTagRequired",
            )
        },
        "projects": projects,
        "models": models,
        "ledgers": ledgers,
        "modelAssetSourceManifestSHA256": sha256_bytes(asset_manifest_raw),
        "fullAssetReceiptSHA256": sha256_bytes(asset_receipt_raw),
        "corpusManifestSHA256": sha256_bytes(manifest_after),
        "createdAt": created_at,
    }
    try:
        validate_snapshot_registration(snapshot, allow_fixture=False)
    except ValueError as error:
        raise SnapshotRegistrationBuildError(
            "derived snapshot registration failed its normative validator"
        ) from error
    return canonical_json_bytes(snapshot) + b"\n"


def build_snapshot_registration_to_path(*, output: Path, **inputs: Any) -> bytes:
    destination = Path(os.path.abspath(os.fspath(output)))
    implementation_root = PROJECT_ROOT.resolve(strict=True)
    try:
        destination.relative_to(implementation_root)
    except ValueError:
        pass
    else:
        raise SnapshotRegistrationBuildError(
            "snapshot output must remain outside the author-verified lab checkout"
        )
    raw = build_snapshot_registration(**inputs)
    try:
        write_new_bytes(output, raw)
    except (OSError, ValueError) as error:
        raise SnapshotRegistrationBuildError("snapshot output publication failed") from error
    return raw


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-design", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--design-release-asset-root", type=Path, required=True)
    parser.add_argument("--signing-public-key", type=Path, required=True)
    parser.add_argument("--design-publication-receipt", type=Path, required=True)
    parser.add_argument("--asset-source-manifest", type=Path, required=True)
    parser.add_argument("--full-asset-receipt", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        build_snapshot_registration_to_path(
            output=arguments.output,
            frozen_design_path=arguments.frozen_design,
            corpus_root=arguments.corpus_root,
            asset_root=arguments.asset_root,
            design_release_asset_root=arguments.design_release_asset_root,
            signing_public_key_path=arguments.signing_public_key,
            design_publication_receipt_path=arguments.design_publication_receipt,
            asset_source_manifest_path=arguments.asset_source_manifest,
            full_asset_receipt_path=arguments.full_asset_receipt,
            created_at=arguments.created_at,
            cryptographic_attestation_verifier=(
                PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            ),
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"SNAPSHOT REGISTRATION FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SnapshotRegistrationBuildError",
    "build_snapshot_registration",
    "build_snapshot_registration_to_path",
]
