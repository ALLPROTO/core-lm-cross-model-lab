#!/usr/bin/env python3
"""Fail-closed supervisor for the registered blind-v3 one-shot.

This program has two deliberately separate phases:

``prepare``
    Verify the public design/snapshot, complete corpus, runtime, model assets,
    NIST trust material, and exact Git source identities.  Copy every byte that
    may be needed later into a read-only private snapshot.  This phase never
    fetches the selection pulse and never creates an attempt reservation or marker.

``run-one-shot``
    Re-exec the supervisor from the sealed private lab tree, repeat all offline
    checks, enforce the registered time window, durably reserve and mark the
    attempt, make exactly one HTTPS request to the exact NIST endpoint, seal and verify it,
    disable networking, derive the selection, execute one model per process,
    and publish an immutable local terminal outcome.

There is no retry flag and no fixture mode.  Unit fixtures exercise pure helper
functions only; this CLI accepts production frozen artifacts exclusively.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.evidence import (  # noqa: E402
    build_sha256_manifest,
    canonical_json_line,
    evaluate_raw_evidence,
    load_canonical_jsonl,
    selected_ledger_token_commitments,
    verify_page_token_evidence,
)
from v3.freeze_manifest import (  # noqa: E402
    validate_freeze_manifest as validate_freeze_manifest_contract,
    verify_artifact_inputs as verify_freeze_artifact_inputs,
)
from v3.git_source import (  # noqa: E402
    GitSourceSeal,
    build_source_manifest,
    seal_git_source,
    source_manifest_bytes,
    verify_copied_source,
)
from v3.mediawiki_snapshot import (  # noqa: E402
    ArchivedHTTPResponse,
    PinnedHTTPSClient,
    PROJECTS,
    load_record_bytes,
    verify_corpus_snapshot,
)
from v3.nist_beacon import (  # noqa: E402
    TARGET_ENDPOINT,
    TARGET_TIMESTAMP,
    TARGET_UNIX_MILLISECONDS,
    canonical_verification_bytes,
    load_offline_trust_bundle,
    verify_nist_pulse_response,
)
from v3.package_design_release import (  # noqa: E402
    DesignReleaseError,
    verify_design_release_package,
)
from v3.package_snapshot_release import (  # noqa: E402
    SnapshotReleaseError,
    verify_snapshot_release,
)
from v3.preflight import (  # noqa: E402
    platform_safety,
    verify_asset_receipt,
    verify_codec_source,
    verify_file_beneath,
    verify_local_assets,
)
from v3.publication import (  # noqa: E402
    PublicationError,
    require_frozen_lab_publication_source,
    verify_publication,
)
from v3.release_attestation_crypto import (  # noqa: E402
    COSIGN_BINARY_VARIANTS,
    PinnedCosignReleaseAttestationVerifier,
)
from v3.protocol import (  # noqa: E402
    MODELS,
    SUITE_ID,
    canonical_json_bytes,
    load_json_strict,
    load_json_strict_bytes,
    resolve_selection,
    sha256_bytes,
    validate_model_asset_manifest,
    validate_snapshot_registration,
)
from v3.reproducibility import (  # noqa: E402
    digest_regular_file,
    scan_tree,
    verify_content_digest,
    write_new_bytes,
)
from v3.state_machine import (  # noqa: E402
    create_attempt_marker,
    create_terminal_outcome,
    load_attempt_marker,
    load_terminal_outcome,
)


PRIVATE_SCHEMA = "corelm-crossmodel-livewiki-v3-private-snapshot-manifest-v1"
FREEZE_SCHEMA = "corelm-crossmodel-livewiki-v3-freeze-manifest-v1"
RESULT_SCHEMA = "corelm-crossmodel-livewiki-v3-result-v1"
ONE_SHOT_NOT_BEFORE = datetime(2026, 9, 3, 18, tzinfo=timezone.utc)
HARD_DEADLINE = datetime(2026, 9, 4, 18, tzinfo=timezone.utc)
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FAILURE_REASON = 4096
MACOS_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
NETWORK_DENY_PROFILE = "(version 1)(allow default)(deny network*)"
SCIENTIFIC_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
SCIENTIFIC_PYTHON_FLAGS = ("-P", "-s", "-B")
SCIENTIFIC_RUNTIME_IMPORT_VERSIONS = {
    "jsonschema": "4.25.1",
    "numpy": "2.5.1",
    "pyarrow": "23.0.1",
    "safetensors": "0.8.0",
    "tokenizers": "0.22.2",
    "transformers": "5.14.1",
}
SCIENTIFIC_HASH_INPUT = "corelm-crossmodel-livewiki-v3"
SCIENTIFIC_HASH_KNOWN_ANSWER = 7326695182870824334
PRIVATE_ROLES = frozenset(
    {
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
)


class RunnerError(RuntimeError):
    """Raised when a scientific execution prerequisite or transition fails."""


def sha256_file(path: Path) -> str:
    return digest_regular_file(path)["sha256"]


def verify_registered_ci_workflow_bytes(
    design: Mapping[str, Any], raw: bytes
) -> None:
    ci = design.get("continuousIntegration")
    if not isinstance(ci, dict):
        raise RunnerError("registered CI workflow binding is absent")
    if (
        len(raw) != ci.get("workflowFileBytes")
        or sha256_bytes(raw) != ci.get("workflowFileSHA256")
    ):
        raise RunnerError("registered CI workflow bytes differ from the frozen source")


def verify_registered_ci_workflow_seal(
    design: Mapping[str, Any], seal: GitSourceSeal
) -> None:
    ci = design.get("continuousIntegration")
    path = ci.get("workflowPath") if isinstance(ci, dict) else None
    matches = [entry for entry in seal.files if entry.path == path]
    if len(matches) != 1:
        raise RunnerError("exact registered CI workflow is absent from the lab Git tree")
    verify_registered_ci_workflow_bytes(design, matches[0].data)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_seconds(value: datetime) -> str:
    if value.tzinfo is None:
        raise RunnerError("UTC timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def attempt_id(now: datetime) -> str:
    prefix = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result = prefix + "-" + secrets.token_hex(8)
    if ATTEMPT_ID.fullmatch(result) is None:
        raise RunnerError("internal attempt ID construction failed")
    return result


def ensure_one_shot_window(now: datetime) -> None:
    if now.tzinfo is None:
        raise RunnerError("one-shot clock must be timezone-aware")
    observed = now.astimezone(timezone.utc)
    if observed < ONE_SHOT_NOT_BEFORE:
        raise RunnerError(
            "scientific one-shot is not yet allowed: "
            + ONE_SHOT_NOT_BEFORE.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    if observed >= HARD_DEADLINE:
        raise RunnerError(
            "scientific one-shot deadline expired before marker creation"
        )


def verify_external_attempt_time_anchor(verification: Mapping[str, Any]) -> datetime:
    """Corroborate the post-marker start window with NIST's HTTPS Date."""

    value = verification.get("responseDate")
    if not isinstance(value, str):
        raise RunnerError("verified NIST response has no HTTPS Date time anchor")
    try:
        observed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise RunnerError("verified NIST HTTPS Date is not canonical UTC") from error
    if observed < ONE_SHOT_NOT_BEFORE or observed >= HARD_DEADLINE:
        raise RunnerError(
            "verified NIST HTTPS Date is outside the registered one-shot window"
        )
    return observed


def _validate_schema(instance: Any, filename: str) -> None:
    """Apply the canonical schema from the locked scientific runtime."""

    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:
        raise RunnerError(
            "locked scientific runtime lacks the required jsonschema validator"
        ) from error
    schema = load_json_strict(V3_ROOT / "schemas" / filename)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = "$" + "".join(f"[{part!r}]" for part in first.path)
        raise RunnerError(f"{filename} validation failed at {location}: {first.message}")


def validate_frozen_design(design: Any) -> None:
    """Validate lifecycle bindings while reusing the exact tracked draft body."""

    if not isinstance(design, dict):
        raise RunnerError("frozen design must be a JSON object")
    _validate_schema(design, "design.schema.json")
    reference = load_json_strict(V3_ROOT / "design-registration.draft.json")
    if design.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-design-v1":
        raise RunnerError("scientific runner requires design-v1")
    if design.get("status") != "PUBLIC_DESIGN_FROZEN":
        raise RunnerError("scientific runner refuses a non-public or draft design")
    if design.get("readyToFreeze") is not True or design.get("freezeBlockers") != []:
        raise RunnerError("frozen design still contains readiness blockers")
    if design.get("countsTowardScientificVerdict") is not False:
        raise RunnerError("a design registration cannot itself claim a verdict")

    lab = design.get("labSource")
    runtime = design.get("runtime")
    beacon = design.get("beacon")
    if not isinstance(lab, dict) or not isinstance(runtime, dict) or not isinstance(beacon, dict):
        raise RunnerError("frozen design lifecycle bindings are incomplete")
    expected_lab_fields = {
        "repository", "status", "commit", "tree", "freezeManifestSHA256"
    }
    if set(lab) != expected_lab_fields or lab.get("status") != "FROZEN_BOUND":
        raise RunnerError("frozen lab source binding differs")
    for field in ("commit", "tree"):
        if not isinstance(lab.get(field), str) or HEX_40.fullmatch(lab[field]) is None:
            raise RunnerError(f"frozen lab {field} is invalid")
    if not isinstance(lab.get("freezeManifestSHA256"), str) or HEX_64.fullmatch(
        lab["freezeManifestSHA256"]
    ) is None:
        raise RunnerError("frozen lab freeze-manifest digest is invalid")
    expected_runtime_fields = {
        "python",
        "primaryPlatform",
        "postEvidenceReplication",
        "requirementsLockSHA256",
        "pipBootstrapLockSHA256",
        "status",
        "runtimeManifestSHA256",
    }
    if set(runtime) != expected_runtime_fields or runtime.get("status") != "FROZEN_BOUND":
        raise RunnerError("frozen runtime binding differs")
    if not isinstance(runtime.get("runtimeManifestSHA256"), str) or HEX_64.fullmatch(
        runtime["runtimeManifestSHA256"]
    ) is None:
        raise RunnerError("frozen runtime-manifest digest is invalid")
    if not isinstance(runtime.get("pipBootstrapLockSHA256"), str) or HEX_64.fullmatch(
        runtime["pipBootstrapLockSHA256"]
    ) is None:
        raise RunnerError("frozen pip-bootstrap lock digest is invalid")
    for field in ("transportCABundleSHA256", "offlineTrustBundleSHA256"):
        if not isinstance(beacon.get(field), str) or HEX_64.fullmatch(beacon[field]) is None:
            raise RunnerError(f"frozen NIST binding is absent: {field}")
    release_identities: list[tuple[str, str]] = []
    for field in ("designRelease", "snapshotRelease", "evidenceRelease"):
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
            or HEX_64.fullmatch(release["signingPublicKeySHA256"]) is None
        ):
            raise RunnerError(f"frozen {field} signing identity is absent")
        release_identities.append(
            (release["signingKeyFingerprint"], release["signingPublicKeySHA256"])
        )
    if len(set(release_identities)) != 1:
        raise RunnerError("frozen release plans do not share one signing identity")

    # Every scientific choice must equal the tracked, author-verified draft. Only the
    # lifecycle fields and immutable artifact bindings may change. The signing
    # identity is already preregistered in the tracked draft.
    normalized = copy.deepcopy(design)
    normalized["schemaVersion"] = reference["schemaVersion"]
    normalized["status"] = reference["status"]
    normalized["readyToFreeze"] = reference["readyToFreeze"]
    normalized["freezeBlockers"] = reference["freezeBlockers"]
    normalized["labSource"] = reference["labSource"]
    normalized["runtime"] = reference["runtime"]
    normalized["developmentControls"]["realDataE2EFreezeGate"] = reference[
        "developmentControls"
    ]["realDataE2EFreezeGate"]
    normalized["beacon"]["transportCABundleSHA256"] = reference["beacon"][
        "transportCABundleSHA256"
    ]
    normalized["beacon"]["offlineTrustBundleSHA256"] = reference["beacon"][
        "offlineTrustBundleSHA256"
    ]
    if normalized != reference:
        raise RunnerError("frozen design changed a field outside the allowed freeze bindings")


def validate_frozen_snapshot_bytes(raw: bytes) -> dict[str, Any]:
    snapshot = load_json_strict_bytes(raw, label="frozen snapshot registration")
    validate_snapshot_registration(snapshot, allow_fixture=False)
    _validate_schema(snapshot, "snapshot.schema.json")
    if canonical_json_bytes(snapshot) + b"\n" != raw:
        raise RunnerError("frozen snapshot registration must be canonical JSON plus LF")
    return snapshot


def _git_output(root: Path, arguments: list[str]) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def verify_git_identity(root: Path, *, commit: str, tree: str) -> None:
    if _git_output(root, ["rev-parse", "HEAD"]) != commit:
        raise RunnerError(f"Git commit differs from frozen binding: {root}")
    if _git_output(root, ["rev-parse", "HEAD^{tree}"]) != tree:
        raise RunnerError(f"Git tree differs from frozen binding: {root}")
    status = _git_output(root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise RunnerError(f"Git worktree is not clean: {root}")


def validate_freeze_manifest(
    manifest: Any,
    *,
    design: Mapping[str, Any],
    file_sha256: str,
    runtime_sha256: str,
    asset_sha256: str,
    github_gate_sha256: str,
) -> None:
    if not isinstance(manifest, dict):
        raise RunnerError("freeze manifest must be an object")
    _validate_schema(manifest, "freeze-manifest.schema.json")
    validate_freeze_manifest_contract(manifest)
    verify_content_digest(manifest)
    if manifest.get("schemaVersion") != FREEZE_SCHEMA:
        raise RunnerError("freeze manifest schemaVersion differs")
    if manifest.get("status") != "IMPLEMENTATION_FREEZE_READY_FOR_DESIGN_BINDING":
        raise RunnerError("freeze manifest is not author-verified/frozen")
    if manifest.get("suiteId") != SUITE_ID:
        raise RunnerError("freeze manifest suite differs")
    if file_sha256 != design["labSource"]["freezeManifestSHA256"]:
        raise RunnerError("design binds a different freeze manifest")
    implementation = manifest.get("implementation")
    codec = manifest.get("codec")
    artifacts = manifest.get("artifacts")
    if not all(isinstance(item, dict) for item in (implementation, codec, artifacts)):
        raise RunnerError("freeze manifest source/artifact bindings are absent")
    expected_sources = {
        "implementation": (
            implementation,
            design["labSource"]["repository"],
            design["labSource"]["commit"],
            design["labSource"]["tree"],
        ),
        "codec": (
            codec,
            design["codecSource"]["repository"],
            design["codecSource"]["commit"],
            design["codecSource"]["tree"],
        ),
    }
    for label, (source, repository, commit, tree) in expected_sources.items():
        if source != {"repository": repository, "commit": commit, "tree": tree}:
            raise RunnerError(f"freeze manifest {label} identity differs")
    expected_artifacts = {
        "runtimeManifestSHA256": runtime_sha256,
        "fullAssetReceiptSHA256": asset_sha256,
        "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
        "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
        "githubGateReceiptSHA256": github_gate_sha256,
    }
    for field, value in expected_artifacts.items():
        if artifacts.get(field) != value:
            raise RunnerError(f"freeze manifest binding differs: {field}")
    author_verification = manifest.get("authorVerification")
    ci = manifest.get("continuousIntegration")
    if (
        not isinstance(author_verification, dict)
        or author_verification.get("mode") != "AUTHOR_SELF_VERIFICATION"
        or author_verification.get("authorName") != "Ivan Tyshchenko"
        or author_verification.get("authorORCID")
        != "https://orcid.org/0009-0000-7935-6090"
        or author_verification.get("authorGitHubLogin") != "ALLPROTO"
        or author_verification.get("implementationCommit")
        != design["labSource"]["commit"]
        or author_verification.get("independentHumanReviewRequired") is not False
        or author_verification.get("independentHumanReviewPerformed") is not False
        or "not independent human review"
        not in author_verification.get("declaration", "")
        or author_verification.get("claimBoundary")
        != (
            "AUTHOR_SELF_VERIFICATION_ONLY;"
            "NO_INDEPENDENT_HUMAN_REVIEW;"
            "NO_PEER_REVIEW;"
            "NO_OPERATOR_BLINDNESS;"
            "NO_INDEPENDENT_REPLICATION"
        )
    ):
        raise RunnerError(
            "freeze manifest lacks the exact author self-verification disclosure"
        )
    if (
        not isinstance(ci, dict)
        or ci.get("conclusion") != "success"
        or ci.get("headSHA") != design["labSource"]["commit"]
        or ci.get("workflowName")
        != design["continuousIntegration"]["workflowName"]
        or ci.get("workflowPath")
        != design["continuousIntegration"]["workflowPath"]
        or ci.get("allJobsCompletedSuccess") is not True
        or ci.get("zeroSkippedOrCancelledJobs") is not True
        or not ci.get("runURL")
    ):
        raise RunnerError("freeze manifest lacks green CI on the exact lab commit")


def _require_design_publication_source(
    publication: Any, design: Mapping[str, Any], *, private: bool = False
) -> None:
    """Require the design tag to target the author-verified implementation tree."""

    _require_publication_source(publication, design, kind="design", private=private)


def _require_publication_source(
    publication: Any,
    design: Mapping[str, Any],
    *,
    kind: str,
    private: bool = False,
) -> None:
    try:
        require_frozen_lab_publication_source(publication, design, kind=kind)
    except PublicationError as error:
        prefix = "private " if private else ""
        raise RunnerError(f"{prefix}{error}") from error


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RunnerError("private snapshot path is not canonical")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or any(part in ("", ".") for part in relative.parts)
        or str(relative) != value
    ):
        raise RunnerError("private snapshot path escapes its root")
    return relative


def _safe_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RunnerError("private snapshot parent contains a symlink/non-directory")
    return current


def _copy_verified_file(
    source: Path,
    root: Path,
    relative_text: str,
    *,
    expected_bytes: int | None = None,
    expected_sha256: str | None = None,
    role: str,
) -> dict[str, Any]:
    relative = _safe_relative(relative_text)
    parent = _safe_parent(root, relative.parent)
    destination = parent / relative.name
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source, source_flags)
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RunnerError(f"private snapshot source is not regular: {source}")
        if expected_bytes is not None and before.st_size != expected_bytes:
            raise RunnerError(f"private snapshot source byte count differs: {source}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        destination_descriptor = os.open(destination, flags, 0o400)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise RunnerError("short write while sealing private snapshot")
                view = view[written:]
        after = os.fstat(source_descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if identity(before) != identity(after) or total != before.st_size:
            raise RunnerError(f"source changed while sealing: {source}")
        observed = digest.hexdigest()
        if expected_sha256 is not None and observed != expected_sha256:
            raise RunnerError(f"private snapshot source SHA-256 differs: {source}")
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    return {
        "path": relative_text,
        "bytes": total,
        "sha256": observed,
        "role": role,
    }


def _write_private_bytes(
    root: Path, relative_text: str, value: bytes, *, role: str
) -> dict[str, Any]:
    relative = _safe_relative(relative_text)
    parent = _safe_parent(root, relative.parent)
    destination = parent / relative.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o400)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerError("short write while sealing metadata")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "path": relative_text,
        "bytes": len(value),
        "sha256": sha256_bytes(value),
        "role": role,
    }


def _write_sealed_git_source(
    root: Path,
    *,
    seal: GitSourceSeal,
    prefix: str,
    source_role: str,
    manifest_role: str,
) -> tuple[list[dict[str, Any]], str]:
    """Export one exact commit from verified Git objects, never the worktree."""

    manifest_raw = source_manifest_bytes(build_source_manifest(seal))
    manifest_relative = f"bindings/{prefix}-source-manifest.json"
    entries = [
        _write_private_bytes(
            root,
            manifest_relative,
            manifest_raw,
            role=manifest_role,
        )
    ]
    for source_file in seal.files:
        relative = f"{prefix}/{source_file.path}"
        entry = _write_private_bytes(
            root,
            relative,
            source_file.data,
            role=source_role,
        )
        destination = root.joinpath(*PurePosixPath(relative).parts)
        os.chmod(destination, 0o500 if source_file.mode == "100755" else 0o400)
        descriptor = os.open(
            destination,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        entries.append(entry)
    return entries, sha256_bytes(manifest_raw)


def _load_owned_tokenizers(
    asset_root: Path, asset_manifest: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        from tokenizers import Tokenizer
    except ImportError as error:
        raise RunnerError("locked runtime lacks tokenizers") from error
    result: dict[str, Any] = {}
    for model_key in MODELS:
        specification = asset_manifest["models"][model_key]["files"]["tokenizer.json"]
        verify_file_beneath(
            asset_root,
            Path(model_key) / "tokenizer.json",
            specification,
        )
        raw = (asset_root / model_key / "tokenizer.json").read_bytes()
        result[model_key] = Tokenizer.from_str(raw.decode("utf-8", errors="strict"))
    return result


def verify_runtime_live(runtime_manifest: Mapping[str, Any], runtime_root: Path) -> None:
    verify_content_digest(dict(runtime_manifest))
    if runtime_manifest.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-runtime-manifest-v1":
        raise RunnerError("runtime manifest schemaVersion differs")
    if runtime_manifest.get("status") != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY":
        raise RunnerError("runtime manifest is incomplete")
    manifest_host = runtime_manifest.get("host")
    if (
        not isinstance(manifest_host, dict)
        or manifest_host.get("system") != "Darwin"
        or manifest_host.get("machine") != "arm64"
    ):
        raise RunnerError("runtime manifest host is not Darwin arm64")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RunnerError("active runtime host is not Darwin arm64")
    runtime_root = runtime_root.resolve(strict=True)
    if Path(sys.prefix).resolve(strict=True) != runtime_root:
        raise RunnerError("active interpreter is not the frozen runtime root")
    if tuple(sys.version_info[:3]) != (3, 12, 10):
        raise RunnerError("active interpreter is not Python 3.12.10")
    base_root = Path(sys.base_prefix).resolve(strict=True)
    base_is_distinct = base_root != runtime_root
    if runtime_manifest.get("basePythonDistinctFromRuntime") is not base_is_distinct:
        raise RunnerError("runtime base-Python boundary differs")
    expected_runtime = runtime_manifest.get("runtimeTree")
    if not isinstance(expected_runtime, dict):
        raise RunnerError("runtime tree commitment is absent")
    expected_base = runtime_manifest.get("basePythonTree")
    if not isinstance(expected_base, dict):
        raise RunnerError("base Python tree commitment is absent")
    if base_is_distinct:
        observed_runtime = scan_tree(
            runtime_root, external_roots={"base-python-root": base_root}
        )
        observed_base = scan_tree(base_root)
    else:
        observed_runtime = scan_tree(runtime_root)
        observed_base = observed_runtime
    for field in ("treeSHA256", "entryCount", "regularFileBytes"):
        if observed_runtime.get(field) != expected_runtime.get(field):
            raise RunnerError(f"live runtime tree differs: {field}")
        if observed_base.get(field) != expected_base.get(field):
            raise RunnerError(f"live base Python tree differs: {field}")
    executable = digest_regular_file(Path(sys.executable).resolve(strict=True))
    expected_executable = runtime_manifest.get("python", {}).get("executable")
    if not isinstance(expected_executable, dict):
        raise RunnerError("runtime executable commitment is absent")
    for field in ("bytes", "sha256"):
        if executable.get(field) != expected_executable.get(field):
            raise RunnerError(f"runtime executable differs: {field}")


def scientific_subprocess_environment(
    execution: Mapping[str, Any],
) -> dict[str, str]:
    """Return the complete, secret-free environment inherited by scientific children."""

    intra_threads = execution.get("intraOpThreads")
    if type(intra_threads) is not int or intra_threads < 1:
        raise RunnerError("frozen intra-op thread count is invalid")
    threads = str(intra_threads)
    return {
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_OFFLINE": "1",
        "LANG": "C",
        "LC_ALL": "C",
        "MKL_NUM_THREADS": threads,
        "NO_PROXY": "*",
        "NUMEXPR_NUM_THREADS": threads,
        "OMP_NUM_THREADS": threads,
        "PATH": SCIENTIFIC_PATH,
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TOKENIZERS_PARALLELISM": "false",
        "TRANSFORMERS_OFFLINE": "1",
        "VECLIB_MAXIMUM_THREADS": threads,
        "no_proxy": "*",
    }


def _scientific_python_command(
    executable: str | Path, *arguments: str
) -> list[str]:
    """Construct a child command without destroying virtualenv semantics.

    A venv launcher is normally a symlink to the base interpreter.  Executing
    the resolved target bypasses the launcher's adjacent ``pyvenv.cfg`` and
    silently drops the locked site-packages.  Preserve the exact active
    launcher's absolute spelling, while still verifying that it is the one
    executable inside the active, non-base runtime and resolves to a regular
    executable file.
    """

    try:
        raw = os.fspath(executable)
    except TypeError as error:
        raise RunnerError("scientific Python launcher path is invalid") from error
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or not os.path.isabs(raw)
        or raw != os.path.abspath(raw)
    ):
        raise RunnerError(
            "scientific Python launcher must be a normalized absolute path"
        )
    launcher = Path(os.path.abspath(raw))
    active_launcher = Path(os.path.abspath(sys.executable))
    runtime_root = Path(os.path.abspath(sys.prefix))
    base_root = Path(os.path.abspath(sys.base_prefix))
    if runtime_root == base_root:
        raise RunnerError("scientific Python requires an active virtual environment")
    if (
        launcher != active_launcher
        or launcher != runtime_root / "bin" / "python"
    ):
        raise RunnerError(
            "scientific Python launcher differs from the active locked runtime"
        )
    try:
        current = Path(launcher.anchor)
        for component in launcher.parts[1:-1]:
            current /= component
            parent_metadata = os.lstat(current)
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise RunnerError(
                    "scientific Python launcher has a symlink/non-directory parent"
                )
        launcher_metadata = os.lstat(launcher)
        resolved = launcher.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except RunnerError:
        raise
    except OSError as error:
        raise RunnerError("scientific Python launcher cannot be verified") from error
    if (
        not (
            stat.S_ISREG(launcher_metadata.st_mode)
            or stat.S_ISLNK(launcher_metadata.st_mode)
        )
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or not os.access(resolved, os.X_OK)
    ):
        raise RunnerError("scientific Python launcher is not executable")
    if any(
        not isinstance(argument, str) or "\x00" in argument for argument in arguments
    ):
        raise RunnerError("scientific Python argument is invalid")
    return [str(launcher), *SCIENTIFIC_PYTHON_FLAGS, *arguments]


def _expected_scientific_runtime_import_versions() -> dict[str, str]:
    versions = dict(SCIENTIFIC_RUNTIME_IMPORT_VERSIONS)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        versions["torch"] = "2.13.0"
    elif platform.system() == "Linux" and platform.machine() == "x86_64":
        versions["torch"] = "2.13.0+cpu"
    else:
        raise RunnerError("scientific runtime import probe is on an unsupported host")
    return versions


def verify_scientific_runtime_imports_subprocess(
    executable: str | Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    """Prove the networkless child can import every inference dependency."""

    if environment.get("PYTHONHASHSEED") != "0" or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise RunnerError("scientific runtime import environment is invalid")

    probe = (
        "import importlib.metadata,json,sys\n"
        "import jsonschema,numpy,pyarrow,safetensors,tokenizers,torch,transformers\n"
        "names=('jsonschema','numpy','pyarrow','safetensors','tokenizers','torch','transformers')\n"
        "value={'basePrefix':sys.base_prefix,'executable':sys.executable,"
        "'prefix':sys.prefix,'venvActive':sys.prefix!=sys.base_prefix,"
        "'versions':{name:importlib.metadata.version(name) for name in names}}\n"
        "sys.stdout.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n')\n"
    )
    launcher = _scientific_python_command(executable)[0]
    command = _scientific_python_command(executable, "-c", probe)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        command = _networkless_macos_command(command)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env=dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError("scientific runtime import subprocess failed") from error
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 4096
    ):
        raise RunnerError("scientific runtime dependency imports failed")
    try:
        observed = load_json_strict_bytes(
            completed.stdout, label="scientific runtime import subprocess"
        )
    except ValueError as error:
        raise RunnerError("scientific runtime import output is invalid") from error
    if canonical_json_bytes(observed) + b"\n" != completed.stdout:
        raise RunnerError("scientific runtime import output is not canonical")
    expected = {
        "basePrefix": os.path.abspath(sys.base_prefix),
        "executable": launcher,
        "prefix": os.path.abspath(sys.prefix),
        "venvActive": True,
        "versions": _expected_scientific_runtime_import_versions(),
    }
    if observed != expected:
        raise RunnerError("scientific runtime dependency identity differs")
    return observed


def _scientific_python_state() -> dict[str, Any]:
    return {
        "dontWriteBytecode": bool(sys.dont_write_bytecode),
        "hashAlgorithm": sys.hash_info.algorithm,
        "hashBits": sys.hash_info.width,
        "hashRandomization": sys.flags.hash_randomization,
        "hashValue": hash(SCIENTIFIC_HASH_INPUT),
        "ignoreEnvironment": sys.flags.ignore_environment,
        "noUserSite": sys.flags.no_user_site,
        "pythonVersion": ".".join(str(value) for value in sys.version_info[:3]),
        "safePath": bool(getattr(sys.flags, "safe_path", False)),
        "seedBits": sys.hash_info.seed_bits,
    }


def _expected_scientific_python_state() -> dict[str, Any]:
    return {
        "dontWriteBytecode": True,
        "hashAlgorithm": "siphash13",
        "hashBits": 64,
        "hashRandomization": 0,
        "hashValue": SCIENTIFIC_HASH_KNOWN_ANSWER,
        "ignoreEnvironment": 0,
        "noUserSite": 1,
        "pythonVersion": "3.12.10",
        "safePath": True,
        "seedBits": 128,
    }


def verify_active_scientific_python_startup() -> None:
    """Fail unless this supervisor itself has the registered startup state."""

    if _scientific_python_state() != _expected_scientific_python_state():
        raise RunnerError(
            "active scientific Python startup differs from the registered state"
        )


def verify_scientific_python_subprocess(
    executable: str | Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    """Run a known-answer child proving that its closed environment is effective."""

    if environment.get("PYTHONHASHSEED") != "0":
        raise RunnerError("scientific child PYTHONHASHSEED is not fixed to zero")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in environment.items()
    ):
        raise RunnerError("scientific child environment contains a non-string value")
    probe = (
        "import json,sys\n"
        "value={"
        "'dontWriteBytecode':bool(sys.dont_write_bytecode),"
        "'hashAlgorithm':sys.hash_info.algorithm,"
        "'hashBits':sys.hash_info.width,"
        "'hashRandomization':sys.flags.hash_randomization,"
        f"'hashValue':hash({SCIENTIFIC_HASH_INPUT!r}),"
        "'ignoreEnvironment':sys.flags.ignore_environment,"
        "'noUserSite':sys.flags.no_user_site,"
        "'pythonVersion':'.'.join(str(v) for v in sys.version_info[:3]),"
        "'safePath':bool(getattr(sys.flags,'safe_path',False)),"
        "'seedBits':sys.hash_info.seed_bits}\n"
        "sys.stdout.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\\n')\n"
    )
    try:
        completed = subprocess.run(
            _scientific_python_command(executable, "-c", probe),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env=dict(environment),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError("scientific Python known-answer subprocess failed") from error
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > 4096
    ):
        raise RunnerError(
            "scientific Python known-answer subprocess produced invalid output"
        )
    try:
        observed = load_json_strict_bytes(
            completed.stdout, label="scientific Python known-answer subprocess"
        )
    except ValueError as error:
        raise RunnerError("scientific Python known-answer output is invalid") from error
    if canonical_json_bytes(observed) + b"\n" != completed.stdout:
        raise RunnerError("scientific Python known-answer output is not canonical")
    if observed != _expected_scientific_python_state():
        raise RunnerError("scientific Python known-answer differs")
    verify_scientific_runtime_imports_subprocess(executable, environment)
    return observed


def _macos_command_value(command: list[str], *, label: str) -> str:
    """Read one bounded macOS platform value without consulting shell or user env."""

    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            env={"PATH": SCIENTIFIC_PATH, "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError(f"cannot inspect {label}") from error
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise RunnerError(f"cannot inspect {label}")
    try:
        value = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RunnerError(f"invalid UTF-8 while inspecting {label}") from error
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RunnerError(f"invalid value while inspecting {label}")
    return value


def verify_primary_host_safety(
    design: Mapping[str, Any], *, output_parent: Path
) -> dict[str, Any]:
    """Enforce the frozen Mac/power/memory/disk gate immediately pre-marker."""

    safety = platform_safety()
    execution = design["execution"]
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RunnerError("primary scientific one-shot requires macOS arm64")
    if execution["acPowerRequired"] is True and safety.get("acPower") is not True:
        raise RunnerError("primary Mac is not connected to AC power")
    free_percent = safety.get("freeMemoryPercent")
    if (
        type(free_percent) is not int
        or free_percent < execution["minimumFreeMemoryPercent"]
    ):
        raise RunnerError(
            "free memory is below the frozen pre-marker floor: "
            f"{free_percent!r}% < {execution['minimumFreeMemoryPercent']}%"
        )
    candidate = output_parent
    while not candidate.exists():
        if candidate == candidate.parent:
            raise RunnerError("cannot resolve output filesystem for disk preflight")
        candidate = candidate.parent
    free_disk = shutil.disk_usage(candidate).free
    if free_disk < execution["minimumFreeDiskBytes"]:
        raise RunnerError(
            "free disk is below the frozen pre-marker floor: "
            f"{free_disk} < {execution['minimumFreeDiskBytes']}"
        )
    logical_cpu_count = os.cpu_count()
    if type(logical_cpu_count) is not int or logical_cpu_count < 1:
        raise RunnerError("logical CPU count is unavailable")
    physical_memory_text = _macos_command_value(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"], label="physical memory"
    )
    try:
        physical_memory_bytes = int(physical_memory_text, 10)
    except ValueError as error:
        raise RunnerError("physical memory is not an integer") from error
    if physical_memory_bytes < 1:
        raise RunnerError("physical memory is invalid")
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "osProductVersion": _macos_command_value(
            ["/usr/bin/sw_vers", "-productVersion"], label="macOS product version"
        ),
        "osBuildVersion": _macos_command_value(
            ["/usr/bin/sw_vers", "-buildVersion"], label="macOS build version"
        ),
        "kernelRelease": platform.release(),
        "kernelVersion": platform.version(),
        "cpuBrand": _macos_command_value(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            label="CPU brand",
        ),
        "logicalCPUCount": logical_cpu_count,
        "physicalMemoryBytes": physical_memory_bytes,
        "pythonVersion": platform.python_version(),
        "pythonExecutableSHA256": sha256_file(executable),
        "effectiveExecutionEnvironment": scientific_subprocess_environment(execution),
        "acPower": safety["acPower"],
        "freeMemoryPercent": free_percent,
        "freeDiskBytes": free_disk,
    }


def _trust_commitment_paths(trust_manifest: Mapping[str, Any]) -> list[str]:
    result: set[str] = set()
    certificates = trust_manifest.get("certificates")
    if not isinstance(certificates, dict):
        raise RunnerError("NIST trust manifest certificate map is absent")
    for specification in certificates.values():
        if not isinstance(specification, dict):
            raise RunnerError("NIST trust certificate entry is invalid")
        values = [specification.get("pem"), *(specification.get("chain") or [])]
        for commitment in values:
            if not isinstance(commitment, dict):
                raise RunnerError("NIST trust file commitment is invalid")
            result.add(str(_safe_relative(commitment.get("relativePath"))))
    return sorted(result)


def prepare_private_snapshot(
    *,
    design_path: Path,
    snapshot_registration_path: Path,
    corpus_root: Path,
    asset_manifest_path: Path,
    asset_receipt_path: Path,
    asset_root: Path,
    runtime_manifest_path: Path,
    runtime_root: Path,
    freeze_manifest_path: Path,
    github_gate_receipt_path: Path,
    development_control_report_path: Path,
    development_control_artifact_root: Path,
    development_control_archive_receipt_path: Path,
    development_control_archive_asset_root: Path,
    sbom_path: Path,
    design_sha256_manifest_path: Path,
    design_publication_receipt_path: Path,
    design_release_asset_root: Path,
    snapshot_publication_receipt_path: Path,
    snapshot_release_asset_root: Path,
    signing_public_key_path: Path,
    nist_trust_manifest_path: Path,
    ca_bundle_path: Path,
    cosign_path: Path,
    codec_root: Path,
    lab_root: Path,
    destination: Path,
) -> dict[str, Any]:
    """Materialize all future readable bytes without consuming the one-shot."""

    cosign_variant = COSIGN_BINARY_VARIANTS.get(
        (platform.system(), platform.machine())
    )
    if cosign_variant is None:
        raise RunnerError("pinned Cosign platform is unsupported")
    cryptographic_attestation_verifier = (
        PinnedCosignReleaseAttestationVerifier(cosign_path)
    )
    design = load_json_strict(design_path)
    validate_frozen_design(design)
    verify_git_identity(
        lab_root,
        commit=design["labSource"]["commit"],
        tree=design["labSource"]["tree"],
    )
    verify_git_identity(
        codec_root,
        commit=design["codecSource"]["commit"],
        tree=design["codecSource"]["tree"],
    )
    verify_codec_source(codec_root, design)
    # Worktree cleanliness is a preflight signal only.  Normative source bytes
    # are read from the two exact Git object graphs so a worktree mutation
    # between preflight and copy cannot enter the private snapshot.
    lab_source_seal = seal_git_source(
        lab_root,
        expected_commit=design["labSource"]["commit"],
        expected_tree=design["labSource"]["tree"],
    )
    verify_registered_ci_workflow_seal(design, lab_source_seal)
    codec_source_seal = seal_git_source(
        codec_root,
        expected_commit=design["codecSource"]["commit"],
        expected_tree=design["codecSource"]["tree"],
    )

    snapshot_raw = snapshot_registration_path.read_bytes()
    snapshot = validate_frozen_snapshot_bytes(snapshot_raw)
    design_release = design["designRelease"]
    snapshot_release = design["snapshotRelease"]
    if snapshot["snapshotReleasePlan"] != {
        key: snapshot_release[key]
        for key in (
            "tag",
            "publishNoLaterThan",
            "serverTimestampRequired",
            "immutableReleaseRequired",
            "signedAnnotatedTagRequired",
        )
    }:
        raise RunnerError("snapshot release plan differs from the frozen design")
    asset_manifest_raw = asset_manifest_path.read_bytes()
    asset_manifest = load_json_strict_bytes(
        asset_manifest_raw, label="model asset source manifest"
    )
    validate_model_asset_manifest(asset_manifest, design)
    asset_source_manifest_sha = sha256_bytes(asset_manifest_raw)
    if snapshot["modelAssetSourceManifestSHA256"] != asset_source_manifest_sha:
        raise RunnerError("snapshot registration binds a different asset source manifest")
    local_assets = verify_local_assets(asset_root, asset_manifest)
    receipt_verification = verify_asset_receipt(
        asset_receipt_path,
        manifest_path=asset_manifest_path,
        manifest=asset_manifest,
        local_assets=local_assets,
    )
    if receipt_verification.get("verified") is not True:
        raise RunnerError("full asset receipt did not verify")
    asset_receipt = load_json_strict(asset_receipt_path)
    verify_content_digest(asset_receipt)
    if asset_receipt.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED":
        raise RunnerError("asset receipt does not prove a full local snapshot")
    asset_receipt_sha = sha256_file(asset_receipt_path)
    if snapshot["fullAssetReceiptSHA256"] != asset_receipt_sha:
        raise RunnerError("snapshot registration binds a different full asset receipt")
    for model_key, model in asset_receipt.get("models", {}).items():
        if model_key not in MODELS:
            raise RunnerError("asset receipt contains an unregistered model")
        for filename, specification in model.get("files", {}).items():
            verify_file_beneath(
                asset_root,
                Path(model_key) / filename,
                specification,
            )

    runtime_raw = runtime_manifest_path.read_bytes()
    runtime_manifest = load_json_strict_bytes(runtime_raw, label="runtime manifest")
    verify_runtime_live(runtime_manifest, runtime_root)
    runtime_sha = sha256_bytes(runtime_raw)
    if design["runtime"]["runtimeManifestSHA256"] != runtime_sha:
        raise RunnerError("design binds a different runtime manifest")
    if runtime_manifest["labSource"].get("commit") != design["labSource"]["commit"]:
        raise RunnerError("runtime manifest binds a different lab commit")
    if runtime_manifest["codecSource"].get("commit") != design["codecSource"]["commit"]:
        raise RunnerError("runtime manifest binds a different codec commit")

    tokenizers = _load_owned_tokenizers(asset_root, asset_manifest)
    corpus_verification = verify_corpus_snapshot(corpus_root, tokenizers=tokenizers)
    if corpus_verification.get("readyForFreeze") is not True:
        raise RunnerError("corpus snapshot is not freeze-ready")
    corpus_manifest_path = corpus_root / "corpus-manifest.json"
    corpus_raw = corpus_manifest_path.read_bytes()
    corpus_manifest = load_json_strict_bytes(corpus_raw, label="corpus manifest")
    corpus_sha = sha256_bytes(corpus_raw)
    if snapshot["corpusManifestSHA256"] != corpus_sha:
        raise RunnerError("snapshot registration binds a different corpus manifest")
    for project in PROJECTS:
        commitment = corpus_manifest["projects"][project]["ledger"]
        ledger_path = corpus_root / commitment["relativePath"]
        ledger_raw = ledger_path.read_bytes()
        if (
            len(ledger_raw) != commitment["bytes"]
            or sha256_bytes(ledger_raw) != commitment["sha256"]
            or snapshot["ledgers"][project] != commitment["sha256"]
        ):
            raise RunnerError(f"snapshot ledger binding differs: {project}")

    ca_sha = sha256_file(ca_bundle_path)
    trust_sha = sha256_file(nist_trust_manifest_path)
    if ca_sha != design["beacon"]["transportCABundleSHA256"]:
        raise RunnerError("design binds a different transport CA bundle")
    if trust_sha != design["beacon"]["offlineTrustBundleSHA256"]:
        raise RunnerError("design binds a different NIST trust bundle")
    target_time = datetime.fromtimestamp(TARGET_UNIX_MILLISECONDS / 1000, tz=timezone.utc)
    load_offline_trust_bundle(
        nist_trust_manifest_path,
        expected_time=target_time,
        expected_manifest_sha256=trust_sha,
        expected_root_der_sha256=design["beacon"]["nistTrustRootDERsSHA256"],
        allow_fixture=False,
    )

    freeze_raw = freeze_manifest_path.read_bytes()
    freeze_manifest = load_json_strict_bytes(freeze_raw, label="freeze manifest")
    github_gate_sha = sha256_file(github_gate_receipt_path)
    verify_freeze_artifact_inputs(
        freeze_manifest,
        runtime_manifest_path=runtime_manifest_path,
        asset_receipt_path=asset_receipt_path,
        ca_bundle_path=ca_bundle_path,
        trust_manifest_path=nist_trust_manifest_path,
        github_gate_receipt_path=github_gate_receipt_path,
        development_control_report_path=development_control_report_path,
        development_control_artifact_root=development_control_artifact_root,
        development_control_archive_receipt_path=(
            development_control_archive_receipt_path
        ),
        development_control_archive_asset_root=(
            development_control_archive_asset_root
        ),
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    validate_freeze_manifest(
        freeze_manifest,
        design=design,
        file_sha256=sha256_bytes(freeze_raw),
        runtime_sha256=runtime_sha,
        asset_sha256=asset_receipt_sha,
        github_gate_sha256=github_gate_sha,
    )

    signing_key_fingerprint = design_release["signingKeyFingerprint"]
    signing_public_key_sha256 = design_release["signingPublicKeySHA256"]
    design_publication = verify_publication(
        design_publication_receipt_path,
        design_release_asset_root,
        kind="design",
        tag=design_release["tag"],
        deadline=design_release["publishNoLaterThan"],
        signing_public_key_path=signing_public_key_path,
        signing_key_fingerprint=signing_key_fingerprint,
        signing_public_key_sha256=signing_public_key_sha256,
        expected_role_paths={
            "asset-source-manifest": asset_manifest_path,
            "design-registration": design_path,
            "development-control-report": development_control_report_path,
            "development-control-archive-receipt": (
                development_control_archive_receipt_path
            ),
            "freeze-manifest": freeze_manifest_path,
            "full-asset-receipt": asset_receipt_path,
            "github-gate-receipt": github_gate_receipt_path,
            "linux-ci-artifact": design_release_asset_root
            / "linux-ci-artifact.zip",
            "macos-arm64-ci-artifact": design_release_asset_root
            / "macos-arm64-ci-artifact.zip",
            "runtime-manifest": runtime_manifest_path,
            "sbom": sbom_path,
            "sha256-manifest": design_sha256_manifest_path,
        },
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    _require_design_publication_source(design_publication, design)
    try:
        verify_design_release_package(
            design_release_asset_root,
            signing_public_key_path=signing_public_key_path,
        )
    except DesignReleaseError as error:
        raise RunnerError(f"design release package failed: {error}") from error
    if snapshot["designPublicationReceiptSHA256"] != design_publication.receipt_sha256:
        raise RunnerError("snapshot registration binds another design publication receipt")
    snapshot_publication = verify_publication(
        snapshot_publication_receipt_path,
        snapshot_release_asset_root,
        kind="snapshot",
        tag=snapshot_release["tag"],
        deadline=snapshot_release["publishNoLaterThan"],
        signing_public_key_path=signing_public_key_path,
        signing_key_fingerprint=snapshot_release["signingKeyFingerprint"],
        signing_public_key_sha256=snapshot_release["signingPublicKeySHA256"],
        expected_role_paths={
            "attribution": snapshot_release_asset_root / "attribution.json",
            "corpus-bytes": snapshot_release_asset_root / "corpus-bytes.zip",
            "design-publication-receipt": design_publication_receipt_path,
            "sha256-manifest": snapshot_release_asset_root
            / "sha256-manifest.json",
            "snapshot-registration": snapshot_registration_path,
        },
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    _require_publication_source(snapshot_publication, design, kind="snapshot")
    try:
        verify_snapshot_release(
            corpus_root=corpus_root,
            snapshot_registration_path=snapshot_registration_path,
            design_publication_receipt_path=design_publication_receipt_path,
            asset_root=snapshot_release_asset_root,
        )
    except SnapshotReleaseError as error:
        raise RunnerError(f"snapshot release package failed: {error}") from error

    if destination.exists() or destination.is_symlink():
        raise RunnerError("private snapshot destination must not already exist")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.partial-", dir=destination.parent
        )
    )
    entries: list[dict[str, Any]] = []
    try:
        metadata_sources = (
            (design_path, "bindings/design.json", "frozen-design"),
            (
                snapshot_registration_path,
                "bindings/snapshot-registration.json",
                "frozen-snapshot-registration",
            ),
            (asset_manifest_path, "bindings/model-assets-source.json", "asset-source-manifest"),
            (asset_receipt_path, "bindings/asset-receipt.json", "full-asset-manifest"),
            (runtime_manifest_path, "bindings/runtime-manifest.json", "runtime-manifest"),
            (freeze_manifest_path, "bindings/freeze-manifest.json", "freeze-manifest"),
            (
                github_gate_receipt_path,
                "bindings/github-gate-receipt.json",
                "github-gate-receipt",
            ),
            (sbom_path, "bindings/sbom.cdx.json", "design-release-asset"),
            (
                design_sha256_manifest_path,
                "bindings/design-release-sha256-manifest.json",
                "design-release-asset",
            ),
            (
                design_publication_receipt_path,
                "publication/design-receipt.json",
                "design-publication-receipt",
            ),
            (
                snapshot_publication_receipt_path,
                "publication/snapshot-receipt.json",
                "snapshot-publication-receipt",
            ),
            (
                signing_public_key_path,
                "publication/signing-key.pub",
                "release-signing-public-key",
            ),
            (corpus_manifest_path, "corpus/corpus-manifest.json", "corpus-manifest"),
            (ca_bundle_path, "nist/transport-ca.pem", "transport-ca-bundle"),
            (nist_trust_manifest_path, "nist/trust/manifest.json", "nist-trust-manifest"),
        )
        for source, relative, role in metadata_sources:
            entries.append(_copy_verified_file(source, temporary, relative, role=role))

        entries.append(
            _copy_verified_file(
                development_control_report_path,
                temporary,
                "development/report.json",
                expected_sha256=freeze_manifest["artifacts"][
                    "developmentControlReportSHA256"
                ],
                role="development-control-report",
            )
        )
        entries.append(
            _copy_verified_file(
                development_control_archive_receipt_path,
                temporary,
                "development/archive/receipt.json",
                expected_sha256=freeze_manifest["artifacts"][
                    "developmentControlArchiveReceiptSHA256"
                ],
                role="development-control-archive-receipt",
            )
        )

        entries.append(
            _copy_verified_file(
                cosign_path,
                temporary,
                "tools/cosign",
                expected_bytes=int(cosign_variant["bytes"]),
                expected_sha256=str(cosign_variant["sha256"]),
                role="pinned-cosign-binary",
            )
        )

        development_report = load_json_strict(development_control_report_path)
        development_inventory = development_report.get("artifactInventory")
        if not isinstance(development_inventory, list) or not development_inventory:
            raise RunnerError("development-control artifact inventory is absent")
        for commitment in development_inventory:
            if not isinstance(commitment, dict):
                raise RunnerError("development-control artifact commitment is invalid")
            relative = _safe_relative(commitment.get("path"))
            expected_bytes = commitment.get("bytes")
            expected_sha256 = commitment.get("sha256")
            if (
                type(expected_bytes) is not int
                or expected_bytes < 1
                or not isinstance(expected_sha256, str)
                or HEX_64.fullmatch(expected_sha256) is None
            ):
                raise RunnerError("development-control artifact commitment differs")
            entries.append(
                _copy_verified_file(
                    development_control_artifact_root.joinpath(*relative.parts),
                    temporary,
                    "development/artifacts/" + relative.as_posix(),
                    expected_bytes=expected_bytes,
                    expected_sha256=expected_sha256,
                    role="development-control-artifact",
                )
            )

        development_archive_receipt = load_json_strict(
            development_control_archive_receipt_path
        )
        development_archive_assets = development_archive_receipt.get(
            "requiredAssets"
        )
        if (
            not isinstance(development_archive_assets, list)
            or not development_archive_assets
        ):
            raise RunnerError("development-control archive assets are absent")
        for commitment in development_archive_assets:
            if not isinstance(commitment, dict):
                raise RunnerError("development archive asset commitment is invalid")
            name = _safe_relative(commitment.get("name"))
            if len(name.parts) != 1:
                raise RunnerError("development archive asset name is not flat")
            expected_bytes = commitment.get("bytes")
            expected_sha256 = commitment.get("sha256")
            if (
                type(expected_bytes) is not int
                or expected_bytes < 1
                or not isinstance(expected_sha256, str)
                or HEX_64.fullmatch(expected_sha256) is None
            ):
                raise RunnerError("development archive asset commitment differs")
            entries.append(
                _copy_verified_file(
                    development_control_archive_asset_root / name,
                    temporary,
                    "development/archive/assets/" + name.as_posix(),
                    expected_bytes=expected_bytes,
                    expected_sha256=expected_sha256,
                    role="development-control-archive-asset",
                )
            )

        for release_kind, receipt_path, release_root, role in (
            (
                "design",
                design_publication_receipt_path,
                design_release_asset_root,
                "design-release-asset",
            ),
            (
                "snapshot",
                snapshot_publication_receipt_path,
                snapshot_release_asset_root,
                "snapshot-release-asset",
            ),
        ):
            receipt_document = load_json_strict(receipt_path)
            for asset in receipt_document["requiredAssets"]:
                entries.append(
                    _copy_verified_file(
                        release_root / asset["name"],
                        temporary,
                        f"publication/{release_kind}-assets/{asset['name']}",
                        expected_bytes=asset["bytes"],
                        expected_sha256=asset["sha256"],
                        role=role,
                    )
                )

        trust_root = nist_trust_manifest_path.parent
        trust_manifest = load_json_strict(nist_trust_manifest_path)
        for relative in _trust_commitment_paths(trust_manifest):
            entries.append(
                _copy_verified_file(
                    trust_root.joinpath(*PurePosixPath(relative).parts),
                    temporary,
                    "nist/trust/" + relative,
                    role="nist-certificate-chain",
                )
            )

        for model_key in MODELS:
            receipt_model = asset_receipt["models"][model_key]
            for filename, specification in sorted(receipt_model["files"].items()):
                entries.append(
                    _copy_verified_file(
                        asset_root / model_key / filename,
                        temporary,
                        f"models/{model_key}/{filename}",
                        expected_bytes=specification["bytes"],
                        expected_sha256=specification["sha256"],
                        role="model-asset",
                    )
                )

        for project in PROJECTS:
            project_entry = corpus_manifest["projects"][project]
            ledger_commitment = project_entry["ledger"]
            entries.append(
                _copy_verified_file(
                    corpus_root / ledger_commitment["relativePath"],
                    temporary,
                    f"corpus/ledgers/{project}.json",
                    expected_bytes=ledger_commitment["bytes"],
                    expected_sha256=ledger_commitment["sha256"],
                    role="eligible-ledger",
                )
            )
            eligible = [
                item
                for item in project_entry["inventory"]
                if item.get("eligible") is True
            ]
            for item in eligible:
                record = item["record"]
                # This call independently verifies the record↔manifest identity.
                observed = load_record_bytes(
                    corpus_manifest, project, item["revid"], corpus_root
                )
                if (
                    len(observed) != record["bytes"]
                    or sha256_bytes(observed) != record["sha256"]
                ):
                    raise RunnerError("eligible corpus record commitment differs")
                entries.append(
                    _copy_verified_file(
                        corpus_root / record["relativePath"],
                        temporary,
                        f"records/{project}/{item['revid']}.bin",
                        expected_bytes=record["bytes"],
                        expected_sha256=record["sha256"],
                        role="eligible-corpus-record",
                    )
                )

        lab_entries, lab_source_manifest_sha = _write_sealed_git_source(
            temporary,
            seal=lab_source_seal,
            prefix="lab",
            source_role="lab-source",
            manifest_role="lab-source-manifest",
        )
        entries.extend(lab_entries)
        codec_entries, codec_source_manifest_sha = _write_sealed_git_source(
            temporary,
            seal=codec_source_seal,
            prefix="codec",
            source_role="codec-source",
            manifest_role="codec-source-manifest",
        )
        entries.extend(codec_entries)

        entries.sort(key=lambda item: os.fsencode(item["path"]))
        if len({item["path"] for item in entries}) != len(entries):
            raise RunnerError("private snapshot contains duplicate target paths")
        created = utc_seconds(utc_now())
        manifest: dict[str, Any] = {
            "schemaVersion": PRIVATE_SCHEMA,
            "suiteId": SUITE_ID,
            "status": "SEALED_BEFORE_ATTEMPT",
            "createdAt": created,
            "countsTowardScientificVerdict": False,
            "designSHA256": sha256_file(design_path),
            "snapshotRegistrationSHA256": sha256_bytes(snapshot_raw),
            "designPublicationReceiptSHA256": design_publication.receipt_sha256,
            "snapshotPublicationReceiptSHA256": snapshot_publication.receipt_sha256,
            "signingPublicKeySHA256": signing_public_key_sha256,
            "runtimeManifestSHA256": runtime_sha,
            "modelAssetSourceManifestSHA256": asset_source_manifest_sha,
            "fullAssetReceiptSHA256": asset_receipt_sha,
            "corpusManifestSHA256": corpus_sha,
            "freezeManifestSHA256": sha256_bytes(freeze_raw),
            "githubGateReceiptSHA256": github_gate_sha,
            "transportCABundleSHA256": ca_sha,
            "offlineTrustBundleSHA256": trust_sha,
            "cosignBinarySHA256": str(cosign_variant["sha256"]),
            "labCommit": design["labSource"]["commit"],
            "labTree": design["labSource"]["tree"],
            "codecCommit": design["codecSource"]["commit"],
            "codecTree": design["codecSource"]["tree"],
            "labSourceManifestSHA256": lab_source_manifest_sha,
            "codecSourceManifestSHA256": codec_source_manifest_sha,
            "files": entries,
        }
        manifest["contentSHA256"] = sha256_bytes(canonical_json_bytes(manifest))
        _validate_schema(manifest, "private-snapshot-manifest.schema.json")
        manifest_raw = canonical_json_bytes(manifest) + b"\n"
        _write_private_bytes(
            temporary,
            "private-snapshot-manifest.json",
            manifest_raw,
            role="private-snapshot-manifest",
        )
        for directory, child_directories, _files in os.walk(temporary, topdown=False):
            for child in child_directories:
                os.chmod(Path(directory) / child, 0o500)
            os.chmod(directory, 0o500)
        os.replace(temporary, destination)
        parent_descriptor = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return {
            "status": "PRIVATE_SNAPSHOT_SEALED",
            "path": str(destination),
            "files": len(entries),
            "bytes": sum(item["bytes"] for item in entries),
            "manifestSHA256": sha256_bytes(manifest_raw),
            "countsTowardScientificVerdict": False,
        }
    except BaseException:
        # The uniquely named partial directory is intentionally retained for
        # forensic diagnosis.  No marker exists, so this is not an attempt.
        raise


def _private_file(root: Path, relative_text: str) -> Path:
    relative = _safe_relative(relative_text)
    current = root
    if root.is_symlink() or not root.is_dir():
        raise RunnerError("private snapshot root is not a real directory")
    for component in relative.parts:
        current = current / component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise RunnerError("private snapshot path contains a symlink")
    if not current.is_file() or current.is_symlink():
        raise RunnerError("private snapshot entry is not a regular file")
    return current


def verify_private_snapshot(root: Path) -> tuple[dict[str, Any], str]:
    manifest_path = _private_file(root, "private-snapshot-manifest.json")
    raw = manifest_path.read_bytes()
    manifest = load_json_strict_bytes(raw, label="private snapshot manifest")
    if canonical_json_bytes(manifest) + b"\n" != raw:
        raise RunnerError("private snapshot manifest is not canonical JSON plus LF")
    if manifest.get("schemaVersion") != PRIVATE_SCHEMA:
        raise RunnerError("private snapshot manifest schemaVersion differs")
    if manifest.get("status") != "SEALED_BEFORE_ATTEMPT":
        raise RunnerError("private snapshot is not sealed")
    _validate_schema(manifest, "private-snapshot-manifest.schema.json")
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
    if set(manifest) != expected_fields:
        raise RunnerError("private snapshot manifest fields differ")
    if (
        manifest.get("suiteId") != SUITE_ID
        or manifest.get("countsTowardScientificVerdict") is not False
    ):
        raise RunnerError("private snapshot scientific boundary differs")
    created_at = manifest.get("createdAt")
    if not isinstance(created_at, str):
        raise RunnerError("private snapshot createdAt is absent")
    try:
        datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise RunnerError("private snapshot createdAt is not UTC seconds") from error
    for field in (
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
        "labSourceManifestSHA256",
        "codecSourceManifestSHA256",
        "contentSHA256",
    ):
        if not isinstance(manifest.get(field), str) or HEX_64.fullmatch(manifest[field]) is None:
            raise RunnerError(f"private snapshot digest is invalid: {field}")
    for field in ("labCommit", "labTree", "codecCommit", "codecTree"):
        if not isinstance(manifest.get(field), str) or HEX_40.fullmatch(manifest[field]) is None:
            raise RunnerError(f"private snapshot Git binding is invalid: {field}")
    verify_content_digest(manifest)
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise RunnerError("private snapshot manifest has no entries")
    observed_paths: set[str] = {"private-snapshot-manifest.json"}
    previous: str | None = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256", "role"}:
            raise RunnerError("private snapshot entry fields differ")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] < 1
            or not isinstance(entry["sha256"], str)
            or HEX_64.fullmatch(entry["sha256"]) is None
            or entry["role"] not in PRIVATE_ROLES
        ):
            raise RunnerError("private snapshot entry commitment is invalid")
        text = entry["path"]
        if previous is not None and text <= previous:
            raise RunnerError("private snapshot paths are not strictly sorted")
        previous = text
        if text in observed_paths:
            raise RunnerError("private snapshot path is duplicated")
        observed_paths.add(text)
        path = _private_file(root, text)
        observed = digest_regular_file(path)
        if observed["bytes"] != entry["bytes"] or observed["sha256"] != entry["sha256"]:
            raise RunnerError(f"private snapshot entry changed: {text}")
    actual_paths: set[str] = set()
    for directory, child_directories, filenames in os.walk(root, followlinks=False):
        for child in child_directories:
            path = Path(directory) / child
            if path.is_symlink():
                raise RunnerError("private snapshot contains a directory symlink")
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                raise RunnerError("private snapshot contains a non-regular file")
            actual_paths.add(path.relative_to(root).as_posix())
    if actual_paths != observed_paths:
        raise RunnerError("private snapshot contains unmanifested or missing files")
    observed_roles = {entry["role"] for entry in entries}
    if observed_roles != PRIVATE_ROLES:
        raise RunnerError("private snapshot does not bind every required input class")
    entry_by_path = {entry["path"]: entry for entry in entries}
    cosign_entry = entry_by_path.get("tools/cosign")
    if (
        cosign_entry is None
        or cosign_entry["role"] != "pinned-cosign-binary"
        or cosign_entry["sha256"] != manifest["cosignBinarySHA256"]
    ):
        raise RunnerError("private pinned Cosign binding differs")
    for prefix, manifest_field, commit_field, tree_field in (
        (
            "lab",
            "labSourceManifestSHA256",
            "labCommit",
            "labTree",
        ),
        (
            "codec",
            "codecSourceManifestSHA256",
            "codecCommit",
            "codecTree",
        ),
    ):
        relative = f"bindings/{prefix}-source-manifest.json"
        commitment = entry_by_path.get(relative)
        if commitment is None:
            raise RunnerError(f"private {prefix} Git-source manifest is absent")
        source_manifest_raw = _private_file(root, relative).read_bytes()
        observed_sha = sha256_bytes(source_manifest_raw)
        if (
            observed_sha != commitment["sha256"]
            or observed_sha != manifest[manifest_field]
        ):
            raise RunnerError(f"private {prefix} Git-source manifest differs")
        verify_copied_source(
            root / prefix,
            source_manifest_raw,
            expected_commit=manifest[commit_field],
            expected_tree=manifest[tree_field],
        )
    return manifest, sha256_bytes(raw)


def install_trusted_supervisor_socket_denial() -> None:
    """Block this trusted Python process's socket API; this is not an OS sandbox."""
    def deny_audit(event: str, _arguments: tuple[Any, ...]) -> None:
        if event.startswith("socket."):
            raise RunnerError(f"network forbidden after pulse seal: {event}")

    sys.addaudithook(deny_audit)

    class DeniedSocket:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RunnerError("network forbidden after pulse seal")

    socket.socket = DeniedSocket  # type: ignore[assignment]
    socket.create_connection = DeniedSocket  # type: ignore[assignment]


def fetch_exact_pulse_with_total_timeout(
    client: Any, *, timeout_seconds: int
) -> ArchivedHTTPResponse:
    """Bound DNS, connect, TLS and body reads with one process-wide timer."""

    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise RunnerError("pulse total timeout is outside the frozen bound")
    if not hasattr(signal, "setitimer") or not hasattr(signal, "SIGALRM"):
        raise RunnerError("host cannot enforce the frozen pulse total timeout")

    def expired(_signum: int, _frame: Any) -> None:
        raise RunnerError("exact NIST pulse request exceeded its total timeout")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        return client(TARGET_ENDPOINT)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def _entry_map(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in manifest["files"]}


def _worker_job(
    *,
    design: Mapping[str, Any],
    selection: Mapping[str, Any],
    private_manifest: Mapping[str, Any],
    model_key: str,
    attempt: str,
) -> dict[str, Any]:
    entries = _entry_map(private_manifest)
    model = next(item for item in design["models"] if item["key"] == model_key)
    files: dict[str, Any] = {}
    for filename in (
        "config.json",
        "generation_config.json",
        "merges.txt",
        "model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    ):
        path = f"models/{model_key}/{filename}"
        entry = entries.get(path)
        if entry is None:
            raise RunnerError(f"private model asset is absent: {path}")
        files[filename] = {
            "path": path,
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
        }
    pages: dict[str, list[dict[str, Any]]] = {}
    for corpus in selection["selectedCorpora"]:
        records: list[dict[str, Any]] = []
        for page_index, page in enumerate(selection["selectedPages"][corpus]):
            path = f"records/{corpus}/{page['revid']}.bin"
            entry = entries.get(path)
            if entry is None:
                raise RunnerError(f"selected private corpus record is absent: {path}")
            records.append(
                {
                    "pageSelectionIndex": page_index,
                    "pageRevisionId": page["revid"],
                    "recordPath": path,
                    "recordBytes": entry["bytes"],
                    "recordSHA256": entry["sha256"],
                }
            )
        pages[corpus] = records
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-worker-job-v1",
        "suiteId": SUITE_ID,
        "attemptId": attempt,
        "countsTowardScientificVerdict": True,
        "model": {
            "key": model_key,
            "files": files,
            "layers": model["layers"],
            "vocabSize": model["vocabSize"],
            "candidateBitsByLayer": model["candidateBitsByLayer"],
        },
        "selectedCorpora": selection["selectedCorpora"],
        "pages": pages,
        "candidate": {
            "backend": design["candidate"]["backend"],
            "groupSize": design["candidate"]["groupSize"],
            "transformBlockSize": design["candidate"]["transformBlockSize"],
            "codeCompression": design["candidate"]["codeCompression"],
            "scaleCompression": design["candidate"]["scaleCompression"],
            "signMode": design["candidate"]["signMode"],
        },
        "seed": 0,
    }


def _process_group_usage(process_group_id: int) -> tuple[int, tuple[int, ...]]:
    """Return aggregate RSS and member PIDs for the worker's new session."""

    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,rss="],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RunnerError(
            "worker process-group observation failed: "
            f"ps exit {completed.returncode}: {completed.stderr.strip()[:256]}"
        )
    total_kibibytes = 0
    members: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not field.isdigit() for field in fields):
            raise RunnerError("worker process-group observation was malformed")
        process_id, observed_group, rss_kibibytes = map(int, fields)
        if observed_group == process_group_id:
            members.append(process_id)
            total_kibibytes += rss_kibibytes
    return total_kibibytes * 1024, tuple(sorted(members))


def _networkless_macos_command(command: list[str]) -> list[str]:
    """Wrap a child in the OS sandbox before its Python interpreter starts."""

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RunnerError("registered networkless child requires macOS arm64")
    observed = digest_regular_file(MACOS_SANDBOX_EXEC)
    if observed["bytes"] <= 0 or not observed["sha256"]:
        raise RunnerError("macOS sandbox executor is unavailable")
    return [
        str(MACOS_SANDBOX_EXEC),
        "-p",
        NETWORK_DENY_PROFILE,
        *command,
    ]


def _network_sandbox_evidence() -> dict[str, Any]:
    observed = digest_regular_file(MACOS_SANDBOX_EXEC)
    return {
        "backend": "macOS sandbox-exec before Python startup",
        "executablePath": str(MACOS_SANDBOX_EXEC),
        "executableBytes": observed["bytes"],
        "executableSHA256": observed["sha256"],
        "profile": NETWORK_DENY_PROFILE,
    }


def fsync_evidence_tree(root: Path) -> None:
    """Durably seal every regular file and directory entry below result root."""

    if root.is_symlink() or not root.is_dir():
        raise RunnerError("evidence root is not a real directory")
    directories: list[Path] = []
    for directory, child_directories, filenames in os.walk(root, topdown=False):
        current = Path(directory)
        directories.append(current)
        for child in child_directories:
            path = current / child
            if path.is_symlink() or not path.is_dir():
                raise RunnerError("evidence tree contains an unsafe directory")
        for filename in filenames:
            path = current / filename
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RunnerError("evidence tree contains a non-regular file")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for directory in directories:
        descriptor = os.open(directory, directory_flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    group_exists = True
    observation_error: RunnerError | None = None
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _rss, members = _process_group_usage(process.pid)
            if not members:
                group_exists = False
                break
            time.sleep(0.05)
    except RunnerError as error:
        observation_error = error
    finally:
        # Observation failure is itself unsafe: SIGKILL remains unconditional
        # so a broken ps invocation cannot let descendants escape.
        if group_exists:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                group_exists = False
    if process.poll() is None:
        process.wait(timeout=5)
    if group_exists:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _rss, members = _process_group_usage(process.pid)
            if not members:
                return
            time.sleep(0.05)
        raise RunnerError("worker process group survived SIGKILL")
    if observation_error is not None:
        raise RunnerError(
            "worker process group required SIGKILL after an observation failure"
        ) from observation_error


def _supervise_worker(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    log: Any,
    maximum_rss_bytes: int,
    poll_milliseconds: int,
) -> dict[str, Any]:
    started_utc = utc_seconds(utc_now())
    started_monotonic = time.monotonic_ns()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    peak_rss = 0
    try:
        while True:
            return_code = process.poll()
            try:
                rss, members = _process_group_usage(process.pid)
            except RunnerError:
                # RSS/process coverage is a normative gate.  Even a just-exited
                # root cannot turn an observation failure into success.
                raise
            if return_code is not None:
                descendants = [member for member in members if member != process.pid]
                if descendants:
                    _terminate_process_group(process)
                    raise RunnerError(
                        "worker exited while descendants remained in its process "
                        f"group: {descendants!r}"
                    )
                return {
                    "schemaVersion": "corelm-crossmodel-livewiki-v3-supervisor-receipt-v1",
                    "processGroupId": process.pid,
                    "startedAt": started_utc,
                    "completedAt": utc_seconds(utc_now()),
                    "durationNanoseconds": time.monotonic_ns() - started_monotonic,
                    "exitCode": return_code,
                    "peakAggregateRSSBytes": peak_rss,
                    "maximumAggregateRSSBytes": maximum_rss_bytes,
                    "watchdogPollMilliseconds": poll_milliseconds,
                    "hardDeadline": HARD_DEADLINE.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "descendantsRemainingAtExit": False,
                    "terminationApplied": False,
                    "countsTowardScientificVerdict": True,
                }
            if utc_now() >= HARD_DEADLINE:
                raise RunnerError("hard deadline reached while a worker was active")
            peak_rss = max(peak_rss, rss)
            if rss > maximum_rss_bytes:
                raise RunnerError(
                    "worker exceeded the frozen RSS bound: "
                    f"{rss} > {maximum_rss_bytes}; peak={peak_rss}"
                )
            time.sleep(poll_milliseconds / 1000)
    except BaseException:
        _terminate_process_group(process)
        raise


def _run_workers(
    *,
    private_root: Path,
    result_root: Path,
    design: Mapping[str, Any],
    selection: Mapping[str, Any],
    private_manifest: Mapping[str, Any],
    attempt: str,
) -> None:
    maximum_rss = design["execution"]["maximumWorkerRSSBytes"]
    poll_milliseconds = design["execution"]["watchdogPollMilliseconds"]
    for model_key in selection["modelExecutionOrder"]:
        job = _worker_job(
            design=design,
            selection=selection,
            private_manifest=private_manifest,
            model_key=model_key,
            attempt=attempt,
        )
        job_path = result_root / "jobs" / f"{model_key}.json"
        write_new_bytes(job_path, canonical_json_bytes(job) + b"\n")
        output_root = result_root / "workers" / model_key
        log_path = result_root / "logs" / f"{model_key}.log"
        log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        worker_environment = scientific_subprocess_environment(design["execution"])
        with log_path.open("xb") as log:
            try:
                supervisor_receipt = _supervise_worker(
                    _networkless_macos_command(
                        _scientific_python_command(
                            sys.executable,
                            str(private_root / "lab" / "v3" / "model_worker.py"),
                            "--job",
                            str(job_path),
                            "--snapshot-root",
                            str(private_root),
                            "--codec-root",
                            str(private_root / "codec"),
                            "--output-root",
                            str(output_root),
                        )
                    ),
                    cwd=private_root / "lab",
                    environment=worker_environment,
                    log=log,
                    maximum_rss_bytes=maximum_rss,
                    poll_milliseconds=poll_milliseconds,
                )
            finally:
                log.flush()
                os.fsync(log.fileno())
        supervisor_receipt.update(
            {"role": "model-worker", "subject": model_key}
        )
        write_new_bytes(
            result_root / "supervision" / f"{model_key}.json",
            canonical_json_bytes(supervisor_receipt) + b"\n",
        )
        if supervisor_receipt["exitCode"] != 0:
            raise RunnerError(
                "networkless model worker failed: "
                f"{model_key}: exit {supervisor_receipt['exitCode']}"
            )


def _consolidate_worker_evidence(
    *, result_root: Path, model_order: Iterable[str]
) -> tuple[Path, Path, Path, list[str]]:
    raw_records: list[dict[str, Any]] = []
    container_records: list[dict[str, Any]] = []
    page_token_records: list[dict[str, Any]] = []
    manifest_paths: list[str] = []
    for model_key in model_order:
        worker_root = result_root / "workers" / model_key
        raw_path = worker_root / "raw-token-evidence.jsonl"
        container_path = worker_root / "container-evidence.jsonl"
        page_token_path = worker_root / "page-token-evidence.jsonl"
        raw_records.extend(
            load_canonical_jsonl(raw_path, maximum_bytes=128 * 1024 * 1024)
        )
        records = load_canonical_jsonl(
            container_path, maximum_bytes=64 * 1024 * 1024
        )
        container_records.extend(records)
        page_token_records.extend(
            load_canonical_jsonl(page_token_path, maximum_bytes=16 * 1024 * 1024)
        )
        for record in records:
            relative = _safe_relative(record["relativePath"])
            source = worker_root.joinpath(*relative.parts)
            destination = result_root.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise RunnerError("duplicate consolidated container path")
            os.replace(source, destination)
            manifest_paths.append(relative.as_posix())
    raw_final = result_root / "raw-token-evidence.jsonl"
    containers_final = result_root / "container-evidence.jsonl"
    page_tokens_final = result_root / "page-token-evidence.jsonl"
    write_new_bytes(raw_final, b"".join(canonical_json_line(item) for item in raw_records))
    write_new_bytes(
        containers_final,
        b"".join(canonical_json_line(item) for item in container_records),
    )
    write_new_bytes(
        page_tokens_final,
        b"".join(canonical_json_line(item) for item in page_token_records),
    )
    return raw_final, containers_final, page_tokens_final, manifest_paths


def scientific_result(
    evaluation: Mapping[str, Any], *, selection_sha256: str, pulse_sha256: str
) -> dict[str, Any]:
    cells: list[dict[str, Any]] = []
    for source in evaluation["cells"]:
        cells.append(
            {
                key: value
                for key, value in source.items()
                if key != "top1ExactMatches"
            }
        )
    aggregates: list[dict[str, Any]] = []
    for source in evaluation["modelAggregates"]:
        aggregates.append(
            {
                "modelKey": source["modelKey"],
                "pages": source["blocks"],
                "predictions": source["predictions"],
                "deltaUpper": source["deltaUpper"],
                "top1Lower": source["top1Lower"],
                "wilsonLower": source["wilsonLower"],
                "pass": source["pass"],
            }
        )
    result = {
        "schemaVersion": RESULT_SCHEMA,
        "suiteId": evaluation["suiteId"],
        "attemptId": evaluation["attemptId"],
        "selectionSHA256": selection_sha256,
        "pulseVerificationSHA256": pulse_sha256,
        "cells": cells,
        "modelAggregates": aggregates,
        "suitePass": evaluation["verdict"] == "PASS",
        "countsTowardScientificVerdict": True,
    }
    _validate_schema(result, "result.schema.json")
    return result


def _failure_reason(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}".replace("\x00", "?")
    return text[:MAX_FAILURE_REASON] or type(error).__name__


def execute_private_one_shot(private_root: Path, result_root: Path) -> str:
    verify_active_scientific_python_startup()
    canonical_result_root = private_root.parent / f"{private_root.name}.one-shot-result"
    if Path(os.path.abspath(os.fspath(result_root))) != Path(
        os.path.abspath(os.fspath(canonical_result_root))
    ):
        raise RunnerError("private execution result root is not canonical")
    expected_script = (private_root / "lab" / "v3" / "runner.py").resolve(strict=True)
    if Path(__file__).resolve(strict=True) != expected_script:
        raise RunnerError("one-shot supervisor is not executing from the private lab tree")
    private_manifest, private_manifest_sha = verify_private_snapshot(private_root)
    entries = _entry_map(private_manifest)

    def bound_path(relative: str) -> Path:
        if relative not in entries:
            raise RunnerError(f"private binding is absent: {relative}")
        return _private_file(private_root, relative)

    private_cosign_path = bound_path("tools/cosign")
    if sha256_file(private_cosign_path) != private_manifest["cosignBinarySHA256"]:
        raise RunnerError("private pinned Cosign binary differs")
    cryptographic_attestation_verifier = (
        PinnedCosignReleaseAttestationVerifier(private_cosign_path)
    )
    design_path = bound_path("bindings/design.json")
    design = load_json_strict(design_path)
    validate_frozen_design(design)
    registered_workflow = _private_file(
        private_root,
        "lab/" + design["continuousIntegration"]["workflowPath"],
    )
    verify_registered_ci_workflow_bytes(design, registered_workflow.read_bytes())
    if sha256_file(design_path) != private_manifest["designSHA256"]:
        raise RunnerError("private design binding differs")
    snapshot_path = bound_path("bindings/snapshot-registration.json")
    snapshot_raw = snapshot_path.read_bytes()
    snapshot = validate_frozen_snapshot_bytes(snapshot_raw)
    if sha256_bytes(snapshot_raw) != private_manifest["snapshotRegistrationSHA256"]:
        raise RunnerError("private snapshot-registration binding differs")
    runtime_path = bound_path("bindings/runtime-manifest.json")
    runtime_raw = runtime_path.read_bytes()
    runtime_manifest = load_json_strict_bytes(runtime_raw, label="private runtime manifest")
    if sha256_bytes(runtime_raw) != private_manifest["runtimeManifestSHA256"]:
        raise RunnerError("private runtime-manifest binding differs")
    verify_runtime_live(runtime_manifest, Path(sys.prefix))
    asset_path = bound_path("bindings/asset-receipt.json")
    if sha256_file(asset_path) != private_manifest["fullAssetReceiptSHA256"]:
        raise RunnerError("private full-asset receipt binding differs")
    asset_source_path = bound_path("bindings/model-assets-source.json")
    if (
        sha256_file(asset_source_path)
        != private_manifest["modelAssetSourceManifestSHA256"]
    ):
        raise RunnerError("private asset source-manifest binding differs")
    corpus_path = bound_path("corpus/corpus-manifest.json")
    if sha256_file(corpus_path) != private_manifest["corpusManifestSHA256"]:
        raise RunnerError("private corpus-manifest binding differs")
    freeze_path = bound_path("bindings/freeze-manifest.json")
    freeze_raw = freeze_path.read_bytes()
    freeze_manifest = load_json_strict_bytes(freeze_raw, label="private freeze manifest")
    github_gate_path = bound_path("bindings/github-gate-receipt.json")
    github_gate_sha = sha256_file(github_gate_path)
    if github_gate_sha != private_manifest["githubGateReceiptSHA256"]:
        raise RunnerError("private GitHub gate receipt binding differs")
    private_ca_path = bound_path("nist/transport-ca.pem")
    private_trust_path = bound_path("nist/trust/manifest.json")
    verify_freeze_artifact_inputs(
        freeze_manifest,
        runtime_manifest_path=runtime_path,
        asset_receipt_path=asset_path,
        ca_bundle_path=private_ca_path,
        trust_manifest_path=private_trust_path,
        github_gate_receipt_path=github_gate_path,
        development_control_report_path=bound_path(
            "development/report.json"
        ),
        development_control_artifact_root=(
            private_root / "development" / "artifacts"
        ),
        development_control_archive_receipt_path=bound_path(
            "development/archive/receipt.json"
        ),
        development_control_archive_asset_root=(
            private_root / "development" / "archive" / "assets"
        ),
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    validate_freeze_manifest(
        freeze_manifest,
        design=design,
        file_sha256=sha256_bytes(freeze_raw),
        runtime_sha256=sha256_bytes(runtime_raw),
        asset_sha256=sha256_file(asset_path),
        github_gate_sha256=github_gate_sha,
    )

    private_signing_key = bound_path("publication/signing-key.pub")
    design_publication = verify_publication(
        bound_path("publication/design-receipt.json"),
        private_root / "publication" / "design-assets",
        kind="design",
        tag=design["designRelease"]["tag"],
        deadline=design["designRelease"]["publishNoLaterThan"],
        signing_public_key_path=private_signing_key,
        signing_key_fingerprint=design["designRelease"]["signingKeyFingerprint"],
        signing_public_key_sha256=design["designRelease"]["signingPublicKeySHA256"],
        expected_role_paths={
            "asset-source-manifest": asset_source_path,
            "design-registration": design_path,
            "development-control-report": bound_path(
                "development/report.json"
            ),
            "development-control-archive-receipt": bound_path(
                "development/archive/receipt.json"
            ),
            "freeze-manifest": freeze_path,
            "full-asset-receipt": asset_path,
            "github-gate-receipt": github_gate_path,
            "linux-ci-artifact": bound_path(
                "publication/design-assets/linux-ci-artifact.zip"
            ),
            "macos-arm64-ci-artifact": bound_path(
                "publication/design-assets/macos-arm64-ci-artifact.zip"
            ),
            "runtime-manifest": runtime_path,
            "sbom": bound_path("bindings/sbom.cdx.json"),
            "sha256-manifest": bound_path(
                "bindings/design-release-sha256-manifest.json"
            ),
        },
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    _require_design_publication_source(design_publication, design, private=True)
    try:
        verify_design_release_package(
            private_root / "publication" / "design-assets",
            signing_public_key_path=private_signing_key,
        )
    except DesignReleaseError as error:
        raise RunnerError(f"private design release package failed: {error}") from error
    snapshot_publication = verify_publication(
        bound_path("publication/snapshot-receipt.json"),
        private_root / "publication" / "snapshot-assets",
        kind="snapshot",
        tag=design["snapshotRelease"]["tag"],
        deadline=design["snapshotRelease"]["publishNoLaterThan"],
        signing_public_key_path=private_signing_key,
        signing_key_fingerprint=design["snapshotRelease"]["signingKeyFingerprint"],
        signing_public_key_sha256=design["snapshotRelease"]["signingPublicKeySHA256"],
        expected_role_paths={
            "attribution": bound_path(
                "publication/snapshot-assets/attribution.json"
            ),
            "corpus-bytes": bound_path(
                "publication/snapshot-assets/corpus-bytes.zip"
            ),
            "design-publication-receipt": bound_path(
                "publication/design-receipt.json"
            ),
            "sha256-manifest": bound_path(
                "publication/snapshot-assets/sha256-manifest.json"
            ),
            "snapshot-registration": snapshot_path,
        },
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    _require_publication_source(
        snapshot_publication,
        design,
        kind="snapshot",
        private=True,
    )
    if (
        design_publication.receipt_sha256
        != private_manifest["designPublicationReceiptSHA256"]
        or snapshot_publication.receipt_sha256
        != private_manifest["snapshotPublicationReceiptSHA256"]
        or sha256_file(private_signing_key)
        != private_manifest["signingPublicKeySHA256"]
    ):
        raise RunnerError("private publication receipts/signing key differ")

    ensure_one_shot_window(utc_now())
    if result_root.exists():
        if result_root.is_symlink() or not result_root.is_dir() or any(result_root.iterdir()):
            raise RunnerError("one-shot result root must be new or empty")
    if load_attempt_marker(result_root) is not None or load_terminal_outcome(result_root) is not None:
        raise RunnerError("one-shot state already exists")

    target_time = datetime.fromtimestamp(TARGET_UNIX_MILLISECONDS / 1000, tz=timezone.utc)
    trust_path = bound_path("nist/trust/manifest.json")
    trust_bundle = load_offline_trust_bundle(
        trust_path,
        expected_time=target_time,
        expected_manifest_sha256=design["beacon"]["offlineTrustBundleSHA256"],
        expected_root_der_sha256=design["beacon"]["nistTrustRootDERsSHA256"],
        allow_fixture=False,
    )
    if trust_bundle.manifest_sha256 != design["beacon"]["offlineTrustBundleSHA256"]:
        raise RunnerError("private NIST trust bundle differs from the design")
    ca_path = bound_path("nist/transport-ca.pem")
    client = PinnedHTTPSClient(
        ca_bundle=ca_path,
        ca_bundle_sha256=design["beacon"]["transportCABundleSHA256"],
        allowed_hosts=("beacon.nist.gov",),
        timeout_seconds=30.0,
    )

    scientific_environment = scientific_subprocess_environment(design["execution"])
    verify_scientific_python_subprocess(sys.executable, scientific_environment)
    host_safety = verify_primary_host_safety(
        design, output_parent=result_root.parent
    )
    # Host commands are intentionally outside the irreversible boundary.  Take
    # a fresh clock sample only after they finish and re-check the window
    # immediately before constructing the durable reservation and marker.
    now = utc_now()
    ensure_one_shot_window(now)
    host_safety.update(
        {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-host-environment-v1",
            "suiteId": SUITE_ID,
            "observedAt": utc_seconds(now),
            "runtimeManifestSHA256": sha256_bytes(runtime_raw),
            "maximumWorkerRSSBytes": design["execution"]["maximumWorkerRSSBytes"],
            "watchdogPollMilliseconds": design["execution"]["watchdogPollMilliseconds"],
            "minimumFreeDiskBytes": design["execution"]["minimumFreeDiskBytes"],
            "networkSandbox": _network_sandbox_evidence(),
            "countsTowardScientificVerdict": True,
        }
    )
    marker = create_attempt_marker(
        result_root,
        suite_id=SUITE_ID,
        attempt_id=attempt_id(now),
        design_sha256=sha256_file(design_path),
        snapshot_registration_sha256=sha256_bytes(snapshot_raw),
        design_publication_receipt_sha256=private_manifest[
            "designPublicationReceiptSHA256"
        ],
        snapshot_publication_receipt_sha256=private_manifest[
            "snapshotPublicationReceiptSHA256"
        ],
        private_snapshot_manifest_sha256=private_manifest_sha,
        runtime_manifest_sha256=sha256_bytes(runtime_raw),
        model_asset_source_manifest_sha256=sha256_file(asset_source_path),
        full_asset_receipt_sha256=sha256_file(asset_path),
        github_gate_receipt_sha256=github_gate_sha,
        corpus_manifest_sha256=sha256_file(corpus_path),
        codec_commit=design["codecSource"]["commit"],
        codec_tree=design["codecSource"]["tree"],
        lab_commit=design["labSource"]["commit"],
        lab_tree=design["labSource"]["tree"],
        target_pulse_timestamp=TARGET_TIMESTAMP,
        created_at=utc_seconds(now),
    )
    try:
        if utc_now() >= HARD_DEADLINE:
            raise RunnerError(
                "hard deadline crossed while the attempt marker became durable"
            )
        write_new_bytes(
            result_root / "environment" / "host-preflight.json",
            canonical_json_bytes(host_safety) + b"\n",
        )
        # Exactly one call through an exact-host, no-redirect client.  There is
        # intentionally no retry loop and no alternate endpoint.
        response = fetch_exact_pulse_with_total_timeout(
            client,
            timeout_seconds=design["execution"]["pulseFetchTotalTimeoutSeconds"],
        )
        write_new_bytes(
            result_root / "nist" / "request-uri.txt",
            TARGET_ENDPOINT.encode("ascii") + b"\n",
        )
        write_new_bytes(
            result_root / "nist" / "response-headers.bin", response.header_bytes
        )
        write_new_bytes(
            result_root / "nist" / "response-body.json", response.body
        )
        verification = verify_nist_pulse_response(
            response=response,
            trust_bundle=trust_bundle,
            expected_unix_milliseconds=TARGET_UNIX_MILLISECONDS,
            allow_fixture=False,
        )
        verify_external_attempt_time_anchor(verification)
        verification_raw = canonical_verification_bytes(verification) + b"\n"
        write_new_bytes(
            result_root / "nist" / "verification.json", verification_raw
        )
        install_trusted_supervisor_socket_denial()

        ledger_bytes = {
            project: bound_path(f"corpus/ledgers/{project}.json").read_bytes()
            for project in PROJECTS
        }
        selection = resolve_selection(
            snapshot_raw,
            verification["outputValue"],
            projects=design["futureCorpus"]["projects"],
            models=[item["key"] for item in design["models"]],
            ledgers=ledger_bytes,
            allow_fixture=False,
        )
        selection_raw = canonical_json_bytes(selection) + b"\n"
        write_new_bytes(result_root / "selection.json", selection_raw)
        write_new_bytes(
            result_root / "private-snapshot-manifest.json",
            (private_root / "private-snapshot-manifest.json").read_bytes(),
        )

        _run_workers(
            private_root=private_root,
            result_root=result_root,
            design=design,
            selection=selection,
            private_manifest=private_manifest,
            attempt=marker["attemptId"],
        )
        raw_path, container_path, page_token_path, container_paths = _consolidate_worker_evidence(
            result_root=result_root,
            model_order=selection["modelExecutionOrder"],
        )
        raw_records = load_canonical_jsonl(
            raw_path, maximum_bytes=128 * 1024 * 1024
        )
        container_records = load_canonical_jsonl(
            container_path, maximum_bytes=64 * 1024 * 1024
        )
        page_token_records = load_canonical_jsonl(
            page_token_path, maximum_bytes=16 * 1024 * 1024
        )
        model_specs = {item["key"]: item for item in design["models"]}
        selected_revisions = {
            corpus: [item["revid"] for item in selection["selectedPages"][corpus]]
            for corpus in selection["selectedCorpora"]
        }
        full_ledgers = {
            corpus: load_json_strict_bytes(
                ledger_bytes[corpus], label=f"full ledger {corpus}"
            )
            for corpus in selection["selectedCorpora"]
        }
        for corpus, ledger in full_ledgers.items():
            if canonical_json_bytes(ledger) != ledger_bytes[corpus]:
                raise RunnerError(f"full ledger is not canonical JSON: {corpus}")
        ledger_commitments = selected_ledger_token_commitments(
            full_ledgers,
            models=[item["key"] for item in design["models"]],
            vocabulary_sizes={
                key: model_specs[key]["vocabSize"] for key in model_specs
            },
            selected_revisions=selected_revisions,
        )
        verify_page_token_evidence(
            page_token_records,
            raw_records,
            suite_id=SUITE_ID,
            attempt_id=marker["attemptId"],
            models=selection["modelExecutionOrder"],
            corpora=selection["selectedCorpora"],
            vocabulary_sizes={
                key: model_specs[key]["vocabSize"] for key in model_specs
            },
            selected_revisions=selected_revisions,
            ledger_token_commitments=ledger_commitments,
        )
        evaluation = evaluate_raw_evidence(
            raw_records,
            container_records,
            suite_id=SUITE_ID,
            attempt_id=marker["attemptId"],
            models=selection["modelExecutionOrder"],
            corpora=selection["selectedCorpora"],
            layer_counts={key: model_specs[key]["layers"] for key in MODELS},
            bits_by_model={
                key: model_specs[key]["candidateBitsByLayer"] for key in MODELS
            },
            selected_revisions=selected_revisions,
            counts_toward_scientific_verdict=True,
            evidence_root=result_root,
            codec_root=private_root / "codec",
        )
        result = scientific_result(
            evaluation,
            selection_sha256=sha256_bytes(selection_raw),
            pulse_sha256=sha256_bytes(verification_raw),
        )
        result_raw = canonical_json_bytes(result) + b"\n"
        write_new_bytes(result_root / "result.json", result_raw)

        manifest_relatives = [
            "attempt-reservation.json",
            "attempt-marker.json",
            "private-snapshot-manifest.json",
            "environment/host-preflight.json",
            "selection.json",
            "nist/request-uri.txt",
            "nist/response-headers.bin",
            "nist/response-body.json",
            "nist/verification.json",
            "raw-token-evidence.jsonl",
            "container-evidence.jsonl",
            "page-token-evidence.jsonl",
            *container_paths,
        ]
        for model_key in selection["modelExecutionOrder"]:
            manifest_relatives.extend(
                [
                    f"jobs/{model_key}.json",
                    f"logs/{model_key}.log",
                    f"supervision/{model_key}.json",
                    f"workers/{model_key}/worker-summary.json",
                    f"workers/{model_key}/raw-token-evidence.jsonl",
                    f"workers/{model_key}/container-evidence.jsonl",
                    f"workers/{model_key}/page-token-evidence.jsonl",
                ]
            )
        fsync_evidence_tree(result_root)
        evidence_manifest = build_sha256_manifest(
            result_root, manifest_relatives
        )
        evidence_manifest_raw = canonical_json_bytes(evidence_manifest) + b"\n"
        write_new_bytes(
            result_root / "evidence-manifest.json", evidence_manifest_raw
        )

        verifier_log = result_root / "logs" / "independent-verifier.log"
        verifier_output = result_root / "independent-verifier-report.json"
        verifier_environment = scientific_subprocess_environment(
            design["execution"]
        )
        with verifier_log.open("xb") as log:
            try:
                verifier_supervisor_receipt = _supervise_worker(
                    _networkless_macos_command(
                        _scientific_python_command(
                            sys.executable,
                            str(private_root / "lab" / "v3" / "verify_evidence.py"),
                            "--evidence-root",
                            str(result_root),
                            "--codec-root",
                            str(private_root / "codec"),
                            "--private-root",
                            str(private_root),
                            "--design",
                            str(design_path),
                            "--snapshot-registration",
                            str(snapshot_path),
                            "--ledgers-root",
                            str(private_root / "corpus" / "ledgers"),
                            "--nist-trust-manifest",
                            str(trust_path),
                            "--result",
                            str(result_root / "result.json"),
                            "--output",
                            str(verifier_output),
                        )
                    ),
                    cwd=private_root / "lab",
                    environment=verifier_environment,
                    log=log,
                    maximum_rss_bytes=design["execution"]["maximumWorkerRSSBytes"],
                    poll_milliseconds=design["execution"]["watchdogPollMilliseconds"],
                )
            finally:
                log.flush()
                os.fsync(log.fileno())
        verifier_supervisor_receipt.update(
            {"role": "independent-verifier", "subject": "evidence"}
        )
        write_new_bytes(
            result_root / "supervision" / "independent-verifier.json",
            canonical_json_bytes(verifier_supervisor_receipt) + b"\n",
        )
        if verifier_supervisor_receipt["exitCode"] != 0 or not verifier_output.is_file():
            raise RunnerError(
                "independent verifier failed with exit "
                f"{verifier_supervisor_receipt['exitCode']}"
            )
        verifier_report = load_json_strict(verifier_output)
        if verifier_report.get("producerResultExactMatch") is not True:
            raise RunnerError("independent verifier did not match producer result")
        replay_summary = verifier_report.get("modelReplaySummary")
        if not isinstance(replay_summary, dict):
            raise RunnerError("independent verifier omitted real-model replay")
        replay_unsigned = dict(replay_summary)
        replay_digest = replay_unsigned.pop("contentSHA256", None)
        if (
            replay_digest
            != sha256_bytes(canonical_json_bytes(replay_unsigned))
            or verifier_report.get("modelReplaySummarySHA256") != replay_digest
            or replay_summary.get("replayComplete") is not True
            or replay_summary.get("exactTokenIds") is not True
            or replay_summary.get("exactLossFloat32Bits") is not True
            or replay_summary.get("exactTop1TokenIds") is not True
            or replay_summary.get("allContainerInputsBoundToBaselineCache")
            is not True
            or replay_summary.get("countsTowardScientificVerdict") is not True
        ):
            raise RunnerError("independent real-model replay proof is incomplete")
        fsync_evidence_tree(result_root)
        terminal_state = "PASS" if result["suitePass"] else "FAIL_GATES"
        create_terminal_outcome(
            result_root,
            terminal_state=terminal_state,
            result_sha256=sha256_bytes(result_raw),
            evidence_manifest_sha256=sha256_bytes(evidence_manifest_raw),
            independent_verifier_sha256=sha256_file(verifier_output),
        )
        return terminal_state
    except BaseException as error:
        if load_terminal_outcome(result_root) is None:
            try:
                fsync_evidence_tree(result_root)
            except BaseException as durability_error:
                error = RunnerError(
                    f"{_failure_reason(error)}; evidence durability barrier failed: "
                    f"{_failure_reason(durability_error)}"
                )
            create_terminal_outcome(
                result_root,
                terminal_state="FAIL_EXECUTION",
                result_sha256=None,
                evidence_manifest_sha256=None,
                independent_verifier_sha256=None,
                failure_reason=_failure_reason(error),
            )
        raise


def reexec_private_one_shot(
    *, private_root: Path, result_root: Path
) -> int:
    canonical_result_root = private_root.parent / f"{private_root.name}.one-shot-result"
    observed_result_root = Path(os.path.abspath(os.fspath(result_root)))
    expected_result_root = Path(os.path.abspath(os.fspath(canonical_result_root)))
    if observed_result_root != expected_result_root:
        raise RunnerError(
            "result root is not the canonical path derived from the sealed snapshot: "
            f"{expected_result_root}"
        )
    private_manifest, _ = verify_private_snapshot(private_root)
    runtime_manifest_path = _private_file(
        private_root, "bindings/runtime-manifest.json"
    )
    runtime_manifest = load_json_strict(runtime_manifest_path)
    expected_executable = runtime_manifest.get("python", {}).get("executable")
    observed_executable = digest_regular_file(Path(sys.executable).resolve(strict=True))
    if not isinstance(expected_executable, dict) or any(
        observed_executable.get(field) != expected_executable.get(field)
        for field in ("bytes", "sha256")
    ):
        raise RunnerError("outer interpreter differs from frozen runtime executable")
    design = load_json_strict(_private_file(private_root, "bindings/design.json"))
    validate_frozen_design(design)
    outer_environment = scientific_subprocess_environment(design["execution"])
    # The private child performs the complete startup/import probe once, after
    # reopening every frozen binding and immediately before the irreversible
    # reservation/marker boundary.  Repeating it in this outer watchdog would
    # make the registered singular pre-marker phase ambiguous and needlessly
    # load the scientific dependency stack twice.
    script = _private_file(private_root, "lab/v3/runner.py")
    command = _scientific_python_command(
        sys.executable,
        str(script),
        "run-one-shot",
        "--private-root",
        str(private_root),
        "--result-root",
        str(result_root),
        "--confirm-scientific-one-shot",
        SUITE_ID,
        "--private-execution",
    )
    process = subprocess.Popen(
        command,
        cwd=private_root / "lab",
        env=outer_environment,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        while True:
            return_code = process.poll()
            _rss, members = _process_group_usage(process.pid)
            if return_code is not None:
                descendants = [member for member in members if member != process.pid]
                if descendants:
                    _terminate_process_group(process)
                    raise RunnerError(
                        "private supervisor exited with descendants still active"
                    )
                del private_manifest
                return return_code
            if utc_now() >= HARD_DEADLINE:
                raise RunnerError("hard deadline reached in the outer supervisor")
            time.sleep(0.25)
    except BaseException as error:
        try:
            _terminate_process_group(process)
        finally:
            if result_root.is_dir() and not result_root.is_symlink():
                try:
                    marker = load_attempt_marker(result_root)
                    outcome = load_terminal_outcome(result_root)
                    if marker is not None and outcome is None:
                        try:
                            fsync_evidence_tree(result_root)
                        except BaseException:
                            pass
                        create_terminal_outcome(
                            result_root,
                            terminal_state="FAIL_EXECUTION",
                            result_sha256=None,
                            evidence_manifest_sha256=None,
                            independent_verifier_sha256=None,
                            failure_reason=_failure_reason(error),
                        )
                except BaseException:
                    # A partial/unreadable marker remains forensic evidence and
                    # is classified as consumed incomplete at publication.
                    pass
        raise


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--design", type=Path, required=True)
    prepare.add_argument("--snapshot-registration", type=Path, required=True)
    prepare.add_argument("--corpus-root", type=Path, required=True)
    prepare.add_argument("--asset-manifest", type=Path, required=True)
    prepare.add_argument("--asset-receipt", type=Path, required=True)
    prepare.add_argument("--asset-root", type=Path, required=True)
    prepare.add_argument("--runtime-manifest", type=Path, required=True)
    prepare.add_argument("--runtime-root", type=Path, required=True)
    prepare.add_argument("--freeze-manifest", type=Path, required=True)
    prepare.add_argument("--github-gate-receipt", type=Path, required=True)
    prepare.add_argument("--development-control-report", type=Path, required=True)
    prepare.add_argument(
        "--development-control-artifact-root", type=Path, required=True
    )
    prepare.add_argument(
        "--development-control-archive-receipt", type=Path, required=True
    )
    prepare.add_argument(
        "--development-control-archive-assets", type=Path, required=True
    )
    prepare.add_argument("--sbom", type=Path, required=True)
    prepare.add_argument("--design-sha256-manifest", type=Path, required=True)
    prepare.add_argument("--design-publication-receipt", type=Path, required=True)
    prepare.add_argument("--design-release-assets", type=Path, required=True)
    prepare.add_argument("--snapshot-publication-receipt", type=Path, required=True)
    prepare.add_argument("--snapshot-release-assets", type=Path, required=True)
    prepare.add_argument("--signing-public-key", type=Path, required=True)
    prepare.add_argument("--nist-trust-manifest", type=Path, required=True)
    prepare.add_argument("--ca-bundle", type=Path, required=True)
    prepare.add_argument("--cosign", type=Path, required=True)
    prepare.add_argument("--codec-root", type=Path, required=True)
    prepare.add_argument("--lab-root", type=Path, default=PROJECT_ROOT)
    prepare.add_argument("--destination", type=Path, required=True)

    run = subparsers.add_parser("run-one-shot")
    run.add_argument("--private-root", type=Path, required=True)
    run.add_argument("--result-root", type=Path, required=True)
    run.add_argument("--confirm-scientific-one-shot", required=True)
    run.add_argument("--private-execution", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "prepare":
            summary = prepare_private_snapshot(
                design_path=arguments.design,
                snapshot_registration_path=arguments.snapshot_registration,
                corpus_root=arguments.corpus_root,
                asset_manifest_path=arguments.asset_manifest,
                asset_receipt_path=arguments.asset_receipt,
                asset_root=arguments.asset_root,
                runtime_manifest_path=arguments.runtime_manifest,
                runtime_root=arguments.runtime_root,
                freeze_manifest_path=arguments.freeze_manifest,
                github_gate_receipt_path=arguments.github_gate_receipt,
                development_control_report_path=(
                    arguments.development_control_report
                ),
                development_control_artifact_root=(
                    arguments.development_control_artifact_root
                ),
                development_control_archive_receipt_path=(
                    arguments.development_control_archive_receipt
                ),
                development_control_archive_asset_root=(
                    arguments.development_control_archive_assets
                ),
                sbom_path=arguments.sbom,
                design_sha256_manifest_path=arguments.design_sha256_manifest,
                design_publication_receipt_path=arguments.design_publication_receipt,
                design_release_asset_root=arguments.design_release_assets,
                snapshot_publication_receipt_path=arguments.snapshot_publication_receipt,
                snapshot_release_asset_root=arguments.snapshot_release_assets,
                signing_public_key_path=arguments.signing_public_key,
                nist_trust_manifest_path=arguments.nist_trust_manifest,
                ca_bundle_path=arguments.ca_bundle,
                cosign_path=arguments.cosign,
                codec_root=arguments.codec_root,
                lab_root=arguments.lab_root,
                destination=arguments.destination,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if arguments.confirm_scientific_one_shot != SUITE_ID:
            raise RunnerError("explicit scientific one-shot confirmation differs")
        if arguments.private_execution:
            state = execute_private_one_shot(
                arguments.private_root, arguments.result_root
            )
            print(state)
            return 0
        return reexec_private_one_shot(
            private_root=arguments.private_root,
            result_root=arguments.result_root,
        )
    except (OSError, ValueError, RunnerError, subprocess.SubprocessError) as error:
        print(f"BLIND-V3 RUNNER FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
