#!/usr/bin/env python3
"""Build and independently verify the twelve frozen design-release assets.

The packager is deliberately offline.  As inputs it preserves eleven exact
provenance artifacts, derives a canonical SHA-256 inventory for those eleven
files, and explicitly excludes that inventory from its own file-hash list.
The later signed GitHub release receipt binds all twelve assets, including the
SHA-256 inventory itself, without a self-reference.

The preregistered SSH public key is an external trust input.  Its exact file
digest and OpenSSH fingerprint are checked against every release plan in the
frozen design, but the key is not a design-release asset because
``v2.release_receipt`` verifies it separately.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


V2_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V2_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v2 import freeze_manifest  # noqa: E402
from v2.create_sbom import build_sbom  # noqa: E402
from v2.github_gate_receipt import (  # noqa: E402
    REQUIRED_LINUX_ARTIFACT_PREFIX,
    REQUIRED_MACOS_ARTIFACT_PREFIX,
    canonical_ci_artifact_commitments,
)
from v2.protocol import (  # noqa: E402
    load_json_strict_bytes,
    validate_frozen_design_registration,
    validate_model_asset_manifest,
)
from v2.release_receipt import REQUIRED_ASSET_ROLES  # noqa: E402
from v2.release_attestation_crypto import (  # noqa: E402
    ReleaseAttestationCryptoError,
    validate_known_answer_result,
)
from v2.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    verify_content_digest,
    verify_runtime_manifest_integrity,
    with_content_digest,
)


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v2"
SHA256_MANIFEST_SCHEMA = (
    "corelm-crossmodel-livewiki-v2-design-release-sha256-manifest-v1"
)
VERIFICATION_SCHEMA = (
    "corelm-crossmodel-livewiki-v2-design-release-verification-v1"
)
TRACKED_ASSET_SOURCE_NAME = "model-assets.draft.json"
READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_JSON_BYTES = 512 * 1024 * 1024
MAXIMUM_KEY_BYTES = 1024 * 1024
MAXIMUM_CI_ZIP_BYTES = 512 * 1024 * 1024
MAXIMUM_CI_MEMBER_BYTES = 512 * 1024 * 1024
MAXIMUM_CI_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024

ASSET_NAMES: dict[str, str] = {
    "asset-source-manifest": "asset-source-manifest.json",
    "design-registration": "design-registration.json",
    "development-control-report": "development-control-report.json",
    "development-control-archive-receipt": "development-control-archive-receipt.json",
    "freeze-manifest": "freeze-manifest.json",
    "full-asset-receipt": "full-asset-receipt.json",
    "github-gate-receipt": "github-gate-receipt.json",
    "linux-ci-artifact": "linux-ci-artifact.zip",
    "macos-arm64-ci-artifact": "macos-arm64-ci-artifact.zip",
    "runtime-manifest": "runtime-manifest.json",
    "sbom": "sbom.cdx.json",
    "sha256-manifest": "sha256-manifest.json",
}
ASSET_ROLES = tuple(ASSET_NAMES)
MANIFEST_ROLES = tuple(
    role for role in ASSET_ROLES if role != "sha256-manifest"
)
CI_ARTIFACT_ROLES = ("linux-ci-artifact", "macos-arm64-ci-artifact")
CI_PLATFORM_SPECS: dict[str, dict[str, str]] = {
    "linux-ci-artifact": {
        "platform": "linux-x86_64",
        "memberSuffix": "linux",
        "system": "Linux",
        "machine": "x86_64",
        "artifactPrefix": REQUIRED_LINUX_ARTIFACT_PREFIX,
        "cosignPlatform": "linux/amd64",
    },
    "macos-arm64-ci-artifact": {
        "platform": "macos-arm64",
        "memberSuffix": "macos",
        "system": "Darwin",
        "machine": "arm64",
        "artifactPrefix": REQUIRED_MACOS_ARTIFACT_PREFIX,
        "cosignPlatform": "darwin/arm64",
    },
}
CI_REQUIREMENTS_LOCK_NAMES: dict[str, tuple[str, ...]] = {
    "linux-ci-artifact": (
        "pip-bootstrap.txt",
        "real-llm-linux-cpu-py312.txt",
        "torch-linux-cpu-py312.txt",
    ),
    "macos-arm64-ci-artifact": (
        "pip-bootstrap.txt",
        "requirements.lock",
    ),
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
ZERO_SKIP_PASS = re.compile(
    r"ZERO-SKIP POLICY PASS: ([1-9][0-9]*) tests, 0 skipped\Z"
)
UNITTEST_RAN = re.compile(r"Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s\Z")


class DesignReleaseError(RuntimeError):
    """The design-release package is unsafe, incomplete, or inconsistent."""


@dataclass(frozen=True)
class AssetRecord:
    role: str
    name: str
    bytes: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "name": self.name,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class CIArtifactVerification:
    role: str
    release_name: str
    github_actions_artifact_name: str
    platform: str
    system: str
    machine: str
    archive_bytes: int
    archive_sha256: str
    design_registration_file_sha256: str
    runtime_manifest_content_sha256: str
    workflow_file_bytes: int
    workflow_file_sha256: str
    tests_run: int
    members: tuple[AssetRecord, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": (
                "corelm-crossmodel-livewiki-v2-ci-artifact-verification-v1"
            ),
            "suiteId": SUITE_ID,
            "status": "VERIFIED_CI_ARTIFACT_PAYLOAD",
            "role": self.role,
            "releaseName": self.release_name,
            "githubActionsArtifactName": self.github_actions_artifact_name,
            "platform": self.platform,
            "system": self.system,
            "machine": self.machine,
            "archiveBytes": self.archive_bytes,
            "archiveSHA256": self.archive_sha256,
            "designRegistrationFileSHA256": (
                self.design_registration_file_sha256
            ),
            "runtimeManifestContentSHA256": (
                self.runtime_manifest_content_sha256
            ),
            "workflowFileBytes": self.workflow_file_bytes,
            "workflowFileSHA256": self.workflow_file_sha256,
            "testsRun": self.tests_run,
            "skippedTests": 0,
            "members": [record.as_dict() for record in self.members],
        }


@dataclass(frozen=True)
class DesignReleaseVerification:
    asset_root: Path
    implementation_commit: str
    implementation_tree: str
    freeze_manifest_sha256: str
    runtime_manifest_sha256: str
    full_asset_receipt_sha256: str
    github_gate_receipt_sha256: str
    development_control_report_sha256: str
    development_control_archive_receipt_sha256: str
    development_control_artifact_set_sha256: str
    development_control_configuration_sha256: str
    signing_key_fingerprint: str
    signing_public_key_sha256: str
    ci_artifacts: tuple[CIArtifactVerification, ...]
    assets: tuple[AssetRecord, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": VERIFICATION_SCHEMA,
            "suiteId": SUITE_ID,
            "status": "VERIFIED_DESIGN_RELEASE_ASSETS",
            "assetRoot": str(self.asset_root),
            "implementationCommit": self.implementation_commit,
            "implementationTree": self.implementation_tree,
            "freezeManifestSHA256": self.freeze_manifest_sha256,
            "runtimeManifestSHA256": self.runtime_manifest_sha256,
            "fullAssetReceiptSHA256": self.full_asset_receipt_sha256,
            "githubGateReceiptSHA256": self.github_gate_receipt_sha256,
            "developmentControlReportSHA256": (
                self.development_control_report_sha256
            ),
            "developmentControlArchiveReceiptSHA256": (
                self.development_control_archive_receipt_sha256
            ),
            "developmentControlArtifactSetSHA256": (
                self.development_control_artifact_set_sha256
            ),
            "developmentControlConfigurationSHA256": (
                self.development_control_configuration_sha256
            ),
            "signingKeyFingerprint": self.signing_key_fingerprint,
            "signingPublicKeySHA256": self.signing_public_key_sha256,
            "ciArtifacts": [item.as_dict() for item in self.ci_artifacts],
            "assets": [record.as_dict() for record in self.assets],
        }


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_no_symlinks(path: Path, *, label: str) -> tuple[Path, int]:
    absolute = _absolute_without_resolving(path)
    descriptor = os.open(os.sep, _directory_flags())
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise DesignReleaseError(
                    f"{label} contains a symlink or non-directory component"
                ) from error
            os.close(descriptor)
            descriptor = child
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise DesignReleaseError(f"{label} is not a directory")
        return absolute, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _read_unique_regular_path(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = MAXIMUM_JSON_BYTES,
) -> bytes:
    """Read one stable, unique regular file through no-follow descriptors."""

    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise DesignReleaseError(f"{label} byte bound is invalid")
    absolute = _absolute_without_resolving(path)
    _parent, parent_descriptor = _open_directory_no_symlinks(
        absolute.parent, label=f"{label} parent"
    )
    try:
        try:
            descriptor = os.open(
                absolute.name, _file_flags(), dir_fd=parent_descriptor
            )
        except OSError as error:
            raise DesignReleaseError(
                f"{label} must be a regular non-symlink file"
            ) from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise DesignReleaseError(f"{label} is not a regular file")
            if before.st_nlink != 1:
                raise DesignReleaseError(f"{label} must not be hard-linked")
            if before.st_size <= 0 or before.st_size > maximum_bytes:
                raise DesignReleaseError(f"{label} is empty or exceeds its byte bound")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise DesignReleaseError(f"{label} grew past its byte bound")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if _identity(before) != _identity(after) or observed != before.st_size:
                raise DesignReleaseError(f"{label} changed while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _load_json(raw: bytes, *, label: str) -> Mapping[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise DesignReleaseError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise DesignReleaseError(f"{label} root must be an object")
    return value


def _load_canonical_json(raw: bytes, *, label: str) -> Mapping[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise DesignReleaseError(f"{label} must end in exactly one LF")
    value = _load_json(raw, label=label)
    if raw != canonical_json_bytes(value) + b"\n":
        raise DesignReleaseError(f"{label} bytes are not canonical JSON plus LF")
    return value


def _load_pretty_json(raw: bytes, *, label: str) -> Mapping[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise DesignReleaseError(f"{label} must end in exactly one LF")
    value = _load_json(raw, label=label)
    expected = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if raw != expected:
        raise DesignReleaseError(
            f"{label} bytes differ from the pinned producer serialization"
        )
    return value


def _member_record(role: str, name: str, raw: bytes) -> AssetRecord:
    return AssetRecord(
        role=role,
        name=name,
        bytes=len(raw),
        sha256=sha256_bytes(raw),
    )


def _read_ci_zip_members(
    raw_zip: bytes,
    *,
    expected_names: tuple[str, ...],
    label: str,
) -> dict[str, bytes]:
    """Read an exact small flat ZIP without ever extracting to the filesystem."""

    if not isinstance(raw_zip, bytes) or not 22 <= len(raw_zip) <= MAXIMUM_CI_ZIP_BYTES:
        raise DesignReleaseError(f"{label} ZIP size is invalid")
    if not raw_zip.startswith(b"PK\x03\x04"):
        raise DesignReleaseError(f"{label} is not a plain ZIP archive")
    search_start = max(0, len(raw_zip) - (65535 + 22))
    eocd_offset = raw_zip.rfind(b"PK\x05\x06", search_start)
    if eocd_offset < 0 or eocd_offset + 22 > len(raw_zip):
        raise DesignReleaseError(f"{label} ZIP end record is absent")
    try:
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_bytes,
            central_offset,
            comment_bytes,
        ) = struct.unpack_from("<4s4H2IH", raw_zip, eocd_offset)
    except struct.error as error:
        raise DesignReleaseError(f"{label} ZIP end record is malformed") from error
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != len(expected_names)
        or total_entries != len(expected_names)
        or central_bytes in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_bytes != eocd_offset
        or eocd_offset + 22 + comment_bytes != len(raw_zip)
    ):
        raise DesignReleaseError(
            f"{label} must be one non-ZIP64 archive with no prefix or trailer"
        )

    expected = set(expected_names)
    result: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw_zip), mode="r", allowZip64=False) as archive:
            infos = archive.infolist()
            if len(infos) != len(expected_names):
                raise DesignReleaseError(f"{label} ZIP member count differs")
            total_uncompressed = 0
            for info in infos:
                name = info.filename
                if (
                    name not in expected
                    or name in result
                    or info.is_dir()
                    or "/" in name
                    or "\\" in name
                    or "\x00" in name
                ):
                    raise DesignReleaseError(
                        f"{label} ZIP member name/inventory differs"
                    )
                if info.flag_bits & 0x1:
                    raise DesignReleaseError(f"{label} ZIP member is encrypted")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise DesignReleaseError(
                        f"{label} ZIP member compression is unsupported"
                    )
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                unix_type = stat.S_IFMT(unix_mode)
                if (
                    info.external_attr & 0x10
                    or unix_type not in {0, stat.S_IFREG}
                    or not 0 < info.file_size <= MAXIMUM_CI_MEMBER_BYTES
                    or not 0 <= info.compress_size <= MAXIMUM_CI_ZIP_BYTES
                ):
                    raise DesignReleaseError(
                        f"{label} ZIP member type or size is unsafe"
                    )
                total_uncompressed += info.file_size
                if total_uncompressed > MAXIMUM_CI_UNCOMPRESSED_BYTES:
                    raise DesignReleaseError(
                        f"{label} ZIP uncompressed byte bound is exceeded"
                    )
                chunks: list[bytes] = []
                observed = 0
                with archive.open(info, mode="r") as member:
                    while True:
                        chunk = member.read(READ_CHUNK_BYTES)
                        if not chunk:
                            break
                        observed += len(chunk)
                        if observed > info.file_size or observed > MAXIMUM_CI_MEMBER_BYTES:
                            raise DesignReleaseError(
                                f"{label} ZIP member expanded past its bound"
                            )
                        chunks.append(chunk)
                if observed != info.file_size:
                    raise DesignReleaseError(f"{label} ZIP member length differs")
                result[name] = b"".join(chunks)
    except (zipfile.BadZipFile, NotImplementedError, OSError) as error:
        raise DesignReleaseError(f"{label} ZIP integrity verification failed") from error
    if set(result) != expected:
        raise DesignReleaseError(f"{label} ZIP exact member inventory differs")
    return result


def _verify_zero_skip_log(raw: bytes, *, label: str) -> int:
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= MAXIMUM_CI_MEMBER_BYTES
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\x00" in raw
    ):
        raise DesignReleaseError(f"{label} zero-skip log byte boundary differs")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DesignReleaseError(f"{label} zero-skip log is not strict UTF-8") from error
    lines = text[:-1].split("\n")
    if not lines:
        raise DesignReleaseError(f"{label} zero-skip log is empty")
    pass_match = ZERO_SKIP_PASS.fullmatch(lines[-1])
    ran = [UNITTEST_RAN.fullmatch(line) for line in lines]
    ran = [match for match in ran if match is not None]
    tests_run = int(pass_match.group(1)) if pass_match is not None else -1
    if (
        pass_match is None
        or len(ran) != 1
        or tests_run != int(ran[0].group(1))
        or sum(line.endswith(" ... ok") for line in lines) != tests_run
        or sum(line == "OK" for line in lines) != 1
        or any(
            line.startswith("FAILED")
            or line.startswith("OK (")
            or line.startswith("ZERO-SKIP POLICY FAIL")
            or line.endswith(" ... skipped")
            or line.endswith(" ... FAIL")
            or line.endswith(" ... ERROR")
            for line in lines
        )
    ):
        raise DesignReleaseError(f"{label} does not prove one zero-skip test run")
    return tests_run


def _verify_ci_runtime_source(
    source: Any,
    *,
    expected: Mapping[str, Any],
    label: str,
) -> None:
    if (
        not isinstance(source, dict)
        or set(source)
        != {
            "commit",
            "tree",
            "origin",
            "worktreeClean",
            "worktreeStatusSHA256",
        }
        or source.get("commit") != expected.get("commit")
        or source.get("tree") != expected.get("tree")
        or source.get("worktreeClean") is not True
        or source.get("worktreeStatusSHA256") != sha256_bytes(b"")
    ):
        raise DesignReleaseError(f"{label} Git source identity/cleanliness differs")
    try:
        observed_repository = freeze_manifest._github_repository_base(
            source.get("origin"), label=f"{label} origin"
        )
        expected_repository = freeze_manifest._github_repository_base(
            expected.get("repository"), label=f"{label} frozen repository"
        )
    except freeze_manifest.FreezeManifestError as error:
        raise DesignReleaseError(f"{label} Git repository differs") from error
    if observed_repository != expected_repository:
        raise DesignReleaseError(f"{label} Git repository differs")


def _verify_ci_runtime_manifest(
    runtime: Mapping[str, Any],
    *,
    role: str,
    spec: Mapping[str, str],
    design: Mapping[str, Any],
    freeze: Mapping[str, Any],
) -> None:
    """Verify one platform CI inventory without applying the macOS one-shot rule."""

    try:
        verify_runtime_manifest_integrity(runtime)
    except ValueError as error:
        raise DesignReleaseError(f"{role} runtime manifest integrity failed") from error

    expected_fields = {
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
    if (
        set(runtime) != expected_fields
        or runtime.get("schemaVersion") != freeze_manifest.RUNTIME_SCHEMA
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
        raise DesignReleaseError(f"{role} runtime manifest boundary differs")

    python = runtime.get("python")
    executable = python.get("executable") if isinstance(python, dict) else None
    platform_pattern = (
        r"linux-[A-Za-z0-9_.-]*x86_64"
        if role == "linux-ci-artifact"
        else r"macosx-[A-Za-z0-9_.-]+-arm64"
    )
    if (
        not isinstance(python, dict)
        or python.get("registeredVersion") != "3.12.10"
        or python.get("version") != "3.12.10"
        or not isinstance(python.get("platformTag"), str)
        or re.fullmatch(platform_pattern, python["platformTag"]) is None
        or not isinstance(executable, dict)
        or type(executable.get("bytes")) is not int
        or executable["bytes"] <= 0
        or re.fullmatch(r"[0-9a-f]{64}", str(executable.get("sha256"))) is None
    ):
        raise DesignReleaseError(f"{role} runtime Python identity differs")

    host = runtime.get("host")
    if (
        not isinstance(host, dict)
        or set(host)
        != {"system", "release", "version", "machine", "processor", "macVersion"}
        or host.get("system") != spec["system"]
        or host.get("machine") != spec["machine"]
        or not isinstance(host.get("release"), str)
        or not host["release"]
        or not isinstance(host.get("version"), str)
        or not host["version"]
        or not isinstance(host.get("processor"), str)
        or (
            spec["system"] == "Darwin"
            and (
                not isinstance(host.get("macVersion"), str)
                or not host["macVersion"]
            )
        )
        or (spec["system"] == "Linux" and host.get("macVersion") is not None)
    ):
        raise DesignReleaseError(f"{role} runtime host platform differs")

    environment = runtime.get("environment")
    if (
        not isinstance(environment, dict)
        or set(environment) != RUNTIME_ENVIRONMENT_KEYS
        or any(value is not None and not isinstance(value, str) for value in environment.values())
    ):
        raise DesignReleaseError(f"{role} runtime environment inventory differs")

    locks = runtime.get("requirementsLocks")
    expected_lock_names = CI_REQUIREMENTS_LOCK_NAMES[role]
    if (
        not isinstance(locks, list)
        or tuple(item.get("name") for item in locks if isinstance(item, dict))
        != expected_lock_names
        or len(locks) != len(expected_lock_names)
    ):
        raise DesignReleaseError(f"{role} runtime requirements lock set differs")
    for lock in locks:
        if (
            not isinstance(lock, dict)
            or set(lock) != {"name", "bytes", "sha256"}
            or type(lock.get("bytes")) is not int
            or lock["bytes"] <= 0
            or re.fullmatch(r"[0-9a-f]{64}", str(lock.get("sha256"))) is None
        ):
            raise DesignReleaseError(f"{role} runtime lock commitment differs")
    registered_runtime = design.get("runtime")
    if not isinstance(registered_runtime, dict):
        raise DesignReleaseError(f"{role} frozen runtime registration is absent")
    expected_pip_lock = {
        "name": "pip-bootstrap.txt",
        "bytes": 173,
        "sha256": registered_runtime.get("pipBootstrapLockSHA256"),
    }
    if locks[0] != expected_pip_lock:
        raise DesignReleaseError(f"{role} pip-bootstrap lock differs")
    if role == "macos-arm64-ci-artifact" and locks != [
        expected_pip_lock,
        {
            "name": "requirements.lock",
            "bytes": 55_781,
            "sha256": registered_runtime.get("requirementsLockSHA256"),
        },
    ]:
        raise DesignReleaseError(
            "macos-arm64-ci-artifact exact registered lock set differs"
        )

    distributions = runtime.get("installedDistributions")
    distribution_count = runtime.get("installedDistributionCount")
    if (
        not isinstance(distributions, list)
        or not distributions
        or type(distribution_count) is not int
        or distribution_count != len(distributions)
        or not all(isinstance(item, dict) and item for item in distributions)
    ):
        raise DesignReleaseError(f"{role} runtime distribution inventory differs")
    for field in ("runtimeTree", "basePythonTree"):
        tree = runtime.get(field)
        if (
            not isinstance(tree, dict)
            or type(tree.get("entryCount")) is not int
            or tree["entryCount"] <= 0
            or re.fullmatch(r"[0-9a-f]{64}", str(tree.get("treeSHA256"))) is None
        ):
            raise DesignReleaseError(f"{role} runtime {field} inventory differs")
    if type(runtime.get("basePythonDistinctFromRuntime")) is not bool:
        raise DesignReleaseError(f"{role} runtime base-Python boundary differs")

    _verify_ci_runtime_source(
        runtime.get("labSource"),
        expected=freeze["implementation"],
        label=f"{role} labSource",
    )
    _verify_ci_runtime_source(
        runtime.get("codecSource"),
        expected=freeze["codec"],
        label=f"{role} codecSource",
    )


def _verify_ci_artifact_payload(
    *,
    role: str,
    raw_zip: bytes,
    github_actions_artifact_name: str,
    expected_archive_sha256: str,
    workflow_run_id: int,
    design: Mapping[str, Any],
    freeze: Mapping[str, Any],
) -> CIArtifactVerification:
    spec = CI_PLATFORM_SPECS.get(role)
    if spec is None:
        raise DesignReleaseError("unsupported CI artifact role")
    expected_name = (
        spec["artifactPrefix"] + str(workflow_run_id) + r"-[1-9][0-9]*"
    )
    if re.fullmatch(expected_name, github_actions_artifact_name) is None:
        raise DesignReleaseError(
            f"{role} GitHub Actions artifact name/run binding differs"
        )
    archive_sha256 = sha256_bytes(raw_zip)
    if archive_sha256 != expected_archive_sha256:
        raise DesignReleaseError(f"{role} raw ZIP differs from GitHub artifact digest")

    suffix = spec["memberSuffix"]
    names = {
        "preflight": f"v2-preflight-{suffix}.json",
        "runtime-manifest": f"v2-runtime-{suffix}.json",
        "zero-skip-log": f"v2-zero-skip-{suffix}.log",
        "design-check": f"v2-design-check-{suffix}.json",
        "release-attestation-known-answer": (
            f"v2-release-attestation-known-answer-{suffix}.json"
        ),
    }
    members = _read_ci_zip_members(
        raw_zip,
        expected_names=tuple(names.values()),
        label=role,
    )
    preflight = _load_pretty_json(
        members[names["preflight"]], label=f"{role} preflight"
    )
    runtime = _load_canonical_json(
        members[names["runtime-manifest"]], label=f"{role} runtime manifest"
    )
    design_check = _load_pretty_json(
        members[names["design-check"]], label=f"{role} design check"
    )
    known_answer = _load_pretty_json(
        members[names["release-attestation-known-answer"]],
        label=f"{role} release-attestation known answer",
    )
    try:
        validate_known_answer_result(
            known_answer,
            expected_platform=spec["cosignPlatform"],
        )
    except ReleaseAttestationCryptoError as error:
        raise DesignReleaseError(
            f"{role} release-attestation known answer differs"
        ) from error
    tests_run = _verify_zero_skip_log(
        members[names["zero-skip-log"]], label=role
    )

    expected_preflight_fields = {
        "schemaVersion",
        "status",
        "countsTowardScientificVerdict",
        "networkUsed",
        "modelInferenceUsed",
        "corpusOpened",
        "attemptMarkerCreated",
        "primaryPlatformRequired",
        "designSHA256",
        "codec",
        "assetManifest",
        "localAssets",
        "assetReceipt",
        "platformSafety",
        "resultBoundary",
        "executionReady",
        "readinessFailures",
    }
    safety = preflight.get("platformSafety")
    codec = preflight.get("codec")
    design_sha256 = preflight.get("designSHA256")
    if (
        set(preflight) != expected_preflight_fields
        or preflight.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v2-preflight-v1"
        or preflight.get("status") != "DEVELOPMENT_PREFLIGHT_ONLY"
        or any(
            preflight.get(field) is not False
            for field in (
                "countsTowardScientificVerdict",
                "networkUsed",
                "modelInferenceUsed",
                "corpusOpened",
                "attemptMarkerCreated",
                "executionReady",
            )
        )
        or preflight.get("primaryPlatformRequired") != "Darwin-arm64"
        or preflight.get("localAssets")
        != {"provided": False, "verified": False, "files": 0}
        or preflight.get("assetReceipt") != {"provided": False, "verified": False}
        or preflight.get("resultBoundary")
        != {"pristine": True, "entries": ["README.md"]}
        or not isinstance(preflight.get("readinessFailures"), list)
        or not preflight["readinessFailures"]
        or not isinstance(safety, dict)
        or safety.get("system") != spec["system"]
        or safety.get("machine") != spec["machine"]
        or not isinstance(codec, dict)
        or codec
        != {
            "commit": freeze["codec"]["commit"],
            "tree": freeze["codec"]["tree"],
            "files": design["codecSource"]["requiredFiles"],
        }
        or not isinstance(design_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", design_sha256) is None
    ):
        raise DesignReleaseError(f"{role} preflight content/platform differs")

    _verify_content_digest(runtime, label=f"{role} runtime manifest")
    _verify_ci_runtime_manifest(
        runtime,
        role=role,
        spec=spec,
        design=design,
        freeze=freeze,
    )

    expected_design_check_fields = {
        "schemaVersion",
        "status",
        "readyToFreeze",
        "freezeValidatorImplemented",
        "countsTowardScientificVerdict",
        "designRegistrationFileSHA256",
        "canonicalDesignSHA256",
        "modelAssetManifestFileSHA256",
        "modelAssetSummary",
        "knownAnswerSelectionSHA256",
        "knownAnswerDrawsSHA256",
        "freezeBlockers",
        "workflowFileBytes",
        "workflowFileSHA256",
        "platformSafety",
        "networkUsed",
        "modelInferenceUsed",
        "corpusOpened",
    }
    registered_ci = design.get("continuousIntegration")
    check_platform = design_check.get("platformSafety")
    if (
        set(design_check) != expected_design_check_fields
        or design_check.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v2-design-check-v1"
        or design_check.get("status") != "DRAFT_VERIFIED_NOT_PREREGISTERED"
        or design_check.get("readyToFreeze") is not False
        or design_check.get("freezeValidatorImplemented") is not True
        or any(
            design_check.get(field) is not False
            for field in (
                "countsTowardScientificVerdict",
                "networkUsed",
                "modelInferenceUsed",
                "corpusOpened",
            )
        )
        or not isinstance(design_check.get("freezeBlockers"), list)
        or not design_check["freezeBlockers"]
        or not isinstance(registered_ci, dict)
        or design_check.get("workflowFileBytes")
        != registered_ci.get("workflowFileBytes")
        or design_check.get("workflowFileSHA256")
        != registered_ci.get("workflowFileSHA256")
        or design_check.get("designRegistrationFileSHA256") != design_sha256
        or not isinstance(check_platform, dict)
        or check_platform
        != {"system": spec["system"], "machine": spec["machine"]}
    ):
        raise DesignReleaseError(f"{role} design check/workflow/platform differs")
    for field in (
        "designRegistrationFileSHA256",
        "canonicalDesignSHA256",
        "modelAssetManifestFileSHA256",
        "knownAnswerSelectionSHA256",
        "knownAnswerDrawsSHA256",
    ):
        if (
            not isinstance(design_check.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", design_check[field]) is None
        ):
            raise DesignReleaseError(f"{role} design-check digest differs: {field}")

    member_records = tuple(
        _member_record(member_role, member_name, members[member_name])
        for member_role, member_name in names.items()
    )
    return CIArtifactVerification(
        role=role,
        release_name=ASSET_NAMES[role],
        github_actions_artifact_name=github_actions_artifact_name,
        platform=spec["platform"],
        system=spec["system"],
        machine=spec["machine"],
        archive_bytes=len(raw_zip),
        archive_sha256=archive_sha256,
        design_registration_file_sha256=design_sha256,
        runtime_manifest_content_sha256=runtime["contentSHA256"],
        workflow_file_bytes=registered_ci["workflowFileBytes"],
        workflow_file_sha256=registered_ci["workflowFileSHA256"],
        tests_run=tests_run,
        members=member_records,
    )


def _verify_content_digest(value: Mapping[str, Any], *, label: str) -> None:
    try:
        verify_content_digest(dict(value))
    except ValueError as error:
        raise DesignReleaseError(f"{label}: {error}") from error


def _parse_ssh_public_key(raw: bytes) -> tuple[str, str]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        raise DesignReleaseError(
            "SSH public key must be one OpenSSH line with exactly one terminal LF"
        )
    try:
        text = raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise DesignReleaseError("SSH public key must be ASCII") from error
    if not text or "\t" in text or "  " in text:
        raise DesignReleaseError("SSH public key spacing is not canonical")
    fields = text.split(" ", 2)
    if len(fields) not in {2, 3} or not fields[0] or not fields[1]:
        raise DesignReleaseError("SSH public key line is malformed")
    if len(fields) == 3 and not fields[2]:
        raise DesignReleaseError("SSH public key comment is empty")
    key_type, encoded = fields[:2]
    if not (
        key_type == "ssh-ed25519"
        or key_type == "ssh-rsa"
        or key_type.startswith("ecdsa-sha2-")
    ):
        raise DesignReleaseError("SSH public key algorithm is unsupported")
    try:
        blob = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise DesignReleaseError("SSH public key base64 is invalid") from error
    if base64.b64encode(blob).decode("ascii") != encoded or len(blob) < 5:
        raise DesignReleaseError("SSH public key blob is not canonical")
    type_length = int.from_bytes(blob[:4], "big")
    try:
        embedded_type = blob[4 : 4 + type_length].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise DesignReleaseError("SSH public key blob type is not ASCII") from error
    if type_length <= 0 or 4 + type_length > len(blob) or embedded_type != key_type:
        raise DesignReleaseError("SSH public key text/blob algorithms differ")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return "SHA256:" + fingerprint.rstrip("="), sha256_bytes(raw)


def _verify_release_signing_key(
    design: Mapping[str, Any], signing_key_raw: bytes
) -> tuple[str, str]:
    fingerprint, file_sha256 = _parse_ssh_public_key(signing_key_raw)
    identities: set[tuple[str, str]] = set()
    for field in (
        "designRelease",
        "snapshotRelease",
        "evidenceRelease",
        "closeoutRelease",
    ):
        release = design.get(field)
        if not isinstance(release, dict):
            raise DesignReleaseError(f"frozen {field} is missing")
        identity = (
            release.get("signingKeyFingerprint"),
            release.get("signingPublicKeySHA256"),
        )
        identities.add(identity)
        if release.get("signatureType") != "SSH" or identity != (
            fingerprint,
            file_sha256,
        ):
            raise DesignReleaseError(
                f"preregistered SSH key differs from frozen {field}"
            )
    if identities != {(fingerprint, file_sha256)}:
        raise DesignReleaseError("frozen release plans use different signing keys")
    return fingerprint, file_sha256


def _expected_asset_models(source: Mapping[str, Any]) -> dict[str, Any]:
    models = source.get("models")
    if not isinstance(models, dict):
        raise DesignReleaseError("asset-source manifest models are missing")
    result: dict[str, Any] = {}
    for model_key, model in models.items():
        if not isinstance(model, dict) or not isinstance(model.get("files"), dict):
            raise DesignReleaseError(f"asset-source model is invalid: {model_key}")
        result[model_key] = {
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
    return result


def _verify_bindings(
    paths: Mapping[str, Path],
    *,
    signing_public_key_path: Path,
    include_sha256_manifest: bool,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    expected_roles = set(ASSET_ROLES if include_sha256_manifest else MANIFEST_ROLES)
    if set(paths) != expected_roles:
        raise DesignReleaseError("design-release input roles differ")

    raw = {
        role: _read_unique_regular_path(
            path,
            label=role,
            maximum_bytes=(
                MAXIMUM_CI_ZIP_BYTES if role in CI_ARTIFACT_ROLES else MAXIMUM_JSON_BYTES
            ),
        )
        for role, path in paths.items()
    }
    design = _load_canonical_json(
        raw["design-registration"], label="frozen design registration"
    )
    try:
        validate_frozen_design_registration(design)
    except ValueError as error:
        raise DesignReleaseError("frozen design registration failed validation") from error

    try:
        freeze, freeze_raw = freeze_manifest.load_freeze_manifest(
            paths["freeze-manifest"]
        )
        if freeze_raw != raw["freeze-manifest"]:
            raise DesignReleaseError("freeze manifest changed while being verified")
        freeze_binding = freeze_manifest.verify_design_binding(
            freeze, freeze_raw, paths["design-registration"]
        )
    except freeze_manifest.FreezeManifestError as error:
        raise DesignReleaseError("freeze/design binding failed verification") from error

    runtime = _load_canonical_json(
        raw["runtime-manifest"], label="runtime manifest"
    )
    _verify_content_digest(runtime, label="runtime manifest")
    assets = _load_canonical_json(
        raw["full-asset-receipt"], label="full asset receipt"
    )
    _verify_content_digest(assets, label="full asset receipt")
    try:
        freeze_manifest._verify_runtime_receipt(
            runtime,
            implementation=freeze["implementation"],
            codec=freeze["codec"],
        )
        freeze_manifest._verify_asset_receipt(assets)
    except freeze_manifest.FreezeManifestError as error:
        raise DesignReleaseError("runtime/full-asset receipt failed validation") from error

    design_runtime = design.get("runtime")
    runtime_python = runtime.get("python")
    requirements_locks = runtime.get("requirementsLocks")
    if (
        not isinstance(design_runtime, dict)
        or not isinstance(runtime_python, dict)
        or runtime_python.get("registeredVersion") != design_runtime.get("python")
        or runtime_python.get("version") != design_runtime.get("python")
        or not isinstance(requirements_locks, list)
        or sum(
            1
            for item in requirements_locks
            if isinstance(item, dict)
            and item.get("name") == "requirements.lock"
            and item.get("sha256") == design_runtime.get("requirementsLockSHA256")
        )
        != 1
    ):
        raise DesignReleaseError(
            "runtime Python/requirements lock differs from frozen design"
        )

    commitments = freeze["artifacts"]
    if sha256_bytes(raw["runtime-manifest"]) != commitments["runtimeManifestSHA256"]:
        raise DesignReleaseError("runtime manifest differs from freeze commitment")
    if sha256_bytes(raw["full-asset-receipt"]) != commitments[
        "fullAssetReceiptSHA256"
    ]:
        raise DesignReleaseError("full asset receipt differs from freeze commitment")

    try:
        development = freeze_manifest.verify_development_control_report(
            paths["development-control-report"],
            completed_no_later_than=freeze_manifest.DESIGN_PUBLISH_DEADLINE,
            require_artifacts=False,
        )
    except freeze_manifest.FreezeManifestError as error:
        raise DesignReleaseError(
            "development-control report failed canonical verification"
        ) from error
    if (
        development["reportFileSHA256"]
        != commitments["developmentControlReportSHA256"]
        or development["artifactSetSHA256"]
        != commitments["developmentControlArtifactSetSHA256"]
        or development["controlConfigurationSHA256"]
        != commitments["developmentControlConfigurationSHA256"]
        or development["completedAt"]
        != freeze["developmentControl"]["completedAt"]
    ):
        raise DesignReleaseError(
            "development-control report differs from freeze commitment"
        )
    archive_receipt = _load_canonical_json(
        raw["development-control-archive-receipt"],
        label="development-control archive release receipt",
    )
    archive_source = archive_receipt.get("source")
    archive_release = archive_receipt.get("release")
    if (
        archive_receipt.get("schemaVersion") != "corelm-github-release-receipt-v2"
        or archive_receipt.get("suiteId") != SUITE_ID
        or archive_receipt.get("kind") != "development-control"
        or archive_receipt.get("tag")
        != freeze_manifest.DEVELOPMENT_ARCHIVE_TAG
        or not isinstance(archive_source, dict)
        or archive_source.get("commit") != freeze["implementation"]["commit"]
        or archive_source.get("tree") != freeze["implementation"]["tree"]
        or not isinstance(archive_release, dict)
        or archive_release.get("publishedAt")
        != freeze["developmentControl"]["archivePublishedAt"]
        or archive_release.get("deadline") != "2026-08-09T00:00:00Z"
        or sha256_bytes(raw["development-control-archive-receipt"])
        != commitments["developmentControlArchiveReceiptSHA256"]
    ):
        raise DesignReleaseError(
            "development-control archive receipt differs from freeze commitment"
        )
    _verify_content_digest(
        archive_receipt, label="development-control archive release receipt"
    )

    try:
        verified_gate, gate_raw = freeze_manifest._verify_github_gate_input(
            paths["github-gate-receipt"],
            implementation=freeze["implementation"],
        )
    except freeze_manifest.FreezeManifestError as error:
        raise DesignReleaseError("GitHub gate receipt failed offline verification") from error
    if gate_raw != raw["github-gate-receipt"]:
        raise DesignReleaseError("GitHub gate receipt changed while being verified")
    expected_review, expected_ci = freeze_manifest._gate_manifest_sections(
        verified_gate,
        implementation_repository=freeze["implementation"]["repository"],
    )
    if freeze["review"] != expected_review:
        raise DesignReleaseError("freeze review differs from GitHub gate receipt")
    if freeze["continuousIntegration"] != expected_ci:
        raise DesignReleaseError("freeze CI differs from GitHub gate receipt")
    if sha256_bytes(gate_raw) != commitments["githubGateReceiptSHA256"]:
        raise DesignReleaseError("GitHub gate receipt differs from freeze commitment")

    try:
        gate_artifacts = canonical_ci_artifact_commitments(
            verified_gate.artifact_sha256,
            run_id=verified_gate.workflow_run_id,
        )
    except ValueError as error:
        raise DesignReleaseError(
            "GitHub gate CI artifact commitments differ"
        ) from error
    ci_verifications = tuple(
        _verify_ci_artifact_payload(
            role=role,
            raw_zip=raw[role],
            github_actions_artifact_name=artifact[0],
            expected_archive_sha256=artifact[1],
            workflow_run_id=verified_gate.workflow_run_id,
            design=design,
            freeze=freeze,
        )
        for role, artifact in zip(CI_ARTIFACT_ROLES, gate_artifacts)
    )
    if (
        len({item.design_registration_file_sha256 for item in ci_verifications}) != 1
        or len({item.workflow_file_sha256 for item in ci_verifications}) != 1
        or len({item.workflow_file_bytes for item in ci_verifications}) != 1
        or len({item.tests_run for item in ci_verifications}) != 1
    ):
        raise DesignReleaseError(
            "Linux/macOS CI payloads do not prove the same design/workflow/test suite"
        )

    source = _load_json(
        raw["asset-source-manifest"], label="tracked asset-source manifest"
    )
    try:
        validate_model_asset_manifest(source, dict(design))
    except ValueError as error:
        raise DesignReleaseError(
            "tracked asset-source manifest differs from frozen design"
        ) from error
    if (
        assets.get("manifestFile") != TRACKED_ASSET_SOURCE_NAME
        or assets.get("manifestFileBytes") != len(raw["asset-source-manifest"])
        or assets.get("manifestFileSHA256")
        != sha256_bytes(raw["asset-source-manifest"])
        or assets.get("manifestSchemaVersion") != source.get("schemaVersion")
        or assets.get("manifestDeclaredStatus") != source.get("status")
        or assets.get("manifestDeclaredFullSafetensorsBytesLocallyVerified")
        != source.get("fullSafetensorsBytesLocallyVerified")
    ):
        raise DesignReleaseError(
            "full asset receipt does not bind the exact tracked source manifest"
        )
    if assets.get("models") != _expected_asset_models(source):
        raise DesignReleaseError(
            "full asset receipt model/file commitments differ from source manifest"
        )

    sbom = _load_canonical_json(raw["sbom"], label="CycloneDX SBOM")
    try:
        expected_sbom = build_sbom(dict(runtime), dict(assets))
    except (KeyError, TypeError, ValueError) as error:
        raise DesignReleaseError("bound runtime/assets cannot produce the SBOM") from error
    if sbom != expected_sbom:
        raise DesignReleaseError("SBOM differs from bound runtime and asset receipts")

    signing_key_raw = _read_unique_regular_path(
        signing_public_key_path,
        label="preregistered SSH public key",
        maximum_bytes=MAXIMUM_KEY_BYTES,
    )
    fingerprint, public_key_sha256 = _verify_release_signing_key(
        design, signing_key_raw
    )

    if include_sha256_manifest:
        sha_manifest = _load_canonical_json(
            raw["sha256-manifest"], label="design-release SHA-256 manifest"
        )
        _verify_sha256_manifest(sha_manifest, raw)

    report = {
        "implementationCommit": freeze_binding["implementationCommit"],
        "implementationTree": freeze_binding["implementationTree"],
        "freezeManifestSHA256": sha256_bytes(freeze_raw),
        "runtimeManifestSHA256": sha256_bytes(raw["runtime-manifest"]),
        "fullAssetReceiptSHA256": sha256_bytes(raw["full-asset-receipt"]),
        "githubGateReceiptSHA256": sha256_bytes(gate_raw),
        "developmentControlReportSHA256": development["reportFileSHA256"],
        "developmentControlArchiveReceiptSHA256": sha256_bytes(
            raw["development-control-archive-receipt"]
        ),
        "developmentControlArtifactSetSHA256": development["artifactSetSHA256"],
        "developmentControlConfigurationSHA256": development[
            "controlConfigurationSHA256"
        ],
        "ciArtifacts": ci_verifications,
        "signingKeyFingerprint": fingerprint,
        "signingPublicKeySHA256": public_key_sha256,
    }
    return raw, report


def _asset_record(role: str, raw: bytes) -> AssetRecord:
    return AssetRecord(
        role=role,
        name=ASSET_NAMES[role],
        bytes=len(raw),
        sha256=sha256_bytes(raw),
    )


def _build_sha256_manifest(raw: Mapping[str, bytes]) -> bytes:
    if set(raw) != set(MANIFEST_ROLES):
        raise DesignReleaseError("SHA-256 manifest inputs differ")
    payload = {
        "schemaVersion": SHA256_MANIFEST_SCHEMA,
        "suiteId": SUITE_ID,
        "status": "COMPLETE_DESIGN_RELEASE_ASSET_INVENTORY",
        "countsTowardScientificVerdict": False,
        "releaseAssetRoles": list(ASSET_ROLES),
        "manifestAssetRoles": list(MANIFEST_ROLES),
        "assetCount": len(MANIFEST_ROLES),
        "releaseAssetCount": len(ASSET_ROLES),
        "excludedRole": "sha256-manifest",
        "selfReferencePolicy": (
            "SHA256_MANIFEST_EXCLUDED_FROM_OWN_FILE_HASH_LIST_AND_BOUND_BY_"
            "GITHUB_RELEASE_ATTESTATION"
        ),
        "assets": [_asset_record(role, raw[role]).as_dict() for role in MANIFEST_ROLES],
    }
    return canonical_json_bytes(with_content_digest(payload)) + b"\n"


def _verify_sha256_manifest(
    manifest: Mapping[str, Any], raw: Mapping[str, bytes]
) -> None:
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "status",
        "countsTowardScientificVerdict",
        "releaseAssetRoles",
        "manifestAssetRoles",
        "assetCount",
        "releaseAssetCount",
        "excludedRole",
        "selfReferencePolicy",
        "assets",
        "contentSHA256",
    }
    if set(manifest) != expected_fields:
        raise DesignReleaseError("SHA-256 manifest fields differ")
    if (
        manifest.get("schemaVersion") != SHA256_MANIFEST_SCHEMA
        or manifest.get("suiteId") != SUITE_ID
        or manifest.get("status") != "COMPLETE_DESIGN_RELEASE_ASSET_INVENTORY"
        or manifest.get("countsTowardScientificVerdict") is not False
        or manifest.get("releaseAssetRoles") != list(ASSET_ROLES)
        or manifest.get("manifestAssetRoles") != list(MANIFEST_ROLES)
        or manifest.get("assetCount") != len(MANIFEST_ROLES)
        or manifest.get("releaseAssetCount") != len(ASSET_ROLES)
        or manifest.get("excludedRole") != "sha256-manifest"
        or manifest.get("selfReferencePolicy")
        != (
            "SHA256_MANIFEST_EXCLUDED_FROM_OWN_FILE_HASH_LIST_AND_BOUND_BY_"
            "GITHUB_RELEASE_ATTESTATION"
        )
    ):
        raise DesignReleaseError("SHA-256 manifest contract differs")
    _verify_content_digest(manifest, label="SHA-256 manifest")
    expected_assets = [
        _asset_record(role, raw[role]).as_dict() for role in MANIFEST_ROLES
    ]
    if manifest.get("assets") != expected_assets:
        raise DesignReleaseError("SHA-256 manifest file inventory differs")


def _scan_asset_root(asset_root: Path) -> tuple[Path, dict[str, Path]]:
    absolute, descriptor = _open_directory_no_symlinks(
        asset_root, label="design-release asset root"
    )
    try:
        root_metadata = os.fstat(descriptor)
        if root_metadata.st_mode & 0o222:
            raise DesignReleaseError("design-release asset root must be read-only")
        try:
            names = sorted(os.listdir(descriptor), key=os.fsencode)
        except OSError as error:
            raise DesignReleaseError("cannot inventory design-release asset root") from error
        expected_names = sorted(ASSET_NAMES.values(), key=os.fsencode)
        if names != expected_names:
            raise DesignReleaseError(
                "design-release root must contain exactly the twelve required assets"
            )
        identities: set[tuple[int, int]] = set()
        paths: dict[str, Path] = {}
        role_for_name = {name: role for role, name in ASSET_NAMES.items()}
        for name in names:
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise DesignReleaseError(f"cannot stat design-release asset: {name}") from error
            if not stat.S_ISREG(metadata.st_mode):
                raise DesignReleaseError(
                    f"design-release asset is a symlink or special file: {name}"
                )
            if metadata.st_nlink != 1:
                raise DesignReleaseError(f"design-release asset is hard-linked: {name}")
            if metadata.st_mode & 0o222:
                raise DesignReleaseError(f"design-release asset is writable: {name}")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise DesignReleaseError(f"design-release asset inode is reused: {name}")
            identities.add(identity)
            paths[role_for_name[name]] = absolute / name
        return absolute, paths
    finally:
        os.close(descriptor)


def verify_design_release_package(
    asset_root: Path,
    *,
    signing_public_key_path: Path,
) -> DesignReleaseVerification:
    """Independently re-open and verify one completed offline package."""

    absolute, paths = _scan_asset_root(asset_root)
    raw, report = _verify_bindings(
        paths,
        signing_public_key_path=signing_public_key_path,
        include_sha256_manifest=True,
    )
    records = tuple(_asset_record(role, raw[role]) for role in ASSET_ROLES)
    return DesignReleaseVerification(
        asset_root=absolute,
        implementation_commit=report["implementationCommit"],
        implementation_tree=report["implementationTree"],
        freeze_manifest_sha256=report["freezeManifestSHA256"],
        runtime_manifest_sha256=report["runtimeManifestSHA256"],
        full_asset_receipt_sha256=report["fullAssetReceiptSHA256"],
        github_gate_receipt_sha256=report["githubGateReceiptSHA256"],
        development_control_report_sha256=report[
            "developmentControlReportSHA256"
        ],
        development_control_archive_receipt_sha256=report[
            "developmentControlArchiveReceiptSHA256"
        ],
        development_control_artifact_set_sha256=report[
            "developmentControlArtifactSetSHA256"
        ],
        development_control_configuration_sha256=report[
            "developmentControlConfigurationSHA256"
        ],
        signing_key_fingerprint=report["signingKeyFingerprint"],
        signing_public_key_sha256=report["signingPublicKeySHA256"],
        ci_artifacts=report["ciArtifacts"],
        assets=records,
    )


def _write_new_read_only_file(
    root_descriptor: int, name: str, value: bytes
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=root_descriptor)
    published = False
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing design-release asset")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_nlink != 1
            or metadata.st_size != len(value)
        ):
            raise DesignReleaseError(f"published asset metadata differs: {name}")
        os.fsync(descriptor)
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                os.unlink(name, dir_fd=root_descriptor)
            except FileNotFoundError:
                pass


def _cleanup_owned_output(output: Path, names: Sequence[str]) -> None:
    """Remove only names this invocation owns; never recurse through unknown data."""

    try:
        metadata = os.lstat(output)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return
    try:
        os.chmod(output, 0o700, follow_symlinks=False)
        descriptor = os.open(output, _directory_flags())
    except OSError:
        return
    try:
        for name in names:
            try:
                member = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(member.st_mode) and member.st_nlink == 1:
                try:
                    os.unlink(name, dir_fd=descriptor)
                except OSError:
                    pass
    finally:
        os.close(descriptor)
    try:
        os.rmdir(output)
    except OSError:
        pass


def package_design_release(
    *,
    frozen_design_path: Path,
    development_control_report_path: Path,
    development_control_archive_receipt_path: Path,
    freeze_manifest_path: Path,
    github_gate_receipt_path: Path,
    linux_ci_artifact_path: Path,
    macos_arm64_ci_artifact_path: Path,
    asset_source_manifest_path: Path,
    full_asset_receipt_path: Path,
    runtime_manifest_path: Path,
    sbom_path: Path,
    signing_public_key_path: Path,
    output_root: Path,
) -> DesignReleaseVerification:
    """Validate all inputs, durably create twelve assets, then re-verify them."""

    if tuple(REQUIRED_ASSET_ROLES.get("design", ())) != ASSET_ROLES:
        raise DesignReleaseError(
            "release_receipt design roles differ from this packager contract"
        )
    input_paths = {
        "asset-source-manifest": asset_source_manifest_path,
        "design-registration": frozen_design_path,
        "development-control-report": development_control_report_path,
        "development-control-archive-receipt": (
            development_control_archive_receipt_path
        ),
        "freeze-manifest": freeze_manifest_path,
        "full-asset-receipt": full_asset_receipt_path,
        "github-gate-receipt": github_gate_receipt_path,
        "linux-ci-artifact": linux_ci_artifact_path,
        "macos-arm64-ci-artifact": macos_arm64_ci_artifact_path,
        "runtime-manifest": runtime_manifest_path,
        "sbom": sbom_path,
    }
    raw, _report = _verify_bindings(
        input_paths,
        signing_public_key_path=signing_public_key_path,
        include_sha256_manifest=False,
    )
    raw["sha256-manifest"] = _build_sha256_manifest(raw)

    output = _absolute_without_resolving(output_root)
    _parent, parent_descriptor = _open_directory_no_symlinks(
        output.parent, label="output parent"
    )
    created = False
    root_descriptor = -1
    written_names: list[str] = []
    try:
        try:
            os.mkdir(output.name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise DesignReleaseError("output root already exists; overwrite is forbidden") from error
        except OSError as error:
            raise DesignReleaseError("cannot create design-release output root") from error
        created = True
        os.fsync(parent_descriptor)
        root_descriptor = os.open(output.name, _directory_flags(), dir_fd=parent_descriptor)
        for role in ASSET_ROLES:
            name = ASSET_NAMES[role]
            _write_new_read_only_file(root_descriptor, name, raw[role])
            written_names.append(name)
        os.fsync(root_descriptor)
        os.fchmod(root_descriptor, 0o555)
        os.fsync(root_descriptor)
        os.fsync(parent_descriptor)
    except Exception:
        if root_descriptor >= 0:
            os.close(root_descriptor)
            root_descriptor = -1
        if created:
            _cleanup_owned_output(output, written_names)
            try:
                os.fsync(parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)

    try:
        return verify_design_release_package(
            output,
            signing_public_key_path=signing_public_key_path,
        )
    except Exception:
        _cleanup_owned_output(output, ASSET_NAMES.values())
        raise


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    package = subparsers.add_parser("package", help="create twelve release assets")
    package.add_argument("--frozen-design", type=Path, required=True)
    package.add_argument("--development-control-report", type=Path, required=True)
    package.add_argument(
        "--development-control-archive-receipt", type=Path, required=True
    )
    package.add_argument("--freeze-manifest", type=Path, required=True)
    package.add_argument("--github-gate-receipt", type=Path, required=True)
    package.add_argument("--linux-ci-artifact", type=Path, required=True)
    package.add_argument("--macos-arm64-ci-artifact", type=Path, required=True)
    package.add_argument("--asset-source-manifest", type=Path, required=True)
    package.add_argument("--full-asset-receipt", type=Path, required=True)
    package.add_argument("--runtime-manifest", type=Path, required=True)
    package.add_argument("--sbom", type=Path, required=True)
    package.add_argument("--signing-public-key", type=Path, required=True)
    package.add_argument("--output-root", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="re-open an existing package")
    verify.add_argument("--asset-root", type=Path, required=True)
    verify.add_argument("--signing-public-key", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "package":
            report = package_design_release(
                frozen_design_path=arguments.frozen_design,
                development_control_report_path=arguments.development_control_report,
                development_control_archive_receipt_path=(
                    arguments.development_control_archive_receipt
                ),
                freeze_manifest_path=arguments.freeze_manifest,
                github_gate_receipt_path=arguments.github_gate_receipt,
                linux_ci_artifact_path=arguments.linux_ci_artifact,
                macos_arm64_ci_artifact_path=arguments.macos_arm64_ci_artifact,
                asset_source_manifest_path=arguments.asset_source_manifest,
                full_asset_receipt_path=arguments.full_asset_receipt,
                runtime_manifest_path=arguments.runtime_manifest,
                sbom_path=arguments.sbom,
                signing_public_key_path=arguments.signing_public_key,
                output_root=arguments.output_root,
            )
        else:
            report = verify_design_release_package(
                arguments.asset_root,
                signing_public_key_path=arguments.signing_public_key,
            )
    except (DesignReleaseError, OSError, ValueError, KeyError) as error:
        print(f"DESIGN RELEASE FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
