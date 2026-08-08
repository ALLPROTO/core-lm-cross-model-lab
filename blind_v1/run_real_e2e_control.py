#!/usr/bin/env python3
"""Run the fixed, non-scientific real-data candidate/replay E2E control.

The only variable command-line values are locations of already committed
inputs and a new output directory.  Models, candidate, page count, partition
rule, metrics, and thresholds cannot be selected from the command line.  This
control consumes the exact pinned UD English PUD r2.18 CoNLL-U corpus and the
exact three registered model snapshots, produces real VTL5 evidence with the ordinary
model worker, and verifies it in a separate independent real-model process.

It is deliberately incompatible with the scientific attempt state machine:
it has a distinct suite/job/report identity, never reads NIST or future-corpus
inputs, never creates a reservation/marker, never writes ``blind_v1/results``, never
applies scientific thresholds, and cannot count toward the scientific verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.create_asset_receipt import (  # noqa: E402
    _historical_build_asset_receipt,
)
from blind_v1.development_model_replay import (  # noqa: E402
    CANDIDATE,
    CORPORA,
    DATASET_BYTES,
    DATASET_EVIDENCE_PATH,
    DATASET_SHA256,
    DevelopmentReplayError,
    JOB_SCHEMA,
    MODELS,
    MODEL_FILES,
    PLAN_SCHEMA,
    SUMMARY_SCHEMA as REPLAY_SUMMARY_SCHEMA,
    SUITE_ID,
    expected_job,
    validate_plan,
)
from blind_v1.development_runtime import (  # noqa: E402
    DevelopmentRuntimeError,
    closed_environment,
    consolidate_worker_evidence,
    networkless_macos_command,
    process_group_usage,
    python_command,
    terminate_process_group,
    verify_active_python_startup,
    verify_python_subprocess,
    verify_runtime_live,
    wait_for_primary_host_safety,
)
from blind_v1.development_corpus import (  # noqa: E402
    DATASET_ID,
    SENTENCE_COUNT,
    SOURCE_BYTES,
    SOURCE_SHA256,
    joined_text,
    parse_corpus,
    partition_bounds,
    serialize_record,
    verify_rights_evidence,
)
from blind_v1.freeze_manifest import (  # noqa: E402
    FreezeManifestError,
    validate_development_control_report,
)
from blind_v1.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict,
    load_json_strict_bytes,
    require_scientific_schedule_open,
    sha256_bytes,
    validate_development_model_asset_manifest,
    validate_design_registration,
    EXPECTED_DEVELOPMENT_CONTROLS,
)
from blind_v1.reproducibility import (  # noqa: E402
    verify_content_digest,
    verify_runtime_manifest_integrity,
    write_new_bytes,
)


REPORT_SCHEMA = "corelm-blind-crossmodel-v1-real-e2e-development-report-v1"
POST_RELEASE_REPORT_SCHEMA = (
    "corelm-blind-crossmodel-v1-real-e2e-post-release-regression-report-v1"
)
POST_RELEASE_PROFILE = "POST_RELEASE_DEVELOPMENT_REGRESSION"
DEVELOPMENT_RELEASE_TAG = "corelm-blind-crossmodel-v1-development-control"
LAB_REPOSITORY = "https://github.com/ALLPROTO/core-lm-cross-model-lab.git"
LAB_ALLOWED_IGNORED_ROOTS = (
    PurePosixPath("blind_v1/.assets"),
    PurePosixPath("blind_v1/.runtime"),
    PurePosixPath("blind_v1/.working"),
)
SIGNING_PUBLIC_KEY_SHA256 = (
    "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274"
)
ALLOWED_SIGNERS_SHA256 = (
    "36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16"
)
SIGNING_KEY_FINGERPRINT = "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM"
WORKER_SUMMARY_SCHEMA = (
    "corelm-blind-crossmodel-v1-real-e2e-development-worker-summary-v1"
)
SUPERVISOR_SCHEMA = (
    "corelm-blind-crossmodel-v1-real-e2e-development-supervisor-receipt-v1"
)
FULL_ASSET_RECEIPT_ARCHIVE_NAME = "development-model-assets.full-rehash.json"
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
PARTITIONS = 32
DEVELOPMENT_COMPLETE_NO_LATER_THAN = datetime(
    2026, 8, 9, 0, 0, 0, tzinfo=timezone.utc
)
ADAPTER = {
    "source": "pinned-ud-english-pud-r2.18-test-conllu",
    "sentenceText": "exact-single-#-text-comment-per-block",
    "join": "two-LF-between-sentence-texts-within-each-slice",
    "partition": "all-source-sentences-equal-floor-boundaries-32",
    "partitions": PARTITIONS,
    "records": PARTITIONS,
    "contentSynthetic": False,
    "metadataEnvelopeScientificUse": "forbidden",
}
CONTROL_SOURCE_PATHS = (
    "blind_v1/run_real_e2e_control.py",
    "blind_v1/development_model_replay.py",
    "blind_v1/development_corpus.py",
    "blind_v1/development_runtime.py",
    "blind_v1/development_artifact_verifier.py",
    "blind_v1/freeze_manifest.py",
    "blind_v1/model_worker.py",
    "blind_v1/independent_model_replay.py",
    "blind_v1/cache_adapter.py",
    "blind_v1/evidence.py",
    "blind_v1/mediawiki_snapshot.py",
    "blind_v1/protocol.py",
    "blind_v1/reproducibility.py",
    "blind_v1/create_asset_receipt.py",
    "blind_v1/preflight.py",
    "blind_v1/fetch_assets.py",
)


class DevelopmentControlError(RuntimeError):
    """Raised before a development control can be mistaken for evidence."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def verify_development_lifecycle(
    design: Mapping[str, Any],
    *,
    now: datetime | None = None,
    allow_after_cutoff_for_post_release_regression: bool = False,
) -> None:
    controls = design.get("developmentControls")
    gate = controls.get("realDataE2EFreezeGate") if isinstance(controls, dict) else None
    lab = design.get("labSource")
    blockers = design.get("freezeBlockers")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() != timezone.utc.utcoffset(current):
        raise DevelopmentControlError("development lifecycle clock must be UTC")
    if (
        design.get("schemaVersion")
        != "corelm-blind-crossmodel-v1-design-draft-v1"
        or design.get("status") != "DRAFT_NOT_PREREGISTERED"
        or design.get("readyToFreeze") is not False
        or not isinstance(lab, dict)
        or lab.get("status") != "UNBOUND_DRAFT"
        or lab.get("commit") is not None
        or lab.get("tree") is not None
        or not isinstance(controls, dict)
        or controls.get("status") != "NON_SCIENTIFIC_PRE_FREEZE_ONLY"
        or not isinstance(gate, dict)
        or gate.get("required") is not True
        or gate.get("status") != "UNBOUND_DRAFT"
        or gate.get("completeNoLaterThan")
        != DEVELOPMENT_COMPLETE_NO_LATER_THAN.strftime("%Y-%m-%dT%H:%M:%SZ")
        or gate.get("serverTimestampedArchiveRequired") is not True
        or any(
            gate.get(field) is not None
            for field in (
                "executionId",
                "archiveReceiptSHA256",
                "archivePublishedAt",
                "reportSHA256",
                "artifactSetSHA256",
                "controlConfigurationSHA256",
                "completedAt",
            )
        )
        or not isinstance(blockers, list)
        or not any(
            isinstance(value, str)
            and "real UD English PUD" in value
            and "development control" in value
            for value in blockers
        )
    ):
        raise DevelopmentControlError(
            "real E2E control is permitted only on the unbound pre-freeze draft"
        )
    if type(allow_after_cutoff_for_post_release_regression) is not bool:
        raise DevelopmentControlError("development lifecycle profile is invalid")
    if (
        current >= DEVELOPMENT_COMPLETE_NO_LATER_THAN
        and not allow_after_cutoff_for_post_release_regression
    ):
        raise DevelopmentControlError("real E2E development cutoff has passed")


def _digest_bytes(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": sha256_bytes(raw)}


def _read_regular(
    path: Path,
    *,
    maximum_bytes: int,
    expected_executable: bool | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DevelopmentControlError(f"cannot open fixed input: {path.name}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum_bytes:
            raise DevelopmentControlError(f"fixed input is not a bounded regular file: {path.name}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            value = os.read(descriptor, min(1024 * 1024, remaining))
            if not value:
                raise DevelopmentControlError(f"fixed input ended early: {path.name}")
            chunks.append(value)
            remaining -= len(value)
        if os.read(descriptor, 1):
            raise DevelopmentControlError(f"fixed input grew while read: {path.name}")
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )
        if identity(after) != identity(metadata):
            raise DevelopmentControlError(f"fixed input changed while read: {path.name}")
        if (
            expected_executable is not None
            and bool(metadata.st_mode & stat.S_IXUSR) != expected_executable
        ):
            raise DevelopmentControlError("tracked file mode differs from HEAD")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _stream_regular_commitment(
    path: Path, *, exact_bytes: int
) -> dict[str, Any]:
    """Hash one exact-size regular file without retaining its bytes in RAM."""

    if type(exact_bytes) is not int or exact_bytes <= 0:
        raise DevelopmentControlError("fixed input exact byte bound is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DevelopmentControlError(f"cannot open fixed input: {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != exact_bytes:
            raise DevelopmentControlError(
                f"fixed input does not match its exact byte bound: {path.name}"
            )
        digest = hashlib.sha256()
        observed = 0
        while observed < exact_bytes:
            value = os.read(descriptor, min(1024 * 1024, exact_bytes - observed))
            if not value:
                raise DevelopmentControlError(f"fixed input ended early: {path.name}")
            digest.update(value)
            observed += len(value)
        if os.read(descriptor, 1):
            raise DevelopmentControlError(f"fixed input grew while read: {path.name}")
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )
        if identity(after) != identity(before) or observed != exact_bytes:
            raise DevelopmentControlError(f"fixed input changed while read: {path.name}")
        return {"bytes": observed, "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def _canonical_document(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise DevelopmentControlError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise DevelopmentControlError(f"{label} is not a JSON object")
    return value


def _external_output_path(output: Path) -> tuple[Path, str]:
    if not isinstance(output, Path) or output.name in {"", ".", ".."}:
        raise DevelopmentControlError("development output path is invalid")
    try:
        parent = output.parent.resolve(strict=True)
        project = PROJECT_ROOT.resolve(strict=True)
    except OSError as error:
        raise DevelopmentControlError("development output parent must already exist") from error
    candidate = parent / output.name
    if parent == project or parent.is_relative_to(project):
        raise DevelopmentControlError(
            "development output must be outside the repository and blind_v1/results"
        )
    if any(part.endswith(".one-shot-result") for part in candidate.parts):
        raise DevelopmentControlError(
            "development output must not occupy a scientific one-shot result namespace"
        )
    if candidate.exists() or candidate.is_symlink():
        raise DevelopmentControlError("development output already exists")
    if not parent.is_dir() or parent.is_symlink():
        raise DevelopmentControlError("development output parent is unsafe")
    return parent, output.name


def claim_output(output: Path) -> Path:
    """Exclusively claim a new external output root; never replace an old run."""

    require_scientific_schedule_open(operation="claim Blind V1 development output")
    return _historical_claim_output(output)


def _historical_claim_output(output: Path) -> Path:
    """Retain exclusive output creation for post-release regression runs."""

    parent, name = _external_output_path(output)
    descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.mkdir(name, mode=0o700, dir_fd=descriptor)
        os.fsync(descriptor)
    except FileExistsError as error:
        raise DevelopmentControlError("development output already exists") from error
    finally:
        os.close(descriptor)
    return parent / name


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git_bytes(
    root: Path,
    arguments: list[str],
    *,
    maximum_bytes: int = 16 * 1024 * 1024,
    allow_missing_config: bool = False,
) -> bytes:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(root),
            "-c",
            f"core.worktree={root}",
            "-c",
            "core.bare=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.ignoreStat=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
        env=_git_environment(),
    )
    if (
        allow_missing_config
        and completed.returncode == 1
        and not completed.stderr
    ):
        return b""
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > maximum_bytes
    ):
        raise DevelopmentControlError("Git source identity cannot be verified")
    return completed.stdout


def _git_output(root: Path, arguments: list[str]) -> str:
    raw = _git_bytes(root, arguments)
    try:
        value = raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise DevelopmentControlError("Git source identity is not UTF-8") from error
    if "\x00" in value:
        raise DevelopmentControlError("Git source identity contains NUL")
    return value


def _verify_repository_layout(root: Path, *, label: str) -> None:
    try:
        resolved_root = root.resolve(strict=True)
        dot_git_path = root / ".git"
        dot_git_metadata = dot_git_path.lstat()
        dot_git = dot_git_path.resolve(strict=True)
    except OSError as error:
        raise DevelopmentControlError(f"{label} repository layout is unavailable") from error
    local_config = _git_bytes(
        root, ["config", "--local", "--name-only", "--list", "-z"]
    )
    if local_config and not local_config.endswith(b"\x00"):
        raise DevelopmentControlError(f"{label} local Git configuration is invalid")
    try:
        local_names = {
            name.decode("utf-8", errors="strict").casefold()
            for name in local_config[:-1].split(b"\x00")
            if name
        }
    except UnicodeDecodeError as error:
        raise DevelopmentControlError(
            f"{label} local Git configuration is invalid"
        ) from error
    forbidden_names = {
        "core.attributesfile",
        "core.excludesfile",
        "core.worktree",
        "extensions.worktreeconfig",
    }
    if local_names & forbidden_names or any(
        name.startswith("filter.") for name in local_names
    ):
        raise DevelopmentControlError(
            f"{label} repository has forbidden local path or filter configuration"
        )
    try:
        top = Path(_git_output(root, ["rev-parse", "--show-toplevel"])).resolve(
            strict=True
        )
        git_dir = Path(
            _git_output(root, ["rev-parse", "--absolute-git-dir"])
        ).resolve(strict=True)
        common_dir = Path(
            _git_output(
                root,
                ["rev-parse", "--path-format=absolute", "--git-common-dir"],
            )
        ).resolve(strict=True)
    except OSError as error:
        raise DevelopmentControlError(f"{label} repository layout is unavailable") from error
    if (
        resolved_root != root
        or not stat.S_ISDIR(dot_git_metadata.st_mode)
        or stat.S_ISLNK(dot_git_metadata.st_mode)
        or top != root
        or git_dir != dot_git
        or common_dir != dot_git
    ):
        raise DevelopmentControlError(
            f"{label} repository is not a standalone physical checkout"
        )
    exclude_path = dot_git / "info" / "exclude"
    if exclude_path.exists() or exclude_path.is_symlink():
        raw = _read_regular(exclude_path, maximum_bytes=64 * 1024)
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise DevelopmentControlError(
                f"{label} local exclude policy is invalid"
            ) from error
        if any(line.strip() and not line.lstrip().startswith("#") for line in lines):
            raise DevelopmentControlError(
                f"{label} repository has local exclude patterns"
            )
    attributes_path = dot_git / "info" / "attributes"
    if attributes_path.exists() or attributes_path.is_symlink():
        raise DevelopmentControlError(
            f"{label} repository has local Git attributes"
        )


def _verify_isolated_pycache_prefix() -> Path:
    raw = sys.pycache_prefix
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise DevelopmentControlError(
            "post-release runner requires an explicit empty pycache prefix"
        )
    candidate = Path(os.path.abspath(raw))
    if (
        raw != str(candidate)
        or candidate == PROJECT_ROOT
        or PROJECT_ROOT in candidate.parents
    ):
        raise DevelopmentControlError(
            "post-release pycache prefix must be normalized and outside the repository"
        )
    try:
        metadata = candidate.lstat()
        entries = tuple(candidate.iterdir())
    except OSError as error:
        raise DevelopmentControlError(
            "post-release pycache prefix cannot be inspected"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or entries:
        raise DevelopmentControlError(
            "post-release pycache prefix must be an empty real directory"
        )
    return candidate


def _verify_clean_checkout(
    root: Path,
    *,
    label: str,
    allowed_ignored_roots: tuple[PurePosixPath, ...] = (),
) -> None:
    _verify_repository_layout(root, label=label)
    replacement_refs = _git_bytes(
        root, ["for-each-ref", "--format=%(refname)", "refs/replace"]
    )
    if replacement_refs:
        raise DevelopmentControlError(f"{label} repository has replacement refs")
    graft_path_raw = _git_bytes(
        root, ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"]
    )
    try:
        graft_path = Path(graft_path_raw.decode("utf-8", errors="strict").strip())
    except UnicodeDecodeError as error:
        raise DevelopmentControlError(f"{label} graft path is invalid") from error
    if graft_path.exists() or graft_path.is_symlink():
        raise DevelopmentControlError(f"{label} repository has a grafts file")
    index_entries = _git_bytes(root, ["ls-files", "-v", "-z"])
    if index_entries and (
        not index_entries.endswith(b"\x00")
        or any(
            len(entry) < 3 or entry[:2] != b"H "
            for entry in index_entries[:-1].split(b"\x00")
        )
    ):
        raise DevelopmentControlError(
            f"{label} index has non-canonical tracked flags or state"
        )
    status = _git_bytes(
        root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    if status:
        raise DevelopmentControlError(f"{label} worktree is not clean")
    ignored = _git_bytes(
        root,
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
    )
    if ignored:
        if not ignored.endswith(b"\x00"):
            raise DevelopmentControlError(
                f"{label} repository contains invalid ignored untracked paths"
            )
        observed_roots: set[PurePosixPath] = set()
        for raw_path in ignored[:-1].split(b"\x00"):
            try:
                relative = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise DevelopmentControlError(
                    f"{label} repository contains invalid ignored untracked paths"
                ) from error
            pure = PurePosixPath(relative)
            matching_roots = tuple(
                allowed
                for allowed in allowed_ignored_roots
                if pure != allowed and allowed in pure.parents
            )
            if (
                not raw_path
                or pure.is_absolute()
                or ".." in pure.parts
                or len(matching_roots) != 1
            ):
                raise DevelopmentControlError(
                    f"{label} repository contains forbidden ignored untracked paths"
                )
            observed_roots.add(matching_roots[0])
        for allowed in observed_roots:
            try:
                metadata = (root / allowed.as_posix()).lstat()
            except OSError as error:
                raise DevelopmentControlError(
                    f"{label} repository contains invalid ignored untracked paths"
                ) from error
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise DevelopmentControlError(
                    f"{label} repository contains invalid ignored untracked paths"
                )
    _verify_head_tracked_files(root, label=label)


def _verify_head_tracked_files(root: Path, *, label: str) -> None:
    inventory = _git_bytes(root, ["ls-tree", "-r", "-z", "HEAD"])
    for raw_entry in inventory.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            header, raw_path = raw_entry.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = header.split(b" ", 2)
        except ValueError as error:
            raise DevelopmentControlError(
                f"{label} tracked-file inventory is invalid"
            ) from error
        if (
            raw_mode not in {b"100644", b"100755"}
            or raw_type != b"blob"
            or len(raw_object_id) != 40
            or any(byte not in b"0123456789abcdef" for byte in raw_object_id)
        ):
            raise DevelopmentControlError(
                f"{label} tracked entry is not a regular Git blob"
            )
        try:
            relative = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise DevelopmentControlError(f"{label} tracked path is not UTF-8") from error
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise DevelopmentControlError(f"{label} tracked path is unsafe")
        live = _read_regular(
            root / relative,
            maximum_bytes=16 * 1024 * 1024,
            expected_executable=raw_mode == b"100755",
        )
        committed = _git_bytes(
            root,
            ["cat-file", "blob", raw_object_id.decode("ascii")],
            maximum_bytes=16 * 1024 * 1024,
        )
        if live != committed:
            raise DevelopmentControlError(
                f"{label} live tracked file differs from HEAD"
            )


def _verify_head_files(root: Path, paths: tuple[str, ...], *, label: str) -> None:
    for relative in paths:
        live = _read_regular(root / relative, maximum_bytes=16 * 1024 * 1024)
        object_id = _git_output(
            root, ["rev-parse", "--verify", f"HEAD:{relative}"]
        )
        if HEX_40.fullmatch(object_id) is None:
            raise DevelopmentControlError(f"{label} source object differs")
        committed = _git_bytes(
            root,
            ["cat-file", "blob", object_id],
            maximum_bytes=16 * 1024 * 1024,
        )
        if committed != live:
            raise DevelopmentControlError(f"{label} live source differs from HEAD")


def _verify_tag_signature(root: Path, allowed_signers: Path, tag: str) -> None:
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(root),
            "-c",
            f"core.worktree={root}",
            "-c",
            "core.bare=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.ignoreStat=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "-c",
            "gpg.ssh.program=/usr/bin/ssh-keygen",
            "verify-tag",
            tag,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        raise DevelopmentControlError(
            f"signed source tag cannot be verified: {tag}"
        )


def verify_canonical_execution_source() -> dict[str, Any]:
    """Bind the pre-freeze control to the current exact clean source tree.

    The implementation identity cannot be hard-coded before the control has
    passed: the report, runtime manifest, freeze manifest, CI gate, and later
    signed development release must all bind the same commit/tree selected by
    this gate.  A historical release identity is never an admissible shortcut.
    """

    root = PROJECT_ROOT.resolve(strict=True)
    _verify_isolated_pycache_prefix()
    repository = _git_output(root, ["remote", "get-url", "origin"])
    if repository.rstrip("/").removesuffix(".git") != (
        LAB_REPOSITORY.rstrip("/").removesuffix(".git")
    ):
        raise DevelopmentControlError("canonical lab repository differs")
    commit = _git_output(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    tree = _git_output(root, ["rev-parse", "--verify", "HEAD^{tree}"])
    if HEX_40.fullmatch(commit) is None or HEX_40.fullmatch(tree) is None:
        raise DevelopmentControlError("canonical lab commit/tree is invalid")
    _verify_clean_checkout(
        root,
        label="canonical lab",
        allowed_ignored_roots=LAB_ALLOWED_IGNORED_ROOTS,
    )
    _verify_head_files(
        root,
        tuple(dict.fromkeys(("blind_v1/__init__.py", *CONTROL_SOURCE_PATHS))),
        label="canonical lab",
    )
    return {
        "repository": LAB_REPOSITORY,
        "commit": commit,
        "tree": tree,
        "worktreeClean": True,
    }


def verify_post_release_source() -> dict[str, Any]:
    """Bind a later regression to the exact signed development source.

    This path is deliberately unavailable until the future Blind V1
    development-control tag exists.  It derives the tag object, commit, and tree
    from that verified tag instead of inheriting any historical V4 identity.
    Regressions run the exact tagged tree; changed-source experiments need a
    separately registered implementation identity.
    """

    root = PROJECT_ROOT.resolve(strict=True)
    _verify_isolated_pycache_prefix()
    repository = _git_output(root, ["remote", "get-url", "origin"])
    if repository.rstrip("/").removesuffix(".git") != (
        LAB_REPOSITORY.rstrip("/").removesuffix(".git")
    ):
        raise DevelopmentControlError("post-release lab repository differs")
    _verify_clean_checkout(
        root,
        label="post-release lab",
        allowed_ignored_roots=LAB_ALLOWED_IGNORED_ROOTS,
    )
    public_key = BLIND_V1_ROOT / "signing" / "corelm-blind-crossmodel-v1-signing.pub"
    allowed_signers = BLIND_V1_ROOT / "signing" / "allowed_signers"
    if sha256_bytes(_read_regular(public_key, maximum_bytes=4096)) != (
        SIGNING_PUBLIC_KEY_SHA256
    ):
        raise DevelopmentControlError("release signing public key differs")
    if sha256_bytes(_read_regular(allowed_signers, maximum_bytes=4096)) != (
        ALLOWED_SIGNERS_SHA256
    ):
        raise DevelopmentControlError("allowed-signers policy differs")

    object_type = _git_output(root, ["cat-file", "-t", DEVELOPMENT_RELEASE_TAG])
    tag_object = _git_output(root, ["rev-parse", DEVELOPMENT_RELEASE_TAG])
    commit = _git_output(root, ["rev-list", "-n", "1", DEVELOPMENT_RELEASE_TAG])
    tree = _git_output(root, ["rev-parse", f"{DEVELOPMENT_RELEASE_TAG}^{{tree}}"])
    if (
        object_type != "tag"
        or HEX_40.fullmatch(tag_object) is None
        or HEX_40.fullmatch(commit) is None
        or HEX_40.fullmatch(tree) is None
    ):
        raise DevelopmentControlError("frozen development tag identity differs")
    _verify_tag_signature(root, allowed_signers, DEVELOPMENT_RELEASE_TAG)
    current_commit = _git_output(root, ["rev-parse", "HEAD"])
    current_tree = _git_output(root, ["rev-parse", "HEAD^{tree}"])
    if current_commit != commit or current_tree != tree:
        raise DevelopmentControlError(
            "post-release regression must run the exact signed development tree"
        )
    _verify_head_files(
        root,
        tuple(
            dict.fromkeys(
                (
                    "blind_v1/__init__.py",
                    "blind_v1/run_post_release_regression.py",
                    *CONTROL_SOURCE_PATHS,
                )
            )
        ),
        label="post-release lab",
    )
    return {
        "tag": DEVELOPMENT_RELEASE_TAG,
        "tagObject": tag_object,
        "commit": commit,
        "tree": tree,
        "signatureVerified": True,
        "signingPublicKeySHA256": SIGNING_PUBLIC_KEY_SHA256,
        "allowedSignersSHA256": ALLOWED_SIGNERS_SHA256,
        "signingKeyFingerprint": SIGNING_KEY_FINGERPRINT,
        "executionSource": {
            "repository": LAB_REPOSITORY,
            "commit": current_commit,
            "tree": current_tree,
            "worktreeClean": True,
        },
    }


def verify_codec(codec_root: Path, design: Mapping[str, Any]) -> dict[str, Any]:
    source = design.get("codecSource")
    if not isinstance(source, dict):
        raise DevelopmentControlError("blind_v1 codec source binding is absent")
    try:
        root = codec_root.resolve(strict=True)
    except OSError as error:
        raise DevelopmentControlError("codec root is unavailable") from error
    if root.is_symlink() or not root.is_dir():
        raise DevelopmentControlError("codec root is not a real directory")
    commit = _git_output(root, ["rev-parse", "HEAD"])
    tree = _git_output(root, ["rev-parse", "HEAD^{tree}"])
    if commit != source.get("commit") or tree != source.get("tree"):
        raise DevelopmentControlError("codec commit/tree differs from exact blind_v1 binding")
    _verify_clean_checkout(root, label="codec")
    required = source.get("requiredFiles")
    if not isinstance(required, dict) or not required:
        raise DevelopmentControlError("codec required file binding is absent")
    observed: dict[str, dict[str, Any]] = {}
    for relative, commitment in sorted(required.items()):
        if not isinstance(relative, str) or not isinstance(commitment, dict):
            raise DevelopmentControlError("codec file binding is invalid")
        raw = _read_regular(root / relative, maximum_bytes=16 * 1024 * 1024)
        digest = _digest_bytes(raw)
        if digest != commitment:
            raise DevelopmentControlError(f"codec file differs: {relative}")
        observed[relative] = digest
    _verify_head_files(root, tuple(sorted(required)), label="codec")
    return {
        "repository": source.get("repository"),
        "commit": commit,
        "tree": tree,
        "requiredFiles": observed,
    }


def verify_lab_source(design: Mapping[str, Any]) -> dict[str, Any]:
    source = design.get("labSource")
    if not isinstance(source, dict) or not isinstance(source.get("repository"), str):
        raise DevelopmentControlError("lab source repository binding is absent")
    root = PROJECT_ROOT.resolve(strict=True)
    commit = _git_output(root, ["rev-parse", "HEAD"])
    tree = _git_output(root, ["rev-parse", "HEAD^{tree}"])
    repository = _git_output(root, ["remote", "get-url", "origin"])
    if repository.rstrip("/").removesuffix(".git") != source["repository"].rstrip(
        "/"
    ).removesuffix(".git"):
        raise DevelopmentControlError("lab source repository differs")
    _verify_clean_checkout(
        root,
        label="lab",
        allowed_ignored_roots=LAB_ALLOWED_IGNORED_ROOTS,
    )
    _verify_head_files(
        root,
        tuple(
            dict.fromkeys(
                (
                    "blind_v1/__init__.py",
                    "blind_v1/run_post_release_regression.py",
                    *CONTROL_SOURCE_PATHS,
                )
            )
        ),
        label="lab",
    )
    return {
        "repository": source["repository"],
        "commit": commit,
        "tree": tree,
        "worktreeClean": True,
    }


def _tracked_sources() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for relative in CONTROL_SOURCE_PATHS:
        raw = _read_regular(PROJECT_ROOT / relative, maximum_bytes=4 * 1024 * 1024)
        result.append({"path": relative, **_digest_bytes(raw)})
    return result


def _load_fixed_inputs(
    *,
    asset_root: Path,
    dataset_path: Path,
    codec_root: Path,
    runtime_manifest_path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    bytes,
    dict[str, Any],
    dict[str, Any],
    dict[str, bytes],
]:
    design_path = BLIND_V1_ROOT / "design-registration.draft.json"
    manifest_path = BLIND_V1_ROOT / "development-model-assets.json"
    receipt_path = (
        BLIND_V1_ROOT
        / "manifests"
        / "development-model-assets.full-rehash.json"
    )
    corpus_manifest_path = BLIND_V1_ROOT / "development-corpus.draft.json"
    license_source_path = PROJECT_ROOT / "LICENSES" / "source-evidence.json"
    asset_license_matrix_path = PROJECT_ROOT / "LICENSES" / "ASSET_LICENSES.md"
    corpus_readme_path = (
        PROJECT_ROOT / "LICENSES" / "upstream" / "ud-english-pud-r2.18-README.md"
    )
    corpus_license_path = (
        PROJECT_ROOT / "LICENSES" / "upstream" / "ud-english-pud-r2.18-LICENSE.txt"
    )
    corpus_attribution_path = PROJECT_ROOT / "LICENSES" / "UD_ENGLISH_PUD_ATTRIBUTION.md"
    design_raw = _read_regular(design_path, maximum_bytes=4 * 1024 * 1024)
    manifest_raw = _read_regular(manifest_path, maximum_bytes=4 * 1024 * 1024)
    receipt_raw = _read_regular(receipt_path, maximum_bytes=4 * 1024 * 1024)
    corpus_manifest_raw = _read_regular(
        corpus_manifest_path, maximum_bytes=4 * 1024 * 1024
    )
    license_source_raw = _read_regular(
        license_source_path, maximum_bytes=4 * 1024 * 1024
    )
    asset_license_matrix_raw = _read_regular(
        asset_license_matrix_path, maximum_bytes=4 * 1024 * 1024
    )
    corpus_readme_raw = _read_regular(
        corpus_readme_path, maximum_bytes=4 * 1024 * 1024
    )
    corpus_license_raw = _read_regular(
        corpus_license_path, maximum_bytes=4 * 1024 * 1024
    )
    corpus_attribution_raw = _read_regular(
        corpus_attribution_path, maximum_bytes=4 * 1024 * 1024
    )
    runtime_raw = _read_regular(runtime_manifest_path, maximum_bytes=32 * 1024 * 1024)
    design = _canonical_document(design_raw, label="blind_v1 design registration")
    manifest = _canonical_document(manifest_raw, label="blind_v1 model asset manifest")
    receipt = _canonical_document(receipt_raw, label="blind_v1 full asset receipt")
    corpus_manifest = _canonical_document(
        corpus_manifest_raw, label="development corpus manifest"
    )
    license_source_evidence = _canonical_document(
        license_source_raw, label="license source evidence"
    )
    runtime_manifest = _canonical_document(runtime_raw, label="runtime manifest")
    validate_design_registration(design)
    if design.get("developmentControls") != EXPECTED_DEVELOPMENT_CONTROLS:
        raise DevelopmentControlError("registered development control boundary differs")
    dataset = EXPECTED_DEVELOPMENT_CONTROLS["dataset"]
    if _digest_bytes(corpus_manifest_raw) != {
        "bytes": dataset["manifestBytes"],
        "sha256": dataset["manifestSHA256"],
    }:
        raise DevelopmentControlError("registered development corpus manifest differs")
    for field in (
        "datasetId",
        "repository",
        "revision",
        "tree",
        "releaseTag",
        "split",
        "splitPurpose",
        "file",
        "format",
        "bytes",
        "sha256",
        "rows",
        "rowExtraction",
        "joinedTextBytes",
        "joinedTextSHA256",
        "license",
    ):
        if corpus_manifest.get(field) != dataset[field]:
            raise DevelopmentControlError(
                f"registered development corpus manifest differs: {field}"
            )
    try:
        verify_rights_evidence(
            license_source_evidence,
            corpus_readme_raw,
            corpus_license_raw,
            corpus_attribution_raw,
        )
    except ValueError as error:
        raise DevelopmentControlError(
            "registered UD English PUD rights evidence differs"
        ) from error
    try:
        asset_license_matrix = asset_license_matrix_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentControlError("asset license matrix is not UTF-8") from error
    if (
        "UD English PUD" not in asset_license_matrix
        or "CC BY-SA 3.0" not in asset_license_matrix
        or "without added restrictions" not in asset_license_matrix
    ):
        raise DevelopmentControlError("asset license matrix omits PUD obligations")
    validate_development_model_asset_manifest(manifest, design)
    try:
        verify_content_digest(receipt)
    except ValueError as error:
        raise DevelopmentControlError("tracked full asset receipt is invalid") from error
    observed_receipt = _historical_build_asset_receipt(manifest_path, asset_root)
    if observed_receipt != receipt:
        raise DevelopmentControlError("local exact model assets differ from full rehash receipt")
    if tuple(design["developmentControls"]["modelAssets"]["modelKeys"]) != MODELS:
        raise DevelopmentControlError("development pilot model order differs")
    candidate = design.get("candidate")
    if not isinstance(candidate, dict) or {
        key: candidate.get(key) for key in CANDIDATE
    } != CANDIDATE:
        raise DevelopmentControlError("blind_v1 candidate differs from development control")
    dataset_raw = _read_regular(dataset_path, maximum_bytes=16 * 1024 * 1024)
    if _digest_bytes(dataset_raw) != {
        "bytes": dataset["bytes"],
        "sha256": dataset["sha256"],
    }:
        raise DevelopmentControlError("UD English PUD bytes differ from the registered pin")
    lab = verify_lab_source(design)
    codec = verify_codec(codec_root, design)
    try:
        verify_runtime_manifest_integrity(runtime_manifest)
        verify_runtime_live(runtime_manifest, Path(sys.prefix))
    except (ValueError, DevelopmentRuntimeError) as error:
        raise DevelopmentControlError("locked runtime manifest is not live") from error
    for label, observed in (("lab", lab), ("codec", codec)):
        manifest_source = runtime_manifest[f"{label}Source"]
        if (
            manifest_source.get("commit") != observed["commit"]
            or manifest_source.get("tree") != observed["tree"]
            or manifest_source.get("worktreeClean") is not True
        ):
            raise DevelopmentControlError(
                f"runtime manifest binds a different or dirty {label} source"
            )
    bindings = {
        "designRegistration": _digest_bytes(design_raw),
        "modelAssetManifest": _digest_bytes(manifest_raw),
        "fullAssetReceipt": _digest_bytes(receipt_raw),
        "developmentCorpusManifest": _digest_bytes(corpus_manifest_raw),
        "licenseSourceEvidence": _digest_bytes(license_source_raw),
        "assetLicenseMatrix": _digest_bytes(asset_license_matrix_raw),
        "udEnglishPudReadme": _digest_bytes(corpus_readme_raw),
        "udEnglishPudLicense": _digest_bytes(corpus_license_raw),
        "udEnglishPudAttribution": _digest_bytes(corpus_attribution_raw),
        "developmentDataset": _digest_bytes(dataset_raw),
        "runtimeManifest": _digest_bytes(runtime_raw),
        "labSource": lab,
        "codecSource": codec,
        "controlSources": _tracked_sources(),
        "adapter": dict(ADAPTER),
    }
    archival_inputs = {
        "design-registration.draft.json": design_raw,
        "development-model-assets.json": manifest_raw,
        FULL_ASSET_RECEIPT_ARCHIVE_NAME: receipt_raw,
        "development-corpus.draft.json": corpus_manifest_raw,
        "LICENSES/source-evidence.json": license_source_raw,
        "LICENSES/ASSET_LICENSES.md": asset_license_matrix_raw,
        "LICENSES/upstream/ud-english-pud-r2.18-README.md": corpus_readme_raw,
        "LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt": corpus_license_raw,
        "LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md": corpus_attribution_raw,
        "runtime-manifest.json": runtime_raw,
    }
    return design, receipt, dataset_raw, dataset, bindings, archival_inputs


def _real_sentences(dataset_raw: bytes) -> tuple[list[str], dict[str, Any]]:
    try:
        records = parse_corpus(dataset_raw)
        joined = joined_text(records)
    except ValueError as error:
        raise DevelopmentControlError(
            "pinned UD English PUD corpus is invalid"
        ) from error
    return [record.text for record in records], {
        **_digest_bytes(joined),
        "parser": "strict-stdlib-conllu-text-v1",
        "sentences": len(records),
        "sourceConlluSHA256": sha256_bytes(dataset_raw),
    }


def _write_private_records(
    private_root: Path, sentences: list[str]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    pages: dict[str, list[dict[str, Any]]] = {DATASET_ID: []}
    inventory: list[dict[str, Any]] = []
    if len(sentences) != SENTENCE_COUNT:
        raise DevelopmentControlError("PUD sentence count differs")
    for partition_index, (start, end) in enumerate(partition_bounds()):
        content = "\n\n".join(sentences[start:end])
        if not content:
            raise DevelopmentControlError("deterministic PUD partition is empty")
        record = serialize_record(
            sentence_start=start,
            sentence_end=end,
            content=content,
        )
        relative = f"records/ud-english-pud/slice-{partition_index:02d}.bin"
        destination = private_root / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new_bytes(destination, record)
        input_raw = content.encode("utf-8", errors="strict")
        page = {
            "pageSelectionIndex": partition_index,
            "sourceSliceIndex": partition_index,
            "sentenceStart": start,
            "sentenceEnd": end,
            "recordPath": relative,
            "recordBytes": len(record),
            "recordSHA256": sha256_bytes(record),
            "inputTextBytes": len(input_raw),
            "inputTextSHA256": sha256_bytes(input_raw),
        }
        pages[DATASET_ID].append(page)
        inventory.append(
            {
                "path": relative,
                "bytes": len(record),
                "sha256": sha256_bytes(record),
                "role": "development-corpus-record",
            }
        )
    return pages, inventory


def _link_model_assets(
    *,
    private_root: Path,
    asset_root: Path,
    receipt: Mapping[str, Any],
    design: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    inventory: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    receipt_models = receipt["models"]
    for design_model in design["models"]:
        key = design_model["key"]
        source_model = receipt_models[key]
        files: dict[str, dict[str, Any]] = {}
        for filename in MODEL_FILES:
            commitment = source_model["files"][filename]
            relative = f"models/{key}/{filename}"
            destination = private_root / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.link(asset_root / key / filename, destination, follow_symlinks=False)
            except OSError as error:
                raise DevelopmentControlError(
                    "model assets must support same-filesystem no-copy hard links"
                ) from error
            expected_bytes = commitment.get("bytes")
            observed = _stream_regular_commitment(
                destination,
                exact_bytes=expected_bytes,
            )
            if observed != commitment:
                raise DevelopmentControlError(f"linked model asset differs: {key}/{filename}")
            files[filename] = {"path": relative, **observed}
            inventory.append({"path": relative, **observed, "role": "model-asset"})
        models.append(
            {
                "key": key,
                "repository": design_model["repository"],
                "revision": design_model["revision"],
                "layers": design_model["layers"],
                "vocabSize": design_model["vocabSize"],
                "candidateBitsByLayer": design_model["candidateBitsByLayer"],
                "files": files,
            }
        )
    return models, inventory


def _with_content_digest(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["contentSHA256"] = sha256_bytes(canonical_json_bytes(value))
    return result


def build_plan(
    *,
    design: Mapping[str, Any],
    receipt: Mapping[str, Any],
    asset_root: Path,
    private_root: Path,
    sentences: list[str],
    input_bindings: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    require_scientific_schedule_open(operation="build Blind V1 development plan")
    return _historical_build_plan(
        design=design,
        receipt=receipt,
        asset_root=asset_root,
        private_root=private_root,
        sentences=sentences,
        input_bindings=input_bindings,
    )


def _historical_build_plan(
    *,
    design: Mapping[str, Any],
    receipt: Mapping[str, Any],
    asset_root: Path,
    private_root: Path,
    sentences: list[str],
    input_bindings: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Retain deterministic planning for regression and historical fixtures."""

    pages, record_inventory = _write_private_records(private_root, sentences)
    models, model_inventory = _link_model_assets(
        private_root=private_root,
        asset_root=asset_root,
        receipt=receipt,
        design=design,
    )
    execution = {
        "device": design["execution"]["device"],
        "intraOpThreads": design["execution"]["intraOpThreads"],
        "interOpThreads": design["execution"]["interOpThreads"],
        "modelDtype": design["execution"]["modelDtype"],
        "cacheBaseline": design["execution"]["cacheBaseline"],
        "attentionImplementation": design["execution"]["attentionImplementation"],
        "prefillTokens": design["execution"]["prefillTokens"],
        "predictionTokensPerPage": design["execution"]["predictionTokensPerPage"],
        "maximumWorkerRSSBytes": design["execution"]["maximumWorkerRSSBytes"],
        "watchdogPollMilliseconds": design["execution"]["watchdogPollMilliseconds"],
        "deterministicAlgorithms": design["execution"]["deterministicAlgorithms"],
        "modelsSequential": True,
    }
    configuration = {
        "schemaVersion": "corelm-blind-crossmodel-v1-real-e2e-development-configuration-v1",
        "suiteId": SUITE_ID,
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "modelExecutionOrder": list(MODELS),
        "selectedCorpora": list(CORPORA),
        "candidate": dict(CANDIDATE),
        "models": models,
        "pages": pages,
        "execution": execution,
        "inputBindings": input_bindings,
    }
    configuration_sha = sha256_bytes(canonical_json_bytes(configuration))
    run_id = "development-e2e-" + configuration_sha
    base_plan: dict[str, Any] = {
        "schemaVersion": PLAN_SCHEMA,
        "suiteId": SUITE_ID,
        "runId": run_id,
        "status": "SEALED_NON_SCIENTIFIC_DEVELOPMENT_INPUT",
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "modelExecutionOrder": list(MODELS),
        "selectedCorpora": list(CORPORA),
        "candidate": dict(CANDIDATE),
        "models": models,
        "pages": pages,
        "privateFiles": sorted(
            model_inventory
            + record_inventory
            + [
                {
                    "path": DATASET_EVIDENCE_PATH,
                    "bytes": DATASET_BYTES,
                    "sha256": DATASET_SHA256,
                    "role": "development-corpus-source",
                }
            ],
            key=lambda item: item["path"],
        ),
        "jobs": {},
        "inputBindings": input_bindings,
        "execution": execution,
        "controlConfigurationSHA256": configuration_sha,
    }
    jobs: dict[str, bytes] = {}
    commitments: dict[str, dict[str, Any]] = {}
    # expected_job uses only sealed fields that are already present above.
    for model_key in MODELS:
        raw = canonical_json_bytes(expected_job(base_plan, model_key)) + b"\n"
        jobs[model_key] = raw
        commitments[model_key] = {
            "path": f"jobs/{model_key}.json",
            **_digest_bytes(raw),
        }
    base_plan["jobs"] = commitments
    plan = _with_content_digest(base_plan)
    validate_plan(plan)
    return plan, jobs


def _development_child_command(script: Path, *arguments: str) -> tuple[list[str], str]:
    pycache_prefix = _verify_isolated_pycache_prefix()
    command = python_command(
        sys.executable,
        "-X",
        f"pycache_prefix={pycache_prefix}",
        str(script),
        *arguments,
    )
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return networkless_macos_command(command), "macOS-sandbox-exec-deny-network"
    raise DevelopmentControlError(
        "full real-model E2E requires the registered macOS arm64 sandbox host"
    )


def _supervise_development_child(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    log_path: Path,
    maximum_rss_bytes: int,
    poll_milliseconds: int,
    subject: str,
) -> dict[str, Any]:
    started = _utc_now()
    started_monotonic = time.monotonic_ns()
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with log_path.open("xb") as log:
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
                rss, members = process_group_usage(process.pid)
                peak_rss = max(peak_rss, rss)
                if return_code is not None:
                    descendants = [member for member in members if member != process.pid]
                    if descendants:
                        terminate_process_group(process)
                        raise DevelopmentControlError(
                            f"development child left descendants: {subject}"
                        )
                    break
                if rss > maximum_rss_bytes:
                    raise DevelopmentControlError(
                        f"development child exceeded exact RSS bound: {subject}"
                    )
                time.sleep(poll_milliseconds / 1000)
        except BaseException:
            terminate_process_group(process)
            raise
        finally:
            log.flush()
            os.fsync(log.fileno())
    receipt = {
        "schemaVersion": SUPERVISOR_SCHEMA,
        "subject": subject,
        "startedAt": started,
        "completedAt": _utc_now(),
        "durationNanoseconds": time.monotonic_ns() - started_monotonic,
        "exitCode": return_code,
        "peakAggregateRSSBytes": peak_rss,
        "maximumAggregateRSSBytes": maximum_rss_bytes,
        "watchdogPollMilliseconds": poll_milliseconds,
        "descendantsRemainingAtExit": False,
        "terminationApplied": False,
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
    }
    return receipt


def _artifact_inventory(root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for directory, child_directories, filenames in os.walk(root):
        child_directories.sort()
        filenames.sort()
        current = Path(directory)
        for name in child_directories:
            if (current / name).is_symlink():
                raise DevelopmentControlError("development output contains a symlink")
        for name in filenames:
            path = current / name
            relative = path.relative_to(root).as_posix()
            if relative == "development-control-report.json":
                continue
            raw = _read_regular(path, maximum_bytes=512 * 1024 * 1024)
            result.append({"path": relative, **_digest_bytes(raw)})
    return result


def _valid_digest_record(value: Any, *, expected_path: str | None = None) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "bytes", "sha256"}
        and (expected_path is None or value["path"] == expected_path)
        and type(value["bytes"]) is int
        and value["bytes"] > 0
        and isinstance(value["sha256"], str)
        and HEX_64.fullmatch(value["sha256"]) is not None
    )


def validate_worker_summary(
    summary: Any, *, model_key: str, plan: Mapping[str, Any], output_root: Path
) -> None:
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "runId",
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
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "controlConfigurationSHA256",
    }
    if not isinstance(summary, dict) or set(summary) != expected_fields:
        raise DevelopmentControlError(f"development worker summary fields differ: {model_key}")
    model = next(item for item in plan["models"] if item["key"] == model_key)
    geometry = summary["geometry"]
    if (
        summary["schemaVersion"] != WORKER_SUMMARY_SCHEMA
        or summary["suiteId"] != SUITE_ID
        or summary["runId"] != plan["runId"]
        or summary["modelKey"] != model_key
        or summary["controlConfigurationSHA256"]
        != plan["controlConfigurationSHA256"]
        or summary["countsTowardScientificVerdict"] is not False
        or summary["usedForCandidateSelectionOrTuning"] is not False
        or summary["scientificAttemptStateCreated"] is not False
        or summary["nistUsed"] is not False
        or summary["futureCorpusUsed"] is not False
        or summary["networkUsed"] is not False
        or summary["modelLoad"]
        != (
            "verified-owned-bytes-deserialize-drop-before-fp32-model-"
            "no-mmap-no-pickle-no-from_pretrained"
        )
        or type(summary["durationNanoseconds"]) is not int
        or summary["durationNanoseconds"] <= 0
        or not isinstance(geometry, dict)
        or geometry.get("layers") != model["layers"]
    ):
        raise DevelopmentControlError(f"development worker summary boundary differs: {model_key}")
    pages = summary["pages"]
    if not isinstance(pages, list) or len(pages) != PARTITIONS:
        raise DevelopmentControlError(f"development worker page count differs: {model_key}")
    page_fields = {
        "datasetId",
        "pageSelectionIndex",
        "sourceSliceIndex",
        "denseBF16Bytes",
        "containerBytes",
        "compressionRatioVsBF16",
        "deltaNLLNatPerToken",
        "top1ExactMatches",
    }
    for index, page in enumerate(pages):
        if (
            not isinstance(page, dict)
            or set(page) != page_fields
            or page["datasetId"] != DATASET_ID
            or page["pageSelectionIndex"] != index
            or page["sourceSliceIndex"] != index
            or type(page["denseBF16Bytes"]) is not int
            or page["denseBF16Bytes"] <= 0
            or type(page["containerBytes"]) is not int
            or page["containerBytes"] <= 0
            or not isinstance(page["compressionRatioVsBF16"], (int, float))
            or not math.isfinite(page["compressionRatioVsBF16"])
            or page["compressionRatioVsBF16"] <= 0
            or not isinstance(page["deltaNLLNatPerToken"], (int, float))
            or not math.isfinite(page["deltaNLLNatPerToken"])
            or type(page["top1ExactMatches"]) is not int
            or not 0 <= page["top1ExactMatches"] <= 128
        ):
            raise DevelopmentControlError(
                f"development worker page summary differs: {model_key}/{index}"
            )
    evidence = {
        "rawTokenEvidence": "raw-token-evidence.jsonl",
        "containerEvidence": "container-evidence.jsonl",
        "pageTokenEvidence": "page-token-evidence.jsonl",
    }
    worker_root = output_root / "workers" / model_key
    for field, filename in evidence.items():
        commitment = summary[field]
        if not _valid_digest_record(commitment, expected_path=filename):
            raise DevelopmentControlError(
                f"development worker evidence commitment differs: {model_key}/{field}"
            )
        observed = _digest_bytes(
            _read_regular(worker_root / filename, maximum_bytes=256 * 1024 * 1024)
        )
        if observed != {"bytes": commitment["bytes"], "sha256": commitment["sha256"]}:
            raise DevelopmentControlError(
                f"development worker evidence bytes differ: {model_key}/{field}"
            )


def validate_replay_summary(summary: Any, *, plan: Mapping[str, Any]) -> None:
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "status",
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
        "controlConfigurationSHA256",
        "modelOrder",
        "selectedCorpora",
        "execution",
        "runtime",
        "models",
        "totalReplayedPages",
        "totalReplayedPredictions",
        "totalReplayedContainers",
        "exactTokenIds",
        "exactLossFloat32Bits",
        "exactTop1TokenIds",
        "allContainerInputsBoundToBaselineCache",
        "replayComplete",
        "contentSHA256",
    }
    if not isinstance(summary, dict) or set(summary) != expected_fields:
        raise DevelopmentControlError("development replay summary fields differ")
    exact_true = (
        "exactTokenIds",
        "exactLossFloat32Bits",
        "exactTop1TokenIds",
        "allContainerInputsBoundToBaselineCache",
        "replayComplete",
    )
    if (
        summary["schemaVersion"] != REPLAY_SUMMARY_SCHEMA
        or summary["suiteId"] != SUITE_ID
        or summary["runId"] != plan["runId"]
        or summary["status"] != "NON_SCIENTIFIC_DEVELOPMENT_REPLAY_PASS"
        or summary["controlConfigurationSHA256"]
        != plan["controlConfigurationSHA256"]
        or any(
            summary[field] is not False
            for field in (
                "countsTowardScientificVerdict",
                "usedForCandidateSelectionOrTuning",
                "scientificAttemptStateCreated",
                "nistUsed",
                "futureCorpusUsed",
                "thresholdsApplied",
            )
        )
        or any(summary[field] is not True for field in exact_true)
        or summary["modelOrder"] != list(MODELS)
        or summary["selectedCorpora"] != list(CORPORA)
        or summary["totalReplayedPages"] != 96
        or summary["totalReplayedPredictions"] != 12288
        or summary["totalReplayedContainers"] != 2048
        or summary["execution"]
        != {
            "device": "cpu",
            "modelDtype": "float32",
            "baselineCache": "bfloat16-roundtrip-to-float32",
            "deterministicAlgorithms": True,
            "intraOpThreads": 2,
            "interOpThreads": 1,
            "modelsSequential": True,
            "networkUsed": False,
            "fixtureBackendUsed": False,
        }
        or summary["runtime"]
        != {
            "numpy": "2.5.1",
            "safetensors": "0.8.0",
            "tokenizers": "0.22.2",
            "torch": "2.13.0",
            "transformers": "5.14.1",
        }
    ):
        raise DevelopmentControlError("development replay summary boundary differs")
    models = summary["models"]
    if not isinstance(models, list) or [item.get("modelKey") for item in models] != list(
        MODELS
    ):
        raise DevelopmentControlError("development replay model order differs")
    model_fields = {
        "modelKey",
        "modelFileSetSHA256",
        "weightSHA256",
        "tokenizerSHA256",
        "corpusRecordSetSHA256",
        "rawTokenEvidenceSHA256",
        "pageTokenEvidenceSHA256",
        "containerEvidenceSHA256",
        "containerByteSetSHA256",
        "pageReplaySHA256",
        "replayedPages",
        "replayedPredictions",
        "replayedContainers",
        "exactTokenIds",
        "exactLossFloat32Bits",
        "exactTop1TokenIds",
        "allContainerInputsBoundToBaselineCache",
    }
    plan_models = {item["key"]: item for item in plan["models"]}
    for item in models:
        model_key = item["modelKey"]
        model = plan_models[model_key]
        if (
            set(item) != model_fields
            or item["weightSHA256"] != model["files"]["model.safetensors"]["sha256"]
            or item["tokenizerSHA256"] != model["files"]["tokenizer.json"]["sha256"]
            or item["replayedPages"] != 32
            or item["replayedPredictions"] != 4096
            or item["replayedContainers"] != 32 * model["layers"]
            or any(item[field] is not True for field in exact_true[:-1])
            or any(
                not isinstance(item[field], str) or HEX_64.fullmatch(item[field]) is None
                for field in (
                    "modelFileSetSHA256",
                    "weightSHA256",
                    "tokenizerSHA256",
                    "corpusRecordSetSHA256",
                    "rawTokenEvidenceSHA256",
                    "pageTokenEvidenceSHA256",
                    "containerEvidenceSHA256",
                    "containerByteSetSHA256",
                    "pageReplaySHA256",
                )
            )
        ):
            raise DevelopmentControlError(
                f"development replay model summary differs: {model_key}"
            )


def validate_post_release_regression_report(value: Any) -> dict[str, Any]:
    """Structurally validate a report incompatible with freeze input.

    Live Git and signature verification is performed before execution; this
    pure validator checks the exact record carried into the report.
    """

    canonical_fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "executionId",
        "status",
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
        "candidateCodecInvoked",
        "realModelsUsed",
        "realDevelopmentCorpusUsed",
        "independentRealModelReplayComplete",
        "startedAt",
        "completedAt",
        "controlConfigurationSHA256",
        "plan",
        "inputs",
        "runtime",
        "hostSafetyChecks",
        "networkIsolationBackend",
        "workerProcessesSequential",
        "replayModelsSequential",
        "supervision",
        "independentReplay",
        "artifactInventory",
        "artifactSetSHA256",
        "scientificClaim",
        "candidateSelectionOrTuning",
        "contentSHA256",
    }
    regression_fields = {
        "executionClass",
        "canonicalDevelopmentControlPackaging",
        "scientificEvidenceUse",
        "frozenDevelopmentSource",
    }
    if (
        not isinstance(value, dict)
        or set(value) != canonical_fields | regression_fields
    ):
        raise DevelopmentControlError("post-release regression report fields differ")
    try:
        verify_content_digest(value)
    except ValueError as error:
        raise DevelopmentControlError(
            "post-release regression report digest differs"
        ) from error
    false_fields = (
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
    )
    true_fields = (
        "candidateCodecInvoked",
        "realModelsUsed",
        "realDevelopmentCorpusUsed",
        "independentRealModelReplayComplete",
        "workerProcessesSequential",
        "replayModelsSequential",
    )
    frozen = value["frozenDevelopmentSource"]
    execution_source = (
        frozen.get("executionSource") if isinstance(frozen, dict) else None
    )
    inputs = value.get("inputs")
    lab_source = inputs.get("labSource") if isinstance(inputs, dict) else None
    if (
        value["schemaVersion"] != POST_RELEASE_REPORT_SCHEMA
        or value["suiteId"] != SUITE_ID
        or value["status"]
        != "NON_SCIENTIFIC_POST_RELEASE_REAL_MODEL_REGRESSION_PASS"
        or not isinstance(value["executionId"], str)
        or re.fullmatch(
            r"post-release-regression-execution-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}",
            value["executionId"],
        )
        is None
        or value["executionClass"] != POST_RELEASE_PROFILE
        or value["canonicalDevelopmentControlPackaging"] != "forbidden"
        or value["scientificEvidenceUse"] != "forbidden"
        or value["scientificClaim"] != "forbidden"
        or value["candidateSelectionOrTuning"] != "forbidden"
        or any(value[field] is not False for field in false_fields)
        or any(value[field] is not True for field in true_fields)
        or not isinstance(frozen, dict)
        or set(frozen)
        != {
            "tag",
            "tagObject",
            "commit",
            "tree",
            "signatureVerified",
            "signingPublicKeySHA256",
            "allowedSignersSHA256",
            "signingKeyFingerprint",
            "executionSource",
        }
        or frozen.get("tag") != DEVELOPMENT_RELEASE_TAG
        or not isinstance(frozen.get("tagObject"), str)
        or HEX_40.fullmatch(frozen["tagObject"]) is None
        or not isinstance(frozen.get("commit"), str)
        or HEX_40.fullmatch(frozen["commit"]) is None
        or not isinstance(frozen.get("tree"), str)
        or HEX_40.fullmatch(frozen["tree"]) is None
        or frozen.get("signatureVerified") is not True
        or frozen.get("signingPublicKeySHA256") != SIGNING_PUBLIC_KEY_SHA256
        or frozen.get("allowedSignersSHA256") != ALLOWED_SIGNERS_SHA256
        or frozen.get("signingKeyFingerprint") != SIGNING_KEY_FINGERPRINT
        or not isinstance(execution_source, dict)
        or set(execution_source)
        != {"repository", "commit", "tree", "worktreeClean"}
        or execution_source.get("repository") != LAB_REPOSITORY
        or execution_source.get("commit") != frozen.get("commit")
        or execution_source.get("tree") != frozen.get("tree")
        or execution_source.get("worktreeClean") is not True
        or not isinstance(lab_source, dict)
        or lab_source.get("repository") != execution_source.get("repository")
        or lab_source.get("commit") != execution_source.get("commit")
        or lab_source.get("tree") != execution_source.get("tree")
        or lab_source.get("worktreeClean") is not True
    ):
        raise DevelopmentControlError("post-release regression boundary differs")
    try:
        started = datetime.strptime(
            value["startedAt"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        completed = datetime.strptime(
            value["completedAt"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as error:
        raise DevelopmentControlError(
            "post-release regression timestamps are invalid"
        ) from error
    if completed < started:
        raise DevelopmentControlError("post-release regression timestamps differ")
    return value


def _run_control(
    arguments: argparse.Namespace,
    *,
    started: str,
    execution_id: str,
    post_release_regression: bool = False,
) -> dict[str, Any]:
    if type(post_release_regression) is not bool:
        raise DevelopmentControlError("execution profile is invalid")
    if post_release_regression:
        frozen_source: Mapping[str, Any] | None = verify_post_release_source()
        arguments._verified_source = dict(frozen_source)
        source_gate = frozen_source["executionSource"]
    else:
        source_gate = verify_canonical_execution_source()
        frozen_source = None
    design, receipt, dataset_raw, dataset, bindings, archival_inputs = _load_fixed_inputs(
        asset_root=arguments.asset_root,
        dataset_path=arguments.dataset,
        codec_root=arguments.codec_root,
        runtime_manifest_path=arguments.runtime_manifest,
    )
    if bindings.get("labSource") != source_gate:
        raise DevelopmentControlError(
            "pre-import source gate differs from runtime/report lab binding"
        )
    verify_development_lifecycle(
        design,
        allow_after_cutoff_for_post_release_regression=post_release_regression,
    )
    environment = closed_environment(design["execution"])
    verify_active_python_startup()
    runtime_probe = verify_python_subprocess(sys.executable, environment)
    sentences, joined = _real_sentences(dataset_raw)
    bindings["joinedCorpusText"] = {
        "bytes": joined["bytes"],
        "sha256": joined["sha256"],
    }
    bindings["conlluDecode"] = {
        "parser": joined["parser"],
        "sentences": joined["sentences"],
        "sourceConlluSHA256": joined["sourceConlluSHA256"],
    }
    try:
        initial_safety = wait_for_primary_host_safety(
            design, output_parent=arguments.output.parent
        )
    except DevelopmentRuntimeError as error:
        raise DevelopmentControlError("development host safety gate failed") from error
    output_root = _historical_claim_output(arguments.output)
    host_safety_checks = [{"phase": "before-output-materialization", **initial_safety}]
    arguments._claimed_output_root = output_root
    arguments._control_phase = "materialize-archived-inputs"
    arguments._control_context = {
        "inputBindings": bindings,
        "runtime": runtime_probe,
        "hostSafetyChecks": host_safety_checks,
    }
    start_payload: dict[str, Any] = {
        "schemaVersion": "corelm-blind-crossmodel-v1-real-e2e-development-start-v1",
        "suiteId": SUITE_ID,
        "executionId": execution_id,
        "status": "NON_SCIENTIFIC_DEVELOPMENT_CONTROL_STARTED",
        "startedAt": started,
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
    }
    start_filename = "development-control-start.json"
    if post_release_regression:
        if not isinstance(frozen_source, Mapping):
            raise DevelopmentControlError(
                "post-release regression has no frozen-source verification"
            )
        start_filename = "post-release-regression-start.json"
        start_payload.update(
            {
                "schemaVersion": (
                    "corelm-blind-crossmodel-v1-real-e2e-post-release-regression-start-v1"
                ),
                "status": "NON_SCIENTIFIC_POST_RELEASE_REAL_MODEL_REGRESSION_STARTED",
                "executionClass": POST_RELEASE_PROFILE,
                "canonicalDevelopmentControlPackaging": "forbidden",
                "scientificEvidenceUse": "forbidden",
            }
        )
    start_marker = _with_content_digest(start_payload)
    write_new_bytes(
        output_root / start_filename,
        canonical_json_bytes(start_marker) + b"\n",
    )
    if post_release_regression:
        write_new_bytes(
            output_root / "inputs" / "frozen-development-source.json",
            canonical_json_bytes(dict(frozen_source)) + b"\n",
        )
    for filename, raw in sorted(archival_inputs.items()):
        write_new_bytes(output_root / "inputs" / filename, raw)
    write_new_bytes(
        output_root / "inputs" / "corpus" / "en_pud-ud-test.conllu",
        dataset_raw,
    )
    with tempfile.TemporaryDirectory(
        prefix=".corelm-development-private-",
        dir=arguments.asset_root.resolve(strict=True),
    ) as temporary:
        private_root = Path(temporary).resolve(strict=True)
        write_new_bytes(private_root / DATASET_EVIDENCE_PATH, dataset_raw)
        plan, job_bytes = _historical_build_plan(
            design=design,
            receipt=receipt,
            asset_root=arguments.asset_root,
            private_root=private_root,
            sentences=sentences,
            input_bindings=bindings,
        )
        arguments._control_context.update(
            {
                "runId": plan["runId"],
                "controlConfigurationSHA256": plan[
                    "controlConfigurationSHA256"
                ],
            }
        )
        for model_key in MODELS:
            write_new_bytes(output_root / "jobs" / f"{model_key}.json", job_bytes[model_key])
        write_new_bytes(
            output_root / "development-plan.json",
            canonical_json_bytes(plan) + b"\n",
        )
        maximum_rss = design["execution"]["maximumWorkerRSSBytes"]
        poll = design["execution"]["watchdogPollMilliseconds"]
        supervision: list[dict[str, Any]] = []
        sandbox_backend: str | None = None
        for model_key in MODELS:
            arguments._control_phase = f"producer:{model_key}"
            try:
                safety = wait_for_primary_host_safety(
                    design, output_parent=output_root
                )
            except DevelopmentRuntimeError as error:
                raise DevelopmentControlError(
                    f"development host safety gate failed before {model_key}"
                ) from error
            host_safety_checks.append({"phase": f"before-producer:{model_key}", **safety})
            command, backend = _development_child_command(
                BLIND_V1_ROOT / "model_worker.py",
                "--job",
                str(output_root / "jobs" / f"{model_key}.json"),
                "--snapshot-root",
                str(private_root),
                "--codec-root",
                str(arguments.codec_root.resolve(strict=True)),
                "--output-root",
                str(output_root / "workers" / model_key),
            )
            sandbox_backend = backend if sandbox_backend is None else sandbox_backend
            if sandbox_backend != backend:
                raise DevelopmentControlError("development sandbox backend changed")
            receipt_value = _supervise_development_child(
                command,
                cwd=PROJECT_ROOT,
                environment=environment,
                log_path=output_root / "logs" / f"{model_key}.log",
                maximum_rss_bytes=maximum_rss,
                poll_milliseconds=poll,
                subject=f"producer:{model_key}",
            )
            supervision.append(receipt_value)
            write_new_bytes(
                output_root / "supervision" / f"{model_key}.json",
                canonical_json_bytes(receipt_value) + b"\n",
            )
            if receipt_value["exitCode"] != 0:
                raise DevelopmentControlError(
                    f"development child failed: producer:{model_key}: "
                    f"exit {receipt_value['exitCode']}"
                )
            worker_summary = load_json_strict(
                output_root / "workers" / model_key / "worker-summary.json"
            )
            validate_worker_summary(
                worker_summary,
                model_key=model_key,
                plan=plan,
                output_root=output_root,
            )
        consolidate_worker_evidence(result_root=output_root, model_order=MODELS)
        arguments._control_phase = "independent-real-model-replay"
        try:
            safety = wait_for_primary_host_safety(
                design, output_parent=output_root
            )
        except DevelopmentRuntimeError as error:
            raise DevelopmentControlError(
                "development host safety gate failed before independent replay"
            ) from error
        host_safety_checks.append({"phase": "before-independent-replay", **safety})
        command, backend = _development_child_command(
            BLIND_V1_ROOT / "development_model_replay.py",
            "--evidence-root",
            str(output_root),
            "--private-root",
            str(private_root),
        )
        if backend != sandbox_backend:
            raise DevelopmentControlError("development replay sandbox backend differs")
        replay_receipt = _supervise_development_child(
            command,
            cwd=PROJECT_ROOT,
            environment=environment,
            log_path=output_root / "logs" / "independent-development-replay.log",
            maximum_rss_bytes=maximum_rss,
            poll_milliseconds=poll,
            subject="independent-real-model-replay",
        )
        supervision.append(replay_receipt)
        write_new_bytes(
            output_root / "supervision" / "independent-development-replay.json",
            canonical_json_bytes(replay_receipt) + b"\n",
        )
        if replay_receipt["exitCode"] != 0:
            raise DevelopmentControlError(
                "development child failed: independent-real-model-replay: "
                f"exit {replay_receipt['exitCode']}"
            )
        replay_summary = load_json_strict(
            output_root / "independent-development-replay.json"
        )
        try:
            verify_content_digest(replay_summary)
        except ValueError as error:
            raise DevelopmentControlError("development replay summary digest differs") from error
        validate_replay_summary(replay_summary, plan=plan)
        if _tracked_sources() != bindings["controlSources"]:
            raise DevelopmentControlError(
                "development control sources changed during execution"
            )
        if verify_codec(arguments.codec_root, design) != bindings["codecSource"]:
            raise DevelopmentControlError(
                "development codec source changed during execution"
            )
        final_source_gate = (
            verify_post_release_source()
            if post_release_regression
            else verify_canonical_execution_source()
        )
        if post_release_regression:
            final_source_gate = final_source_gate["executionSource"]
        if final_source_gate != bindings["labSource"]:
            raise DevelopmentControlError(
                "development lab source changed during execution"
            )
        completed = _utc_now()
        verify_development_lifecycle(
            design,
            now=datetime.strptime(completed, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            ),
            allow_after_cutoff_for_post_release_regression=(
                post_release_regression
            ),
        )
        inventory = _artifact_inventory(output_root)
        report_payload: dict[str, Any] = {
            "schemaVersion": REPORT_SCHEMA,
            "suiteId": SUITE_ID,
            "executionId": execution_id,
            "runId": plan["runId"],
            "status": "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_PASS",
            "countsTowardScientificVerdict": False,
            "usedForCandidateSelectionOrTuning": False,
            "scientificAttemptStateCreated": False,
            "nistUsed": False,
            "futureCorpusUsed": False,
            "thresholdsApplied": False,
            "candidateCodecInvoked": True,
            "realModelsUsed": True,
            "realDevelopmentCorpusUsed": True,
            "independentRealModelReplayComplete": True,
            "startedAt": started,
            "completedAt": completed,
            "controlConfigurationSHA256": plan["controlConfigurationSHA256"],
            "plan": _digest_bytes(
                (output_root / "development-plan.json").read_bytes()
            ),
            "inputs": bindings,
            "runtime": runtime_probe,
            "hostSafetyChecks": host_safety_checks,
            "networkIsolationBackend": sandbox_backend,
            "workerProcessesSequential": True,
            "replayModelsSequential": True,
            "supervision": supervision,
            "independentReplay": replay_summary,
            "artifactInventory": inventory,
            "artifactSetSHA256": sha256_bytes(canonical_json_bytes(inventory)),
            "scientificClaim": "forbidden",
            "candidateSelectionOrTuning": "forbidden",
        }
        report_filename = "development-control-report.json"
        if post_release_regression:
            report_filename = "post-release-regression-report.json"
            report_payload.update(
                {
                    "schemaVersion": POST_RELEASE_REPORT_SCHEMA,
                    "status": (
                        "NON_SCIENTIFIC_POST_RELEASE_REAL_MODEL_REGRESSION_PASS"
                    ),
                    "executionClass": POST_RELEASE_PROFILE,
                    "canonicalDevelopmentControlPackaging": "forbidden",
                    "scientificEvidenceUse": "forbidden",
                    "frozenDevelopmentSource": dict(frozen_source or {}),
                }
            )
        report = _with_content_digest(report_payload)
        if post_release_regression:
            validate_post_release_regression_report(report)
        else:
            try:
                validate_development_control_report(
                    report,
                    completed_no_later_than=DEVELOPMENT_COMPLETE_NO_LATER_THAN,
                )
            except FreezeManifestError as error:
                raise DevelopmentControlError(
                    "development PASS report failed its canonical verifier"
                ) from error
        # This report is the final completion marker.  Partial runs have no report.
        write_new_bytes(
            output_root / report_filename,
            canonical_json_bytes(report) + b"\n",
        )
        arguments._control_phase = "complete"
        return report


def _write_failure_receipt(arguments: argparse.Namespace, error: Exception) -> None:
    output_root = getattr(arguments, "_claimed_output_root", None)
    if not isinstance(output_root, Path):
        return
    post_release_regression = getattr(
        arguments, "_post_release_regression", False
    )
    if post_release_regression:
        start_path = output_root / "post-release-regression-start.json"
        pass_path = output_root / "post-release-regression-report.json"
        failure_path = output_root / "post-release-regression-failure.json"
    else:
        start_path = output_root / "development-control-start.json"
        pass_path = output_root / "development-control-report.json"
        failure_path = output_root / "development-control-failure.json"
    if not start_path.is_file() or pass_path.exists() or failure_path.exists():
        return
    context = getattr(arguments, "_control_context", {})
    if not isinstance(context, dict):
        context = {}
    try:
        inventory = _artifact_inventory(output_root)
        inventory_complete = True
        inventory_error = None
    except Exception as inventory_exception:
        inventory = []
        inventory_complete = False
        inventory_error = type(inventory_exception).__name__
    failure_payload: dict[str, Any] = {
        "schemaVersion": "corelm-blind-crossmodel-v1-real-e2e-development-failure-v1",
        "suiteId": SUITE_ID,
        "executionId": getattr(arguments, "_execution_id", None),
        "runId": context.get("runId"),
        "status": "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_FAIL",
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "startedAt": getattr(arguments, "_control_started_at", None),
        "completedAt": _utc_now(),
        "failurePhase": getattr(arguments, "_control_phase", "unknown"),
        "failureType": type(error).__name__,
        "failureReason": str(error)[:4096],
        "controlConfigurationSHA256": context.get(
            "controlConfigurationSHA256"
        ),
        "inputBindings": context.get("inputBindings"),
        "runtime": context.get("runtime"),
        "hostSafetyChecks": context.get("hostSafetyChecks"),
        "artifactInventoryComplete": inventory_complete,
        "artifactInventoryError": inventory_error,
        "artifactInventory": inventory,
        "artifactSetSHA256": sha256_bytes(canonical_json_bytes(inventory)),
        "scientificClaim": "forbidden",
        "candidateSelectionOrTuning": "forbidden",
    }
    if post_release_regression:
        frozen_source = getattr(arguments, "_verified_source", None)
        failure_payload.update(
            {
                "schemaVersion": (
                    "corelm-blind-crossmodel-v1-real-e2e-post-release-regression-failure-v1"
                ),
                "status": "NON_SCIENTIFIC_POST_RELEASE_REAL_MODEL_REGRESSION_FAIL",
                "executionClass": POST_RELEASE_PROFILE,
                "canonicalDevelopmentControlPackaging": "forbidden",
                "scientificEvidenceUse": "forbidden",
                "frozenDevelopmentSource": (
                    frozen_source if isinstance(frozen_source, dict) else None
                ),
            }
        )
    failure = _with_content_digest(failure_payload)
    write_new_bytes(failure_path, canonical_json_bytes(failure) + b"\n")


def run_control(
    arguments: argparse.Namespace, *, post_release_regression: bool = False
) -> dict[str, Any]:
    if type(post_release_regression) is not bool:
        raise DevelopmentControlError("execution profile is invalid")
    if not post_release_regression:
        require_scientific_schedule_open(
            operation="run Blind V1 development control"
        )
    return _historical_run_control(
        arguments, post_release_regression=post_release_regression
    )


def _historical_run_control(
    arguments: argparse.Namespace, *, post_release_regression: bool = False
) -> dict[str, Any]:
    """Run historical control mechanics; public use is regression-only."""

    if type(post_release_regression) is not bool:
        raise DevelopmentControlError("execution profile is invalid")
    started = _utc_now()
    prefix = (
        "post-release-regression-execution-"
        if post_release_regression
        else "development-execution-"
    )
    execution_id = (
        prefix
        + started.replace("-", "").replace(":", "")
        + "-"
        + secrets.token_hex(8)
    )
    arguments._execution_id = execution_id
    arguments._control_started_at = started
    arguments._post_release_regression = post_release_regression
    try:
        return _run_control(
            arguments,
            started=started,
            execution_id=execution_id,
            post_release_regression=post_release_regression,
        )
    except Exception as error:
        try:
            _write_failure_receipt(arguments, error)
        except Exception:
            pass
        raise


def parse_arguments(
    argv: list[str] | None = None, *, post_release_regression: bool = False
) -> argparse.Namespace:
    description = __doc__
    if post_release_regression:
        description = (
            "Run the fixed real-data BLIND_V1 workload only as a non-scientific "
            "post-release development regression."
        )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--codec-root", type=Path, required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(*, post_release_regression: bool = False) -> int:
    arguments = parse_arguments(
        post_release_regression=post_release_regression
    )
    try:
        if not post_release_regression:
            require_scientific_schedule_open(
                operation="run Blind V1 real-model development control CLI"
            )
        report = run_control(
            arguments,
            post_release_regression=post_release_regression,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        DevelopmentControlError,
        DevelopmentReplayError,
        DevelopmentRuntimeError,
    ) as error:
        failure_label = (
            "POST-RELEASE REAL-MODEL REGRESSION FAIL"
            if post_release_regression
            else "REAL E2E DEVELOPMENT CONTROL FAIL"
        )
        print(f"{failure_label}: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "runId": report["runId"],
                "countsTowardScientificVerdict": False,
                "usedForCandidateSelectionOrTuning": False,
                "contentSHA256": report["contentSHA256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
