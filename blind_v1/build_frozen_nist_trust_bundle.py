#!/usr/bin/env python3
"""Promote the tracked candidate NIST trust bundle into a frozen external copy.

The command performs no network access. It validates the exact tracked
candidate with both independent X.509 implementations, copies every committed
PEM/DER byte into a new self-contained directory, changes only the manifest
status, verifies the resulting frozen bundle again, and never overwrites an
existing path.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.independent_verifier_core import (  # noqa: E402
    IndependentVerificationError,
    load_independent_trust_bundle,
)
from blind_v1.nist_beacon import (  # noqa: E402
    BeaconVerificationError,
    NIST_TRUST_ROOT_DER_SHA256,
    TRUST_CANDIDATE_STATUS,
    TRUST_FROZEN_STATUS,
    load_offline_trust_bundle,
)
from blind_v1.protocol import (  # noqa: E402
    load_json_strict_bytes,
    require_scientific_schedule_open,
)
from blind_v1.reproducibility import (  # noqa: E402
    _assert_safe_output_parent,
    _fsync_directory,
    canonical_json_bytes,
    sha256_bytes,
    write_new_bytes,
)


TRACKED_CANDIDATE_MANIFEST = BLIND_V1_ROOT / "trust" / "nist" / "manifest.json"
TARGET_TIME = datetime(2026, 8, 21, 18, 0, 0, tzinfo=timezone.utc)
CANDIDATE_MANIFEST_SHA256 = (
    "cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706"
)
FROZEN_MANIFEST_SHA256 = (
    "5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a"
)
FROZEN_MANIFEST_BYTES = 1_930
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA512 = re.compile(r"[0-9a-f]{128}\Z")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_COMMITTED_FILE_BYTES = 16 * 1024 * 1024


class FrozenNISTTrustBuildError(ValueError):
    """The candidate cannot be promoted without weakening its commitments."""


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FrozenNISTTrustBuildError(f"cannot inspect input: {path}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 1 <= metadata.st_size <= maximum_bytes
    ):
        raise FrozenNISTTrustBuildError(f"input is not a bounded regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FrozenNISTTrustBuildError(f"cannot open input safely: {path}") from error
    try:
        value = bytearray()
        while len(value) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(value) != metadata.st_size
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise FrozenNISTTrustBuildError(f"input changed while reading: {path}")
    return bytes(value)


def _safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FrozenNISTTrustBuildError("committed trust path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise FrozenNISTTrustBuildError("committed trust path is unsafe")
    return path


def _read_commitment(root: Path, commitment: Any) -> tuple[PurePosixPath, bytes]:
    if not isinstance(commitment, Mapping):
        raise FrozenNISTTrustBuildError("trust commitment is not an object")
    fields = set(commitment)
    if fields not in (
        {"relativePath", "bytes", "sha256"},
        {"relativePath", "bytes", "sha256", "sha512"},
    ):
        raise FrozenNISTTrustBuildError("trust commitment fields differ")
    relative = _safe_relative(commitment["relativePath"])
    current = root
    for component in relative.parts:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise FrozenNISTTrustBuildError(
                f"committed trust path is missing: {relative}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise FrozenNISTTrustBuildError(
                f"committed trust path contains a symlink: {relative}"
            )
    raw = _read_regular(current, maximum_bytes=MAX_COMMITTED_FILE_BYTES)
    if type(commitment["bytes"]) is not int or commitment["bytes"] != len(raw):
        raise FrozenNISTTrustBuildError("committed trust byte count differs")
    if (
        not isinstance(commitment["sha256"], str)
        or SHA256.fullmatch(commitment["sha256"]) is None
        or sha256_bytes(raw) != commitment["sha256"]
    ):
        raise FrozenNISTTrustBuildError("committed trust SHA-256 differs")
    if "sha512" in commitment and (
        not isinstance(commitment["sha512"], str)
        or SHA512.fullmatch(commitment["sha512"]) is None
        or hashlib.sha512(raw).hexdigest() != commitment["sha512"]
    ):
        raise FrozenNISTTrustBuildError("committed trust SHA-512 differs")
    return relative, raw


def _committed_files(manifest: Mapping[str, Any], root: Path) -> dict[PurePosixPath, bytes]:
    certificates = manifest.get("certificates")
    if not isinstance(certificates, Mapping) or len(certificates) != 1:
        raise FrozenNISTTrustBuildError("candidate certificate map is not singleton")
    files: dict[PurePosixPath, bytes] = {}
    for specification in certificates.values():
        if not isinstance(specification, Mapping):
            raise FrozenNISTTrustBuildError("candidate certificate specification differs")
        commitments: list[Any] = [specification.get("pem")]
        chain = specification.get("chain")
        if not isinstance(chain, list):
            raise FrozenNISTTrustBuildError("candidate certificate chain differs")
        commitments.extend(chain)
        for commitment in commitments:
            relative, raw = _read_commitment(root, commitment)
            if relative in files:
                raise FrozenNISTTrustBuildError("candidate repeats a committed path")
            files[relative] = raw
    return files


def _require_external_new_root(output_root: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(output_root)))
    project = PROJECT_ROOT.resolve(strict=True)
    try:
        common = Path(os.path.commonpath((os.fspath(absolute), os.fspath(project))))
    except ValueError as error:
        raise FrozenNISTTrustBuildError("output path cannot be compared safely") from error
    if common == project:
        raise FrozenNISTTrustBuildError(
            "frozen NIST trust output must be outside the tracked project"
        )
    _assert_safe_output_parent(absolute)
    try:
        absolute.lstat()
    except FileNotFoundError:
        return absolute
    raise FileExistsError(f"frozen NIST trust output already exists: {absolute}")


def _different_paths(
    left: Any, right: Any, prefix: tuple[Any, ...] = ()
) -> set[tuple[Any, ...]]:
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        paths: set[tuple[Any, ...]] = set()
        for key in set(left) | set(right):
            if key not in left or key not in right:
                paths.add(prefix + (key,))
            else:
                paths.update(
                    _different_paths(left[key], right[key], prefix + (key,))
                )
        return paths
    if isinstance(left, list):
        if len(left) != len(right):
            return {prefix}
        paths: set[tuple[Any, ...]] = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            paths.update(
                _different_paths(left_item, right_item, prefix + (index,))
            )
        return paths
    return set() if left == right else {prefix}


def assert_status_only_promotion(
    candidate: Mapping[str, Any], promoted: Mapping[str, Any]
) -> None:
    if (
        candidate.get("status") != TRUST_CANDIDATE_STATUS
        or promoted.get("status") != TRUST_FROZEN_STATUS
        or _different_paths(candidate, promoted) != {("status",)}
    ):
        raise FrozenNISTTrustBuildError(
            "promotion must change exactly candidate status to frozen"
        )


def _remove_staging(staging: Path, expected_parent: Path) -> None:
    """Remove only the exact private sibling staging tree created by this process."""

    if (
        staging.parent != expected_parent
        or not staging.name.startswith(".corelm-nist-trust-staging-")
    ):
        raise FrozenNISTTrustBuildError("refusing unsafe staging cleanup")
    try:
        metadata = staging.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FrozenNISTTrustBuildError("refusing non-directory staging cleanup")
    shutil.rmtree(staging)
    _fsync_directory(expected_parent)


def _at_fdcwd_for_platform(platform_name: str) -> int:
    """Return the native ``AT_FDCWD`` ABI value for a supported host."""

    if platform_name == "darwin":
        return -2
    if platform_name.startswith("linux"):
        return -100
    raise FrozenNISTTrustBuildError(
        "platform lacks atomic exclusive directory publication"
    )


def _publish_directory_exclusive(staging: Path, destination: Path) -> None:
    """Atomically rename a directory while refusing any existing destination."""

    library = ctypes.CDLL(None, use_errno=True)
    source_raw = os.fsencode(staging)
    destination_raw = os.fsencode(destination)
    if sys.platform == "darwin":
        at_fdcwd = _at_fdcwd_for_platform(sys.platform)
        try:
            operation = library.renameatx_np
        except AttributeError as error:
            raise FrozenNISTTrustBuildError(
                "platform lacks atomic exclusive directory publication"
            ) from error
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        operation.restype = ctypes.c_int
        result = operation(
            at_fdcwd,
            source_raw,
            at_fdcwd,
            destination_raw,
            0x00000004,  # RENAME_EXCL
        )
    elif sys.platform.startswith("linux"):
        at_fdcwd = _at_fdcwd_for_platform(sys.platform)
        try:
            operation = library.renameat2
        except AttributeError as error:
            raise FrozenNISTTrustBuildError(
                "platform lacks atomic exclusive directory publication"
            ) from error
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        operation.restype = ctypes.c_int
        result = operation(
            at_fdcwd,
            source_raw,
            at_fdcwd,
            destination_raw,
            0x00000001,  # RENAME_NOREPLACE
        )
    else:
        _at_fdcwd_for_platform(sys.platform)
        raise AssertionError("unreachable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(
            error_number,
            os.strerror(error_number),
            os.fspath(destination),
        )
    raise OSError(
        error_number,
        os.strerror(error_number),
        os.fspath(destination),
    )


def build_frozen_nist_trust_bundle(*, output_root: Path) -> dict[str, Any]:
    """Validate and promote the exact tracked candidate into a new bundle root."""

    require_scientific_schedule_open(operation="build frozen NIST trust bundle")
    return _historical_build_frozen_nist_trust_bundle(output_root=output_root)


def _historical_build_frozen_nist_trust_bundle(
    *, output_root: Path
) -> dict[str, Any]:
    """Retain the frozen-bundle structure for offline historical fixtures."""

    candidate_path = TRACKED_CANDIDATE_MANIFEST
    candidate_raw = _read_regular(candidate_path, maximum_bytes=MAX_MANIFEST_BYTES)
    candidate_sha256 = sha256_bytes(candidate_raw)
    candidate = load_json_strict_bytes(candidate_raw, label="candidate NIST trust")
    if (
        not isinstance(candidate, dict)
        or canonical_json_bytes(candidate) != candidate_raw
        or candidate_sha256 != CANDIDATE_MANIFEST_SHA256
        or candidate.get("status") != TRUST_CANDIDATE_STATUS
        or candidate.get("fixtureOnly") is not False
    ):
        raise FrozenNISTTrustBuildError(
            "tracked NIST trust input is not a canonical production candidate"
        )
    try:
        producer = load_offline_trust_bundle(
            candidate_path,
            expected_time=TARGET_TIME,
            expected_manifest_sha256=candidate_sha256,
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
            allow_fixture=False,
            allow_candidate=True,
        )
        independent = load_independent_trust_bundle(
            candidate_path,
            expected_time=TARGET_TIME,
            expected_manifest_sha256=candidate_sha256,
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
            allow_known_answer_fixture=False,
            allow_candidate=True,
        )
    except (BeaconVerificationError, IndependentVerificationError, OSError) as error:
        raise FrozenNISTTrustBuildError(
            "tracked candidate failed independent offline trust verification"
        ) from error
    if (
        producer.fixture_only
        or independent.fixture_only
        or tuple(producer.records) != tuple(independent.records)
        or len(producer.records) != 1
        or not all(record.chain_verified for record in producer.records.values())
        or not all(record.chain_verified for record in independent.records.values())
    ):
        raise FrozenNISTTrustBuildError("candidate verifier results disagree")

    committed_files = _committed_files(candidate, candidate_path.parent)
    promoted = deepcopy(candidate)
    promoted["status"] = TRUST_FROZEN_STATUS
    assert_status_only_promotion(candidate, promoted)
    frozen_raw = canonical_json_bytes(promoted)
    destination = _require_external_new_root(output_root)
    frozen_sha256 = sha256_bytes(frozen_raw)
    if (
        len(frozen_raw) != FROZEN_MANIFEST_BYTES
        or frozen_sha256 != FROZEN_MANIFEST_SHA256
    ):
        raise FrozenNISTTrustBuildError(
            "status-normalized frozen manifest differs from the preregistered bytes"
        )
    staging = Path(
        tempfile.mkdtemp(
            prefix=".corelm-nist-trust-staging-",
            dir=destination.parent,
        )
    )
    published = False
    try:
        for relative in sorted(
            committed_files, key=lambda item: item.as_posix()
        ):
            write_new_bytes(
                staging / Path(*relative.parts), committed_files[relative]
            )
        staging_manifest_path = staging / "manifest.json"
        write_new_bytes(staging_manifest_path, frozen_raw)
        frozen_producer = load_offline_trust_bundle(
            staging_manifest_path,
            expected_time=TARGET_TIME,
            expected_manifest_sha256=frozen_sha256,
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
            allow_fixture=False,
        )
        frozen_independent = load_independent_trust_bundle(
            staging_manifest_path,
            expected_time=TARGET_TIME,
            expected_manifest_sha256=frozen_sha256,
            expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
            allow_known_answer_fixture=False,
        )
        certificate_id = next(iter(frozen_producer.records))
        if (
            tuple(frozen_producer.records) != tuple(frozen_independent.records)
            or not frozen_producer.records[certificate_id].chain_verified
            or not frozen_independent.records[certificate_id].chain_verified
        ):
            raise FrozenNISTTrustBuildError(
                "promoted verifier results disagree"
            )
        assert_status_only_promotion(
            candidate,
            load_json_strict_bytes(
                staging_manifest_path.read_bytes(),
                label="staged frozen NIST trust",
            ),
        )
        _fsync_directory(staging)
        _publish_directory_exclusive(staging, destination)
        _fsync_directory(destination.parent)
        published = True
    except (BeaconVerificationError, IndependentVerificationError) as error:
        raise FrozenNISTTrustBuildError(
            "promoted bundle failed independent offline verification"
        ) from error
    finally:
        if not published:
            _remove_staging(staging, destination.parent)
    manifest_path = destination / "manifest.json"
    return {
        "status": "FROZEN_NIST_TRUST_BUNDLE_BUILT",
        "outputRoot": str(destination),
        "manifestPath": str(manifest_path),
        "candidateManifestSHA256": candidate_sha256,
        "frozenManifestSHA256": frozen_sha256,
        "frozenManifestBytes": len(frozen_raw),
        "certificateId": certificate_id,
        "copiedFiles": [item.as_posix() for item in sorted(committed_files, key=str)],
        "onlyStatusChanged": True,
        "producerVerified": True,
        "independentVerified": True,
        "networkUsed": False,
        "pulseFetched": False,
        "modelInferenceUsed": False,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        require_scientific_schedule_open(
            operation="run frozen Blind V1 NIST trust-bundle builder"
        )
        report = build_frozen_nist_trust_bundle(output_root=arguments.output_root)
    except (OSError, ValueError) as error:
        print(f"FROZEN NIST TRUST BUILD FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
