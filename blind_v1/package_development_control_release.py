#!/usr/bin/env python3
"""Package and verify the three pre-freeze development-control release assets.

This command does not publish anything and cannot create a scientific result.
It first re-verifies the completed real-model development control, then writes
one deterministic uncompressed ZIP, the exact PASS report, and a canonical
non-self-referential SHA-256 manifest.  A later GitHub release receipt must
bind all three assets before the implementation freeze can be created. The
archive includes the exact PUD source, license, README, attribution notice,
and a machine-readable rights declaration; all are reverified before output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.freeze_manifest import (  # noqa: E402
    DESIGN_PUBLISH_DEADLINE,
    DEVELOPMENT_ARCHIVE_MAX_BYTES,
    DEVELOPMENT_ARCHIVE_MANIFEST_SCHEMA,
    DEVELOPMENT_RIGHTS_DECLARATION,
    DEVELOPMENT_SUITE_ID,
    MAX_DEVELOPMENT_REPORT_BYTES,
    MAX_RUNTIME_MANIFEST_BYTES,
    FreezeManifestError,
    _load_canonical_line_bytes,
    _read_bound_development_artifact,
    _validate_development_archive_manifest,
    _verify_development_archive_zip,
    read_regular_bytes,
    verify_development_control_report,
)
from blind_v1.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    with_content_digest,
)


ASSET_NAMES = (
    "development-control-report.json",
    "development-control-artifacts.zip",
    "sha256-manifest.json",
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
READ_CHUNK_BYTES = 1024 * 1024
ZIP_PREFLIGHT_FIXED_OVERHEAD_BYTES = 64 * 1024
ZIP_PREFLIGHT_MEMBER_OVERHEAD_BYTES = 256


class DevelopmentControlPackageError(RuntimeError):
    """The local release asset set is incomplete, unsafe, or inconsistent."""


def _archive_size_upper_bound(
    inventory: Sequence[Mapping[str, Any]],
) -> int:
    """Conservatively bound the deterministic stored ZIP before creating it."""

    total = ZIP_PREFLIGHT_FIXED_OVERHEAD_BYTES
    paths: set[str] = set()
    for item in inventory:
        relative = item.get("path")
        byte_count = item.get("bytes")
        if (
            not isinstance(relative, str)
            or not relative
            or relative in paths
            or type(byte_count) is not int
            or byte_count <= 0
        ):
            raise DevelopmentControlPackageError(
                "development archive inventory is invalid"
            )
        paths.add(relative)
        total += (
            byte_count
            + ZIP_PREFLIGHT_MEMBER_OVERHEAD_BYTES
            + 2 * len(os.fsencode(relative))
        )
        if total >= DEVELOPMENT_ARCHIVE_MAX_BYTES:
            return total
    return total


def _bounded_archive_commitment(path: Path) -> tuple[int, str]:
    """Stream one no-follow archive under the conservative release-file cap."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DevelopmentControlPackageError(
            "development archive is not a no-follow regular file"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size >= DEVELOPMENT_ARCHIVE_MAX_BYTES
        ):
            raise DevelopmentControlPackageError(
                "development archive exceeds the release-file size cap"
            )
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            if observed >= DEVELOPMENT_ARCHIVE_MAX_BYTES:
                raise DevelopmentControlPackageError(
                    "development archive exceeds the release-file size cap"
                )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or observed != before.st_size
        ):
            raise DevelopmentControlPackageError(
                "development archive changed while hashing"
            )
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)


def _write_new_read_only(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    published = False
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing development asset")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _cleanup_owned_output(root: Path) -> None:
    try:
        os.chmod(root, 0o700, follow_symlinks=False)
    except OSError:
        return
    for name in ASSET_NAMES:
        path = root / name
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            try:
                os.unlink(path)
            except OSError:
                pass
    try:
        os.rmdir(root)
    except OSError:
        pass


def _write_archive(
    path: Path,
    *,
    artifact_root: Path,
    inventory: Sequence[Mapping[str, Any]],
) -> tuple[int, str]:
    projected_bytes = _archive_size_upper_bound(inventory)
    if projected_bytes >= DEVELOPMENT_ARCHIVE_MAX_BYTES:
        raise DevelopmentControlPackageError(
            "development archive cannot fit below the release-file size cap"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    published = False
    try:
        inventory_by_path = {item["path"]: item for item in inventory}
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            with zipfile.ZipFile(
                stream,
                mode="w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
                strict_timestamps=True,
            ) as archive:
                archive.comment = b""
                for relative in sorted(inventory_by_path, key=os.fsencode):
                    commitment = inventory_by_path[relative]
                    raw = _read_bound_development_artifact(
                        artifact_root,
                        inventory_by_path,
                        relative,
                        maximum_bytes=512 * 1024 * 1024,
                    )
                    information = zipfile.ZipInfo(relative, date_time=ZIP_TIMESTAMP)
                    information.compress_type = zipfile.ZIP_STORED
                    information.create_system = 3
                    information.external_attr = (stat.S_IFREG | 0o444) << 16
                    information.extra = b""
                    information.comment = b""
                    information.file_size = commitment["bytes"]
                    with archive.open(
                        information, mode="w", force_zip64=True
                    ) as member:
                        member.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.fstat(descriptor).st_size >= DEVELOPMENT_ARCHIVE_MAX_BYTES:
            raise DevelopmentControlPackageError(
                "development archive exceeds the release-file size cap"
            )
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    return _bounded_archive_commitment(path)


def verify_development_control_release_assets(
    asset_root: Path,
    *,
    expected_report_path: Path | None = None,
) -> dict[str, Any]:
    """Re-open a local three-asset package without claiming GitHub publication."""

    root = Path(os.path.abspath(os.fspath(asset_root)))
    try:
        metadata = os.lstat(root)
    except OSError as error:
        raise DevelopmentControlPackageError("asset root is absent") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DevelopmentControlPackageError("asset root is not a safe directory")
    if sorted(os.listdir(root), key=os.fsencode) != sorted(
        ASSET_NAMES, key=os.fsencode
    ):
        raise DevelopmentControlPackageError("release asset inventory differs")
    report_path = root / "development-control-report.json"
    report_raw = read_regular_bytes(
        report_path, maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES
    )
    if expected_report_path is not None:
        expected_raw = read_regular_bytes(
            expected_report_path, maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES
        )
        if report_raw != expected_raw:
            raise DevelopmentControlPackageError(
                "packaged report differs from completed report"
            )
    report = _load_canonical_line_bytes(
        report_raw, label="packaged development-control report"
    )
    summary = verify_development_control_report(
        report_path,
        completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
        require_artifacts=False,
    )
    archive_path = root / "development-control-artifacts.zip"
    archive_bytes, archive_sha256 = _bounded_archive_commitment(archive_path)
    _verify_development_archive_zip(
        archive_path,
        inventory=report["artifactInventory"],
        expected_sha256=archive_sha256,
    )
    manifest_raw = read_regular_bytes(
        root / "sha256-manifest.json",
        maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES,
    )
    manifest = _load_canonical_line_bytes(
        manifest_raw, label="development archive SHA-256 manifest"
    )
    _validate_development_archive_manifest(
        manifest,
        report_summary=summary,
        report_raw=report_raw,
        archive_bytes=archive_bytes,
        archive_sha256=archive_sha256,
    )
    return {
        "status": "VERIFIED_LOCAL_DEVELOPMENT_CONTROL_RELEASE_ASSETS",
        "executionId": summary["executionId"],
        "artifactCount": summary["artifactCount"],
        "artifactSetSHA256": summary["artifactSetSHA256"],
        "reportSHA256": sha256_bytes(report_raw),
        "artifactArchiveSHA256": archive_sha256,
        "archiveManifestSHA256": sha256_bytes(manifest_raw),
    }


def package_development_control_release(
    *,
    report_path: Path,
    artifact_root: Path,
    runtime_manifest_path: Path,
    lab_repository: str,
    lab_commit: str,
    lab_tree: str,
    codec_repository: str,
    codec_commit: str,
    codec_tree: str,
    output_root: Path,
) -> dict[str, Any]:
    """Create a new local package after re-verifying every real-data artifact."""

    runtime_raw = read_regular_bytes(
        runtime_manifest_path, maximum_bytes=MAX_RUNTIME_MANIFEST_BYTES
    )
    implementation = {
        "repository": lab_repository,
        "commit": lab_commit,
        "tree": lab_tree,
    }
    codec = {
        "repository": codec_repository,
        "commit": codec_commit,
        "tree": codec_tree,
    }
    summary = verify_development_control_report(
        report_path,
        artifact_root=artifact_root,
        expected_implementation=implementation,
        expected_codec=codec,
        completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
        expected_runtime_manifest_sha256=sha256_bytes(runtime_raw),
        require_artifacts=True,
    )
    report_raw = read_regular_bytes(
        report_path, maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES
    )
    report = _load_canonical_line_bytes(
        report_raw, label="development-control report"
    )
    output = Path(os.path.abspath(os.fspath(output_root)))
    try:
        os.mkdir(output, 0o700)
    except OSError as error:
        raise DevelopmentControlPackageError(
            "output root already exists or cannot be created"
        ) from error
    try:
        _write_new_read_only(output / ASSET_NAMES[0], report_raw)
        archive_bytes, archive_sha256 = _write_archive(
            output / ASSET_NAMES[1],
            artifact_root=Path(os.path.abspath(os.fspath(artifact_root))),
            inventory=report["artifactInventory"],
        )
        manifest = with_content_digest(
            {
                "schemaVersion": DEVELOPMENT_ARCHIVE_MANIFEST_SCHEMA,
                "suiteId": DEVELOPMENT_SUITE_ID,
                "executionId": summary["executionId"],
                "status": (
                    "COMPLETE_NON_SCIENTIFIC_DEVELOPMENT_ARCHIVE_INVENTORY"
                ),
                "countsTowardScientificVerdict": False,
                "usedForCandidateSelectionOrTuning": False,
                "scientificAttemptStateCreated": False,
                "nistUsed": False,
                "futureCorpusUsed": False,
                "thresholdsApplied": False,
                "artifactSetSHA256": summary["artifactSetSHA256"],
                "artifactCount": summary["artifactCount"],
                "rights": dict(DEVELOPMENT_RIGHTS_DECLARATION),
                "assets": [
                    {
                        "role": "development-control-report",
                        "name": ASSET_NAMES[0],
                        "bytes": len(report_raw),
                        "sha256": sha256_bytes(report_raw),
                    },
                    {
                        "role": "development-control-artifacts",
                        "name": ASSET_NAMES[1],
                        "bytes": archive_bytes,
                        "sha256": archive_sha256,
                    },
                ],
                "excludedRole": "sha256-manifest",
                "selfReferencePolicy": (
                    "MANIFEST_EXCLUDES_ONLY_ITS_OWN_FILE_BYTES;"
                    "GITHUB_RELEASE_ATTESTATION_BINDS_ALL_THREE_ASSETS"
                ),
            }
        )
        manifest_raw = canonical_json_bytes(manifest) + b"\n"
        _write_new_read_only(output / ASSET_NAMES[2], manifest_raw)
        os.chmod(output, 0o555, follow_symlinks=False)
        verification = verify_development_control_release_assets(
            output, expected_report_path=report_path
        )
        verification["outputRoot"] = str(output)
        return verification
    except Exception:
        _cleanup_owned_output(output)
        raise


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    package = subparsers.add_parser("package")
    package.add_argument("--report", type=Path, required=True)
    package.add_argument("--artifact-root", type=Path, required=True)
    package.add_argument("--runtime-manifest", type=Path, required=True)
    package.add_argument("--lab-repository", required=True)
    package.add_argument("--lab-commit", required=True)
    package.add_argument("--lab-tree", required=True)
    package.add_argument("--codec-repository", required=True)
    package.add_argument("--codec-commit", required=True)
    package.add_argument("--codec-tree", required=True)
    package.add_argument("--output-root", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--asset-root", type=Path, required=True)
    verify.add_argument("--expected-report", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "package":
            report = package_development_control_release(
                report_path=arguments.report,
                artifact_root=arguments.artifact_root,
                runtime_manifest_path=arguments.runtime_manifest,
                lab_repository=arguments.lab_repository,
                lab_commit=arguments.lab_commit,
                lab_tree=arguments.lab_tree,
                codec_repository=arguments.codec_repository,
                codec_commit=arguments.codec_commit,
                codec_tree=arguments.codec_tree,
                output_root=arguments.output_root,
            )
        else:
            report = verify_development_control_release_assets(
                arguments.asset_root,
                expected_report_path=arguments.expected_report,
            )
    except (DevelopmentControlPackageError, FreezeManifestError, OSError, ValueError) as error:
        print(f"DEVELOPMENT CONTROL PACKAGE FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
