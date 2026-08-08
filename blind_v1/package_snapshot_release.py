#!/usr/bin/env python3
"""Build and independently verify the five blind-v1 snapshot release assets.

The packager is deliberately offline and uses only the Python standard
library.  It preserves every byte and relative path in the verified corpus
root in a deterministic, uncompressed ZIP archive.  The generated attribution
file copies only attribution and source fields already present in the corpus
manifest; it never synthesizes a license assertion.

The SHA-256 manifest covers the other four assets and explicitly excludes
itself.  Its own byte count and digest are supplied later by the signed GitHub
release receipt, avoiding an impossible self-reference.

This module checks the internal content digest of the already-created design
publication receipt but does not re-run Git/SSH or GitHub API
verification.  ``blind_v1.release_receipt`` remains the independent verifier for
that receipt and for the eventual snapshot release receipt.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Mapping


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.protocol import (
    require_scientific_schedule_open,
    validate_snapshot_registration,
)


SUITE_ID = "corelm-blind-crossmodel-v1"
SNAPSHOT_SCHEMA = "corelm-blind-crossmodel-v1-snapshot-registration-v1"
CORPUS_SCHEMA = "corelm-blind-crossmodel-v1-corpus-manifest-v1"
DESIGN_RECEIPT_SCHEMA = "corelm-github-release-receipt-v2"
ATTRIBUTION_SCHEMA = "corelm-blind-crossmodel-v1-snapshot-attribution-v1"
SHA256_MANIFEST_SCHEMA = (
    "corelm-blind-crossmodel-v1-snapshot-release-sha256-manifest-v1"
)
VERIFICATION_SCHEMA = (
    "corelm-blind-crossmodel-v1-snapshot-release-verification-v1"
)
PROJECTS = (
    "de.wikipedia.org",
    "en.wikipedia.org",
    "fr.wikipedia.org",
)
READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_JSON_BYTES = 64 * 1024 * 1024
MAXIMUM_CORPUS_FILES = 2_000_000
MAXIMUM_PATH_BYTES = 2048
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PORTABLE_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,254})?\Z")

ASSET_NAMES: dict[str, str] = {
    "attribution": "attribution.json",
    "corpus-bytes": "corpus-bytes.zip",
    "design-publication-receipt": "design-publication-receipt.json",
    "sha256-manifest": "sha256-manifest.json",
    "snapshot-registration": "snapshot-registration.json",
}
ASSET_ROLES = tuple(ASSET_NAMES)
MANIFEST_ROLES = (
    "attribution",
    "corpus-bytes",
    "design-publication-receipt",
    "snapshot-registration",
)


class SnapshotReleaseError(RuntimeError):
    """The snapshot release package is unsafe, mutable, or inconsistent."""


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
class SnapshotReleaseVerification:
    asset_root: Path
    corpus_files: int
    corpus_bytes: int
    attribution_records: int
    corpus_manifest_sha256: str
    design_publication_receipt_sha256: str
    snapshot_registration_sha256: str
    assets: tuple[AssetRecord, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": VERIFICATION_SCHEMA,
            "suiteId": SUITE_ID,
            "status": "VERIFIED_SNAPSHOT_RELEASE_ASSETS",
            "assetRoot": str(self.asset_root),
            "corpusFiles": self.corpus_files,
            "corpusBytes": self.corpus_bytes,
            "attributionRecords": self.attribution_records,
            "corpusManifestSHA256": self.corpus_manifest_sha256,
            "designPublicationReceiptSHA256": (
                self.design_publication_receipt_sha256
            ),
            "snapshotRegistrationSHA256": self.snapshot_registration_sha256,
            "assets": [asset.as_dict() for asset in self.assets],
        }


@dataclass(frozen=True)
class _FileRecord:
    relative_path: str
    bytes: int
    sha256: str
    crc32: int
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class _CorpusSource:
    root: Path
    files: Mapping[str, _FileRecord]
    directories: frozenset[str]
    manifest: Mapping[str, Any]
    manifest_raw: bytes
    attribution: Mapping[str, Any]


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
        raise SnapshotReleaseError("value is not canonical JSON data") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_constant(value: str) -> None:
    raise SnapshotReleaseError(f"non-finite JSON number is forbidden: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise SnapshotReleaseError(f"non-finite JSON number is forbidden: {value}")
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(raw: bytes, *, label: str) -> Any:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAXIMUM_JSON_BYTES:
        raise SnapshotReleaseError(f"{label} is empty or exceeds its byte limit")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except UnicodeDecodeError as error:
        raise SnapshotReleaseError(f"{label} is not strict UTF-8") from error
    except json.JSONDecodeError as error:
        raise SnapshotReleaseError(f"{label} is not strict JSON") from error


def _load_canonical_json(
    raw: bytes,
    *,
    label: str,
    trailing_lf: bool,
) -> Mapping[str, Any]:
    payload = raw[:-1] if trailing_lf and raw.endswith(b"\n") else raw
    if trailing_lf and (not raw.endswith(b"\n") or raw.endswith(b"\n\n")):
        raise SnapshotReleaseError(f"{label} must end in exactly one LF")
    value = _load_json(payload, label=label)
    if not isinstance(value, dict):
        raise SnapshotReleaseError(f"{label} root must be an object")
    expected = canonical_json_bytes(value) + (b"\n" if trailing_lf else b"")
    if raw != expected:
        raise SnapshotReleaseError(f"{label} bytes are not canonical JSON")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise SnapshotReleaseError(f"{label} must be lowercase SHA-256")
    return value


def _safe_relative(value: Any, *, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        raise SnapshotReleaseError(f"{label} is not canonical POSIX syntax")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise SnapshotReleaseError(f"{label} is not a portable ASCII path") from error
    if len(encoded) > MAXIMUM_PATH_BYTES:
        raise SnapshotReleaseError(f"{label} is too long")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.as_posix() != value
        or any(
            component in {"", ".", ".."}
            or PORTABLE_COMPONENT.fullmatch(component) is None
            for component in relative.parts
        )
    ):
        raise SnapshotReleaseError(f"{label} escapes its root or is not portable")
    return relative


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_mode,
        metadata.st_nlink,
    )


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
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_existing_directory(path: Path, *, label: str) -> tuple[Path, int]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        raise SnapshotReleaseError(f"{label} is missing") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise SnapshotReleaseError(f"{label} itself is a symlink")
    real = Path(os.path.realpath(absolute))
    try:
        descriptor = os.open(real, _directory_flags())
    except OSError as error:
        raise SnapshotReleaseError(f"{label} is not a no-follow directory") from error
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        raise SnapshotReleaseError(f"{label} is not a directory")
    return real, descriptor


def _read_descriptor(
    descriptor: int,
    *,
    maximum_bytes: int | None = None,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise SnapshotReleaseError("opened source is not a regular file")
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        raise SnapshotReleaseError("opened source exceeds its byte limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, READ_CHUNK_BYTES)
        if not chunk:
            break
        chunks.append(chunk)
        observed += len(chunk)
        if maximum_bytes is not None and observed > maximum_bytes:
            raise SnapshotReleaseError("opened source grew past its byte limit")
    after = os.fstat(descriptor)
    if _identity(before) != _identity(after) or observed != before.st_size:
        raise SnapshotReleaseError("opened source changed while being read")
    return b"".join(chunks), after


def _read_regular_path(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = MAXIMUM_JSON_BYTES,
) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        leaf_metadata = os.lstat(absolute)
    except OSError as error:
        raise SnapshotReleaseError(f"{label} is missing") from error
    if stat.S_ISLNK(leaf_metadata.st_mode):
        raise SnapshotReleaseError(f"{label} is a symlink")
    parent = Path(os.path.realpath(absolute.parent))
    try:
        parent_descriptor = os.open(parent, _directory_flags())
    except OSError as error:
        raise SnapshotReleaseError(f"{label} parent is unsafe") from error
    try:
        try:
            descriptor = os.open(absolute.name, _file_flags(), dir_fd=parent_descriptor)
        except OSError as error:
            raise SnapshotReleaseError(f"{label} is not a no-follow file") from error
        try:
            raw, opened = _read_descriptor(
                descriptor, maximum_bytes=maximum_bytes
            )
            if not stat.S_ISREG(opened.st_mode):
                raise SnapshotReleaseError(f"{label} is not regular")
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _hash_open_file(descriptor: int) -> tuple[int, str, int, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SnapshotReleaseError("corpus file is not a unique regular file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    checksum = 0
    observed = 0
    while True:
        chunk = os.read(descriptor, READ_CHUNK_BYTES)
        if not chunk:
            break
        observed += len(chunk)
        digest.update(chunk)
        checksum = zlib.crc32(chunk, checksum)
    after = os.fstat(descriptor)
    if _identity(before) != _identity(after) or observed != before.st_size:
        raise SnapshotReleaseError("corpus file changed while being hashed")
    return observed, digest.hexdigest(), checksum & 0xFFFFFFFF, after


def _scan_directory_descriptor(
    descriptor: int,
    *,
    prefix: PurePosixPath | None = None,
    files: dict[str, _FileRecord] | None = None,
    directories: set[str] | None = None,
) -> dict[str, _FileRecord]:
    if files is None:
        files = {}
    if directories is None:
        directories = set()
    directory_before = os.fstat(descriptor)
    if not stat.S_ISDIR(directory_before.st_mode):
        raise SnapshotReleaseError("tree member is not a directory")
    try:
        names_before = sorted(os.listdir(descriptor))
    except OSError as error:
        raise SnapshotReleaseError("cannot inventory directory") from error
    for name in names_before:
        _safe_relative(name, label="directory component")
        relative = PurePosixPath(name) if prefix is None else prefix / name
        relative_text = relative.as_posix()
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise SnapshotReleaseError(
                f"tree member disappeared: {relative_text}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SnapshotReleaseError(f"tree contains a symlink: {relative_text}")
        if stat.S_ISDIR(metadata.st_mode):
            if relative_text in directories:
                raise SnapshotReleaseError(
                    f"tree directory is duplicated: {relative_text}"
                )
            directories.add(relative_text)
            try:
                child = os.open(name, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise SnapshotReleaseError(
                    f"tree directory is not no-follow: {relative_text}"
                ) from error
            try:
                if (
                    os.fstat(child).st_dev != metadata.st_dev
                    or os.fstat(child).st_ino != metadata.st_ino
                ):
                    raise SnapshotReleaseError(
                        f"tree directory changed while opening: {relative_text}"
                    )
                _scan_directory_descriptor(
                    child,
                    prefix=relative,
                    files=files,
                    directories=directories,
                )
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotReleaseError(
                f"tree contains a special file: {relative_text}"
            )
        try:
            child = os.open(name, _file_flags(), dir_fd=descriptor)
        except OSError as error:
            raise SnapshotReleaseError(
                f"tree file is not no-follow: {relative_text}"
            ) from error
        try:
            opened = os.fstat(child)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise SnapshotReleaseError(
                    f"tree file changed while opening: {relative_text}"
                )
            size, digest, checksum, after = _hash_open_file(child)
        finally:
            os.close(child)
        if relative_text in files:
            raise SnapshotReleaseError(f"tree path is duplicated: {relative_text}")
        files[relative_text] = _FileRecord(
            relative_path=relative_text,
            bytes=size,
            sha256=digest,
            crc32=checksum,
            identity=_identity(after),
        )
        if len(files) > MAXIMUM_CORPUS_FILES:
            raise SnapshotReleaseError("tree contains too many files")
    try:
        names_after = sorted(os.listdir(descriptor))
    except OSError as error:
        raise SnapshotReleaseError("cannot re-inventory directory") from error
    directory_after = os.fstat(descriptor)
    if names_after != names_before or _identity(directory_before) != _identity(
        directory_after
    ):
        raise SnapshotReleaseError("directory changed while being inventoried")
    return files


def _scan_tree(
    root: Path,
    *,
    label: str,
) -> tuple[Path, dict[str, _FileRecord], frozenset[str], int]:
    real, descriptor = _open_existing_directory(root, label=label)
    try:
        directories: set[str] = set()
        files = _scan_directory_descriptor(
            descriptor,
            directories=directories,
        )
        return real, files, frozenset(directories), os.fstat(descriptor).st_mode
    finally:
        os.close(descriptor)


def _open_relative_file(root_descriptor: int, relative: str) -> int:
    path = _safe_relative(relative, label="corpus relative path")
    current = os.dup(root_descriptor)
    try:
        for component in path.parts[:-1]:
            child = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = child
        descriptor = os.open(path.parts[-1], _file_flags(), dir_fd=current)
        return descriptor
    except OSError as error:
        raise SnapshotReleaseError(
            f"cannot open no-follow corpus file: {relative}"
        ) from error
    finally:
        os.close(current)


def _read_tree_file(
    root_descriptor: int,
    record: _FileRecord,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    descriptor = _open_relative_file(root_descriptor, record.relative_path)
    try:
        raw, metadata = _read_descriptor(
            descriptor,
            maximum_bytes=maximum_bytes,
        )
        if _identity(metadata) != record.identity:
            raise SnapshotReleaseError(
                f"corpus file identity changed: {record.relative_path}"
            )
        if sha256_bytes(raw) != record.sha256:
            raise SnapshotReleaseError(
                f"corpus file digest changed: {record.relative_path}"
            )
        return raw
    finally:
        os.close(descriptor)


def _collect_commitments(value: Any) -> dict[str, tuple[int, str]]:
    commitments: dict[str, tuple[int, str]] = {}

    def walk(node: Any, label: str) -> None:
        if isinstance(node, dict):
            commitment_fields = {"relativePath", "bytes", "sha256"}
            if commitment_fields.intersection(node):
                if set(node) != commitment_fields:
                    raise SnapshotReleaseError(
                        f"partial corpus byte commitment at {label}"
                    )
                relative = _safe_relative(
                    node["relativePath"], label=f"{label} relativePath"
                ).as_posix()
                size = node["bytes"]
                digest = _digest(node["sha256"], label=f"{label} SHA-256")
                if type(size) is not int or size < 0:
                    raise SnapshotReleaseError(
                        f"{label} byte commitment has an invalid size"
                    )
                if relative in commitments:
                    raise SnapshotReleaseError(
                        f"duplicate corpus commitment path: {relative}"
                    )
                commitments[relative] = (size, digest)
                return
            for key, child in node.items():
                walk(child, f"{label}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{label}[{index}]")

    walk(value, "corpus manifest")
    return commitments


def _derive_attribution(
    manifest: Mapping[str, Any],
    *,
    manifest_raw: bytes,
) -> Mapping[str, Any]:
    records: list[dict[str, Any]] = []
    projects = manifest["projects"]
    for project in PROJECTS:
        entry = projects[project]
        if not isinstance(entry, dict) or set(entry) != {
            "crawls",
            "unionRevisionCount",
            "inventory",
            "eligibleRevisionCount",
            "ledger",
        }:
            raise SnapshotReleaseError(f"corpus project fields differ: {project}")
        if not isinstance(entry["crawls"], list) or len(entry["crawls"]) != 2:
            raise SnapshotReleaseError(f"corpus crawl count differs: {project}")
        inventory = entry["inventory"]
        if not isinstance(inventory, list):
            raise SnapshotReleaseError(f"corpus inventory is invalid: {project}")
        if (
            type(entry["unionRevisionCount"]) is not int
            or entry["unionRevisionCount"] != len(inventory)
        ):
            raise SnapshotReleaseError(f"corpus union count differs: {project}")
        eligible = [
            item
            for item in inventory
            if isinstance(item, dict) and item.get("eligible") is True
        ]
        if (
            type(entry["eligibleRevisionCount"]) is not int
            or entry["eligibleRevisionCount"] != len(eligible)
        ):
            raise SnapshotReleaseError(f"corpus eligible count differs: {project}")
        for item in eligible:
            fields = (
                "project",
                "pageid",
                "revid",
                "timestamp",
                "title",
                "mediaWikiSHA1",
                "titleSHA256",
                "contentSHA256",
                "inputSHA256",
                "revisionURL",
                "historyURL",
                "attribution",
                "record",
            )
            if any(field not in item for field in fields):
                raise SnapshotReleaseError(
                    f"eligible corpus attribution is incomplete: {project}"
                )
            if item["project"] != project:
                raise SnapshotReleaseError("corpus attribution project differs")
            for numeric in ("pageid", "revid"):
                if type(item[numeric]) is not int or item[numeric] < 1:
                    raise SnapshotReleaseError(
                        f"corpus attribution {numeric} is invalid"
                    )
            for digest_field in (
                "titleSHA256",
                "contentSHA256",
                "inputSHA256",
            ):
                _digest(item[digest_field], label=f"attribution {digest_field}")
            if not isinstance(item["attribution"], dict) or not item["attribution"]:
                raise SnapshotReleaseError("eligible corpus attribution is absent")
            # Copy only facts already present in the verified corpus manifest.
            # In particular, no license identifier or URL is supplied here.
            records.append(
                {
                    field: copy.deepcopy(item[field])
                    for field in fields
                }
            )
    records.sort(
        key=lambda item: (
            item["project"],
            item["timestamp"],
            item["revid"],
            item["pageid"],
        )
    )
    identities = [(item["project"], item["revid"]) for item in records]
    if len(identities) != len(set(identities)):
        raise SnapshotReleaseError("attribution contains duplicate revisions")
    return {
        "schemaVersion": ATTRIBUTION_SCHEMA,
        "suiteId": SUITE_ID,
        "source": {
            "corpusManifestPath": "corpus-manifest.json",
            "corpusManifestBytes": len(manifest_raw),
            "corpusManifestSHA256": sha256_bytes(manifest_raw),
        },
        "records": records,
    }


def _load_corpus_source(corpus_root: Path) -> _CorpusSource:
    real, files, directories, _mode = _scan_tree(
        corpus_root, label="corpus root"
    )
    fixed = {
        "corpus-manifest.json",
        "crawl-1-manifest.json",
        "crawl-2-manifest.json",
    }
    if not fixed.issubset(files):
        raise SnapshotReleaseError("corpus root is missing a canonical manifest")
    root_path, root_descriptor = _open_existing_directory(real, label="corpus root")
    try:
        manifest_raw = _read_tree_file(
            root_descriptor,
            files["corpus-manifest.json"],
            maximum_bytes=MAXIMUM_JSON_BYTES,
        )
        manifest = _load_canonical_json(
            manifest_raw,
            label="corpus manifest",
            trailing_lf=False,
        )
        for crawl_manifest in ("crawl-1-manifest.json", "crawl-2-manifest.json"):
            raw = _read_tree_file(
                root_descriptor,
                files[crawl_manifest],
                maximum_bytes=MAXIMUM_JSON_BYTES,
            )
            _load_canonical_json(
                raw,
                label=crawl_manifest,
                trailing_lf=False,
            )
    finally:
        os.close(root_descriptor)
    if set(manifest) != {
        "schemaVersion",
        "suiteId",
        "status",
        "countsTowardScientificVerdict",
        "projects",
    }:
        raise SnapshotReleaseError("corpus manifest fields differ")
    if (
        manifest["schemaVersion"] != CORPUS_SCHEMA
        or manifest["suiteId"] != SUITE_ID
        or manifest["status"] != "SNAPSHOT_READY_FOR_FREEZE"
        or manifest["countsTowardScientificVerdict"] is not False
        or not isinstance(manifest["projects"], dict)
        or tuple(manifest["projects"]) != PROJECTS
    ):
        raise SnapshotReleaseError("corpus manifest is not freeze-ready")
    commitments = _collect_commitments(manifest)
    expected_files = fixed | set(commitments)
    if set(files) != expected_files:
        missing = sorted(expected_files - set(files))
        extra = sorted(set(files) - expected_files)
        raise SnapshotReleaseError(
            f"corpus root inventory differs; missing={missing!r}; extra={extra!r}"
        )
    expected_directories: set[str] = set()
    for relative in expected_files:
        for parent in PurePosixPath(relative).parents:
            if parent != PurePosixPath("."):
                expected_directories.add(parent.as_posix())
    if directories != expected_directories:
        missing = sorted(expected_directories - set(directories))
        extra = sorted(set(directories) - expected_directories)
        raise SnapshotReleaseError(
            f"corpus directory inventory differs; missing={missing!r}; extra={extra!r}"
        )
    for relative, (size, digest) in commitments.items():
        record = files[relative]
        if record.bytes != size or record.sha256 != digest:
            raise SnapshotReleaseError(
                f"corpus byte commitment differs: {relative}"
            )
    attribution = _derive_attribution(manifest, manifest_raw=manifest_raw)
    return _CorpusSource(
        root=root_path,
        files=files,
        directories=directories,
        manifest=manifest,
        manifest_raw=manifest_raw,
        attribution=attribution,
    )


def _load_snapshot_registration(raw: bytes) -> Mapping[str, Any]:
    snapshot = _load_canonical_json(
        raw,
        label="snapshot registration",
        trailing_lf=True,
    )
    if snapshot.get("schemaVersion") != SNAPSHOT_SCHEMA:
        raise SnapshotReleaseError("snapshot registration schema differs")
    try:
        validate_snapshot_registration(snapshot, allow_fixture=False)
    except ValueError as error:
        raise SnapshotReleaseError("snapshot registration is invalid") from error
    return snapshot


def _load_design_receipt(raw: bytes) -> Mapping[str, Any]:
    receipt = _load_canonical_json(
        raw,
        label="design publication receipt",
        trailing_lf=True,
    )
    if (
        receipt.get("schemaVersion") != DESIGN_RECEIPT_SCHEMA
        or receipt.get("suiteId") != SUITE_ID
        or receipt.get("kind") != "design"
    ):
        raise SnapshotReleaseError("design publication receipt identity differs")
    digest = _digest(
        receipt.get("contentSHA256"),
        label="design publication receipt contentSHA256",
    )
    unsigned = dict(receipt)
    del unsigned["contentSHA256"]
    if sha256_bytes(canonical_json_bytes(unsigned)) != digest:
        raise SnapshotReleaseError(
            "design publication receipt contentSHA256 differs"
        )
    return receipt


def _same_file_records(
    left: Mapping[str, _FileRecord],
    right: Mapping[str, _FileRecord],
) -> bool:
    return dict(left) == dict(right)


def _stream_corpus_file(
    root_descriptor: int,
    record: _FileRecord,
    target: BinaryIO,
) -> None:
    descriptor = _open_relative_file(root_descriptor, record.relative_path)
    try:
        before = os.fstat(descriptor)
        if _identity(before) != record.identity:
            raise SnapshotReleaseError(
                f"corpus file identity changed: {record.relative_path}"
            )
        digest = hashlib.sha256()
        checksum = 0
        observed = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            target.write(chunk)
            digest.update(chunk)
            checksum = zlib.crc32(chunk, checksum)
            observed += len(chunk)
        after = os.fstat(descriptor)
        if (
            _identity(after) != record.identity
            or observed != record.bytes
            or digest.hexdigest() != record.sha256
            or checksum & 0xFFFFFFFF != record.crc32
        ):
            raise SnapshotReleaseError(
                f"corpus file changed during archive: {record.relative_path}"
            )
    finally:
        os.close(descriptor)


def _write_corpus_archive(target: BinaryIO, corpus: _CorpusSource) -> None:
    real, current_files, current_directories, _mode = _scan_tree(
        corpus.root, label="corpus root"
    )
    if (
        real != corpus.root
        or not _same_file_records(current_files, corpus.files)
        or current_directories != corpus.directories
    ):
        raise SnapshotReleaseError("corpus root changed before archive creation")
    _, root_descriptor = _open_existing_directory(corpus.root, label="corpus root")
    try:
        with zipfile.ZipFile(
            target,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=True,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for relative in sorted(corpus.files):
                record = corpus.files[relative]
                information = zipfile.ZipInfo(relative, date_time=ZIP_TIMESTAMP)
                information.compress_type = zipfile.ZIP_STORED
                information.create_system = 3
                information.external_attr = (stat.S_IFREG | 0o444) << 16
                information.extra = b""
                information.comment = b""
                information.file_size = record.bytes
                with archive.open(
                    information,
                    mode="w",
                    force_zip64=True,
                ) as destination:
                    _stream_corpus_file(root_descriptor, record, destination)
    finally:
        os.close(root_descriptor)
    _real, after_files, after_directories, _mode = _scan_tree(
        corpus.root, label="corpus root"
    )
    if (
        not _same_file_records(after_files, corpus.files)
        or after_directories != corpus.directories
    ):
        raise SnapshotReleaseError("corpus root changed during archive creation")


class _OutputBuilder:
    def __init__(self, output_root: Path) -> None:
        absolute = Path(os.path.abspath(os.fspath(output_root)))
        if not absolute.name or PORTABLE_COMPONENT.fullmatch(absolute.name) is None:
            raise SnapshotReleaseError("output directory name is not portable")
        parent = Path(os.path.realpath(absolute.parent))
        try:
            self.parent_descriptor = os.open(parent, _directory_flags())
        except OSError as error:
            raise SnapshotReleaseError("output parent is not a safe directory") from error
        self.output_name = absolute.name
        self.root = parent / self.output_name
        try:
            os.mkdir(self.output_name, 0o700, dir_fd=self.parent_descriptor)
            os.fsync(self.parent_descriptor)
            self.root_descriptor = os.open(
                self.output_name,
                _directory_flags(),
                dir_fd=self.parent_descriptor,
            )
        except OSError as error:
            os.close(self.parent_descriptor)
            raise SnapshotReleaseError(
                "output root already exists or cannot be created"
            ) from error
        self.closed = False

    def publish(
        self,
        name: str,
        writer: Callable[[BinaryIO], None],
    ) -> tuple[int, str]:
        if name not in ASSET_NAMES.values():
            raise SnapshotReleaseError("release asset name is not canonical")
        temporary = f"tmp-{secrets.token_hex(16)}"
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(
                temporary,
                flags,
                0o600,
                dir_fd=self.root_descriptor,
            )
        except OSError as error:
            raise SnapshotReleaseError("cannot create private atomic asset") from error
        published = False
        try:
            with os.fdopen(os.dup(descriptor), "w+b") as stream:
                writer(stream)
                stream.flush()
                os.fsync(stream.fileno())
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise SnapshotReleaseError("generated asset is not a private regular file")
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
            if observed != metadata.st_size:
                raise SnapshotReleaseError("generated asset changed while hashing")
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=self.root_descriptor,
                    dst_dir_fd=self.root_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise SnapshotReleaseError(
                    f"release asset already exists or cannot publish: {name}"
                ) from error
            published = True
            os.unlink(temporary, dir_fd=self.root_descriptor)
            os.fsync(self.root_descriptor)
            return observed, digest.hexdigest()
        finally:
            os.close(descriptor)
            if not published:
                try:
                    os.unlink(temporary, dir_fd=self.root_descriptor)
                except OSError:
                    pass

    def publish_bytes(self, name: str, raw: bytes) -> tuple[int, str]:
        return self.publish(name, lambda stream: stream.write(raw))

    def finalize(self) -> None:
        if self.closed:
            return
        os.fchmod(self.root_descriptor, 0o555)
        os.fsync(self.root_descriptor)
        os.fsync(self.parent_descriptor)
        os.close(self.root_descriptor)
        os.close(self.parent_descriptor)
        self.closed = True

    def close(self) -> None:
        if self.closed:
            return
        os.close(self.root_descriptor)
        os.close(self.parent_descriptor)
        self.closed = True


def _asset_record(role: str, size: int, digest: str) -> AssetRecord:
    return AssetRecord(
        role=role,
        name=ASSET_NAMES[role],
        bytes=size,
        sha256=digest,
    )


def _sha256_manifest(records: Mapping[str, AssetRecord]) -> Mapping[str, Any]:
    if set(records) != set(MANIFEST_ROLES):
        raise SnapshotReleaseError("SHA-256 manifest input role set differs")
    return {
        "schemaVersion": SHA256_MANIFEST_SCHEMA,
        "suiteId": SUITE_ID,
        "algorithm": "SHA-256",
        "scope": "all snapshot release assets except this manifest",
        "selfDigestExcluded": True,
        "assets": [records[role].as_dict() for role in MANIFEST_ROLES],
    }


def package_snapshot_release(
    *,
    corpus_root: Path,
    snapshot_registration_path: Path,
    design_publication_receipt_path: Path,
    output_root: Path,
) -> SnapshotReleaseVerification:
    """Create five immutable assets in a new output directory and verify them."""

    require_scientific_schedule_open(operation="package Blind V1 snapshot release")
    return _historical_package_snapshot_release(
        corpus_root=corpus_root,
        snapshot_registration_path=snapshot_registration_path,
        design_publication_receipt_path=design_publication_receipt_path,
        output_root=output_root,
    )


def _historical_package_snapshot_release(
    *,
    corpus_root: Path,
    snapshot_registration_path: Path,
    design_publication_receipt_path: Path,
    output_root: Path,
) -> SnapshotReleaseVerification:
    """Retain the former snapshot package shape for offline fixtures."""

    snapshot_raw = _read_regular_path(
        snapshot_registration_path,
        label="snapshot registration",
    )
    snapshot = _load_snapshot_registration(snapshot_raw)
    design_receipt_raw = _read_regular_path(
        design_publication_receipt_path,
        label="design publication receipt",
    )
    _load_design_receipt(design_receipt_raw)
    corpus = _load_corpus_source(corpus_root)
    corpus_manifest_sha256 = sha256_bytes(corpus.manifest_raw)
    design_receipt_sha256 = sha256_bytes(design_receipt_raw)
    if snapshot["corpusManifestSHA256"] != corpus_manifest_sha256:
        raise SnapshotReleaseError(
            "snapshot registration binds a different corpus manifest"
        )
    if snapshot["designPublicationReceiptSHA256"] != design_receipt_sha256:
        raise SnapshotReleaseError(
            "snapshot registration binds a different design publication receipt"
        )

    attribution_raw = canonical_json_bytes(corpus.attribution) + b"\n"
    builder = _OutputBuilder(output_root)
    try:
        records: dict[str, AssetRecord] = {}
        size, digest = builder.publish_bytes(
            ASSET_NAMES["attribution"], attribution_raw
        )
        records["attribution"] = _asset_record("attribution", size, digest)
        size, digest = builder.publish(
            ASSET_NAMES["corpus-bytes"],
            lambda stream: _write_corpus_archive(stream, corpus),
        )
        records["corpus-bytes"] = _asset_record("corpus-bytes", size, digest)
        size, digest = builder.publish_bytes(
            ASSET_NAMES["design-publication-receipt"], design_receipt_raw
        )
        records["design-publication-receipt"] = _asset_record(
            "design-publication-receipt", size, digest
        )
        size, digest = builder.publish_bytes(
            ASSET_NAMES["snapshot-registration"], snapshot_raw
        )
        records["snapshot-registration"] = _asset_record(
            "snapshot-registration", size, digest
        )
        manifest_raw = canonical_json_bytes(_sha256_manifest(records)) + b"\n"
        size, digest = builder.publish_bytes(
            ASSET_NAMES["sha256-manifest"], manifest_raw
        )
        records["sha256-manifest"] = _asset_record(
            "sha256-manifest", size, digest
        )
        builder.finalize()
    finally:
        builder.close()

    return verify_snapshot_release(
        corpus_root=corpus_root,
        snapshot_registration_path=snapshot_registration_path,
        design_publication_receipt_path=design_publication_receipt_path,
        asset_root=output_root,
    )


def _verify_zip_metadata(information: zipfile.ZipInfo) -> None:
    mode = information.external_attr >> 16
    if (
        information.date_time != ZIP_TIMESTAMP
        or information.compress_type != zipfile.ZIP_STORED
        or information.create_system != 3
        or information.extra != b""
        or information.comment != b""
        or information.flag_bits & 0x1
        or not stat.S_ISREG(mode)
        or stat.S_IMODE(mode) != 0o444
        or information.compress_size != information.file_size
    ):
        raise SnapshotReleaseError(
            f"corpus ZIP metadata differs: {information.filename}"
        )


def _verify_corpus_archive(
    archive_descriptor: int,
    corpus: _CorpusSource,
) -> None:
    _, source_descriptor = _open_existing_directory(
        corpus.root, label="corpus root"
    )
    try:
        with os.fdopen(os.dup(archive_descriptor), "rb") as archive_stream:
            with zipfile.ZipFile(archive_stream, mode="r") as archive:
                if archive.comment != b"":
                    raise SnapshotReleaseError("corpus ZIP comment is not empty")
                information = archive.infolist()
                names = [item.filename for item in information]
                expected_names = sorted(corpus.files)
                if names != expected_names or len(names) != len(set(names)):
                    raise SnapshotReleaseError("corpus ZIP inventory differs")
                for item in information:
                    _safe_relative(item.filename, label="corpus ZIP path")
                    _verify_zip_metadata(item)
                    record = corpus.files[item.filename]
                    if item.file_size != record.bytes or item.CRC != record.crc32:
                        raise SnapshotReleaseError(
                            f"corpus ZIP size/CRC differs: {item.filename}"
                        )
                    source_file = _open_relative_file(
                        source_descriptor, item.filename
                    )
                    try:
                        if _identity(os.fstat(source_file)) != record.identity:
                            raise SnapshotReleaseError(
                                f"corpus source identity differs: {item.filename}"
                            )
                        digest = hashlib.sha256()
                        archived_digest = hashlib.sha256()
                        observed = 0
                        with archive.open(item, mode="r") as archived_file:
                            while True:
                                source_chunk = os.read(
                                    source_file, READ_CHUNK_BYTES
                                )
                                archive_parts: list[bytes] = []
                                archive_observed = 0
                                while archive_observed < len(source_chunk):
                                    part = archived_file.read(
                                        len(source_chunk) - archive_observed
                                    )
                                    if not part:
                                        break
                                    archive_parts.append(part)
                                    archive_observed += len(part)
                                archive_chunk = b"".join(archive_parts)
                                if source_chunk != archive_chunk:
                                    raise SnapshotReleaseError(
                                        f"corpus ZIP bytes differ: {item.filename}"
                                    )
                                if not source_chunk:
                                    break
                                observed += len(source_chunk)
                                digest.update(source_chunk)
                                archived_digest.update(archive_chunk)
                            if archived_file.read(1) != b"":
                                raise SnapshotReleaseError(
                                    f"corpus ZIP entry has trailing bytes: {item.filename}"
                                )
                        if (
                            observed != record.bytes
                            or digest.hexdigest() != record.sha256
                            or archived_digest.hexdigest() != record.sha256
                            or _identity(os.fstat(source_file)) != record.identity
                        ):
                            raise SnapshotReleaseError(
                                f"corpus source changed: {item.filename}"
                            )
                    finally:
                        os.close(source_file)
    except SnapshotReleaseError:
        raise
    except (
        zipfile.BadZipFile,
        RuntimeError,
        zlib.error,
        EOFError,
        OSError,
        ValueError,
    ) as error:
        raise SnapshotReleaseError("corpus ZIP is malformed") from error
    finally:
        os.close(source_descriptor)
    _real, after_files, after_directories, _mode = _scan_tree(
        corpus.root, label="corpus root"
    )
    if (
        not _same_file_records(after_files, corpus.files)
        or after_directories != corpus.directories
    ):
        raise SnapshotReleaseError("corpus root changed during ZIP verification")


def verify_snapshot_release(
    *,
    corpus_root: Path,
    snapshot_registration_path: Path,
    design_publication_receipt_path: Path,
    asset_root: Path,
) -> SnapshotReleaseVerification:
    """Verify the exact five assets against all original source bytes."""

    snapshot_raw = _read_regular_path(
        snapshot_registration_path,
        label="snapshot registration",
    )
    snapshot = _load_snapshot_registration(snapshot_raw)
    design_receipt_raw = _read_regular_path(
        design_publication_receipt_path,
        label="design publication receipt",
    )
    _load_design_receipt(design_receipt_raw)
    corpus = _load_corpus_source(corpus_root)
    corpus_manifest_sha256 = sha256_bytes(corpus.manifest_raw)
    design_receipt_sha256 = sha256_bytes(design_receipt_raw)
    if snapshot["corpusManifestSHA256"] != corpus_manifest_sha256:
        raise SnapshotReleaseError(
            "snapshot registration corpus manifest binding differs"
        )
    if snapshot["designPublicationReceiptSHA256"] != design_receipt_sha256:
        raise SnapshotReleaseError(
            "snapshot registration design receipt binding differs"
        )

    real_asset_root, files, directories, root_mode = _scan_tree(
        asset_root, label="snapshot release asset root"
    )
    if (
        set(files) != set(ASSET_NAMES.values())
        or len(files) != 5
        or directories
    ):
        raise SnapshotReleaseError("snapshot release must contain exactly five assets")
    if root_mode & 0o222:
        raise SnapshotReleaseError("snapshot release asset root is writable")
    for name, record in files.items():
        if record.identity[4] & 0o222:
            raise SnapshotReleaseError(f"snapshot release asset is writable: {name}")

    _, asset_descriptor = _open_existing_directory(
        real_asset_root, label="snapshot release asset root"
    )
    try:
        raw_assets = {
            name: _read_tree_file(
                asset_descriptor,
                record,
                maximum_bytes=(
                    MAXIMUM_JSON_BYTES if name.endswith(".json") else None
                ),
            )
            for name, record in files.items()
            if name != ASSET_NAMES["corpus-bytes"]
        }
        if raw_assets[ASSET_NAMES["snapshot-registration"]] != snapshot_raw:
            raise SnapshotReleaseError("snapshot registration asset bytes differ")
        if (
            raw_assets[ASSET_NAMES["design-publication-receipt"]]
            != design_receipt_raw
        ):
            raise SnapshotReleaseError("design publication receipt asset bytes differ")
        expected_attribution_raw = canonical_json_bytes(corpus.attribution) + b"\n"
        attribution_raw = raw_assets[ASSET_NAMES["attribution"]]
        _load_canonical_json(
            attribution_raw,
            label="snapshot attribution asset",
            trailing_lf=True,
        )
        if attribution_raw != expected_attribution_raw:
            raise SnapshotReleaseError("snapshot attribution asset differs")

        observed_records: dict[str, AssetRecord] = {}
        for role in MANIFEST_ROLES:
            name = ASSET_NAMES[role]
            record = files[name]
            observed_records[role] = _asset_record(
                role, record.bytes, record.sha256
            )
        expected_manifest_raw = (
            canonical_json_bytes(_sha256_manifest(observed_records)) + b"\n"
        )
        manifest_raw = raw_assets[ASSET_NAMES["sha256-manifest"]]
        _load_canonical_json(
            manifest_raw,
            label="snapshot release SHA-256 manifest",
            trailing_lf=True,
        )
        if manifest_raw != expected_manifest_raw:
            raise SnapshotReleaseError("snapshot release SHA-256 manifest differs")

        archive_descriptor = _open_relative_file(
            asset_descriptor, ASSET_NAMES["corpus-bytes"]
        )
        try:
            _verify_corpus_archive(archive_descriptor, corpus)
        finally:
            os.close(archive_descriptor)
    finally:
        os.close(asset_descriptor)

    assets = tuple(
        _asset_record(
            role,
            files[ASSET_NAMES[role]].bytes,
            files[ASSET_NAMES[role]].sha256,
        )
        for role in ASSET_ROLES
    )
    return SnapshotReleaseVerification(
        asset_root=real_asset_root,
        corpus_files=len(corpus.files),
        corpus_bytes=sum(record.bytes for record in corpus.files.values()),
        attribution_records=len(corpus.attribution["records"]),
        corpus_manifest_sha256=corpus_manifest_sha256,
        design_publication_receipt_sha256=design_receipt_sha256,
        snapshot_registration_sha256=sha256_bytes(snapshot_raw),
        assets=assets,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Package or verify the five blind-v1 snapshot release assets"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("package", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--corpus-root", required=True, type=Path)
        child.add_argument("--snapshot-registration", required=True, type=Path)
        child.add_argument(
            "--design-publication-receipt", required=True, type=Path
        )
        asset_argument = "--output-root" if command == "package" else "--asset-root"
        child.add_argument(asset_argument, required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "package":
            require_scientific_schedule_open(
                operation="package Blind V1 snapshot release from CLI"
            )
            result = package_snapshot_release(
                corpus_root=arguments.corpus_root,
                snapshot_registration_path=arguments.snapshot_registration,
                design_publication_receipt_path=(
                    arguments.design_publication_receipt
                ),
                output_root=arguments.output_root,
            )
        else:
            result = verify_snapshot_release(
                corpus_root=arguments.corpus_root,
                snapshot_registration_path=arguments.snapshot_registration,
                design_publication_receipt_path=(
                    arguments.design_publication_receipt
                ),
                asset_root=arguments.asset_root,
            )
    except (SnapshotReleaseError, ValueError) as error:
        print(f"snapshot release error: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result.as_dict()) + b"\n")
    return 0


__all__ = [
    "ASSET_NAMES",
    "ASSET_ROLES",
    "AssetRecord",
    "SnapshotReleaseError",
    "SnapshotReleaseVerification",
    "canonical_json_bytes",
    "main",
    "package_snapshot_release",
    "sha256_bytes",
    "verify_snapshot_release",
]


if __name__ == "__main__":
    raise SystemExit(main())
