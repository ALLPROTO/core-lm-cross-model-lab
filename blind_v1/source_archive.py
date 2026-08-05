#!/usr/bin/env python3
"""Create and independently verify deterministic Git-source archives.

The archive is an uncompressed POSIX ustar stream.  It contains exactly one
canonical ``source-manifest.json`` member followed by the complete tracked
source under ``source/`` in the manifest's byte order.  All members are regular
files with uid/gid/mtime zero and empty owner/group names.  There are no
directory, link, device, FIFO, sparse, PAX, or GNU-extension members.

Creation reads source only through :mod:`blind_v1.git_source`'s exact Git-object
sealer.  Verification is Gitless: it performs bounded member reads, writes only
the manifest-declared regular files into an isolated temporary directory, and
uses ``verify_copied_source`` to re-hash every blob and reconstruct the complete
Git tree and commit binding.  It then regenerates the canonical ustar stream
and compares every archive byte, rejecting alternate headers or trailers.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import stat
import sys
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Sequence


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.git_source import (  # noqa: E402
    DEFAULT_MAXIMUM_FILE_BYTES,
    DEFAULT_MAXIMUM_FILE_COUNT,
    DEFAULT_MAXIMUM_TOTAL_BYTES,
    GitSourceError,
    GitSourceFile,
    build_source_manifest,
    canonical_json_bytes,
    load_source_manifest_bytes,
    seal_git_source,
    source_manifest_bytes,
    verify_copied_source,
)


ARCHIVE_FORMAT = "posix-ustar-uncompressed-v1"
REPORT_SCHEMA_VERSION = "corelm-git-source-archive-report-v1"
MANIFEST_MEMBER = "source-manifest.json"
SOURCE_PREFIX = "source/"
READ_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAXIMUM_MANIFEST_BYTES = 256 * 1024 * 1024
DEFAULT_MAXIMUM_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024


class SourceArchiveError(GitSourceError):
    """The source archive is unsafe, non-canonical, or hash-inexact."""


@dataclass(frozen=True)
class SourceArchiveReport:
    """Path-independent creation/verification result for one archive."""

    commit: str
    tree: str
    file_count: int
    source_bytes: int
    manifest_bytes: int
    manifest_sha256: str
    archive_bytes: int
    archive_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "status": "SOURCE_ARCHIVE_VERIFIED",
            "archiveFormat": ARCHIVE_FORMAT,
            "commit": self.commit,
            "tree": self.tree,
            "fileCount": self.file_count,
            "sourceBytes": self.source_bytes,
            "manifestBytes": self.manifest_bytes,
            "manifestSHA256": self.manifest_sha256,
            "archiveBytes": self.archive_bytes,
            "archiveSHA256": self.archive_sha256,
        }


def _positive_bound(value: int, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise SourceArchiveError(f"{label} must be a positive integer")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_archive_name(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise SourceArchiveError("archive member must have a non-empty relative path")
    if "\\" in value or value.endswith("/"):
        raise SourceArchiveError("archive member path is not canonical POSIX text")
    parts = tuple(value.split("/"))
    for component in parts:
        if not component or component in {".", ".."}:
            raise SourceArchiveError("archive member has an unsafe path component")
        try:
            encoded = component.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise SourceArchiveError("archive member path is not strict UTF-8") from error
        if encoded.decode("utf-8", "strict") != component:
            raise SourceArchiveError("archive member path is not canonical UTF-8")
        if unicodedata.normalize("NFC", component) != component:
            raise SourceArchiveError("archive member path is not NFC-normalized")
        if component.casefold() == ".git":
            raise SourceArchiveError("Git metadata archive path is forbidden")
        if any(ord(character) < 32 or ord(character) == 127 for character in component):
            raise SourceArchiveError("archive member path contains a control character")
    return parts


def _tar_info(name: str, size: int, mode: int) -> tarfile.TarInfo:
    _safe_archive_name(name)
    if type(size) is not int or size < 0:
        raise SourceArchiveError("canonical archive member size is invalid")
    info = tarfile.TarInfo(name=name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.size = size
    info.mtime = 0
    info.type = tarfile.REGTYPE
    info.linkname = ""
    info.uname = ""
    info.gname = ""
    info.devmajor = 0
    info.devminor = 0
    info.pax_headers = {}
    try:
        header = info.tobuf(
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        raise SourceArchiveError(
            f"source path is not representable in canonical ustar: {name}"
        ) from error
    if len(header) != tarfile.BLOCKSIZE:
        raise SourceArchiveError("canonical ustar header has an invalid size")
    return info


def _write_canonical_archive(
    output: BinaryIO,
    manifest_raw: bytes,
    files: Sequence[GitSourceFile],
) -> None:
    if not isinstance(manifest_raw, bytes):
        raise SourceArchiveError("canonical source manifest bytes are required")
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
        encoding="utf-8",
        errors="strict",
    ) as archive:
        manifest_info = _tar_info(MANIFEST_MEMBER, len(manifest_raw), 0o644)
        archive.addfile(manifest_info, _BytesReader(manifest_raw))
        for entry in files:
            mode = 0o755 if entry.mode == "100755" else 0o644
            info = _tar_info(SOURCE_PREFIX + entry.path, len(entry.data), mode)
            archive.addfile(info, _BytesReader(entry.data))


class _BytesReader:
    """Minimal bounded reader used by ``TarFile.addfile``."""

    def __init__(self, value: bytes) -> None:
        self._value = value
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._value) - self._position
        end = min(len(self._value), self._position + size)
        result = self._value[self._position : end]
        self._position = end
        return result


def _canonical_archive_size(manifest_bytes: int, files: Sequence[GitSourceFile]) -> int:
    sizes = [manifest_bytes, *(len(entry.data) for entry in files)]
    blocks = sum(1 + (size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE for size in sizes)
    blocks += 2
    record_blocks = tarfile.RECORDSIZE // tarfile.BLOCKSIZE
    blocks = ((blocks + record_blocks - 1) // record_blocks) * record_blocks
    return blocks * tarfile.BLOCKSIZE


def _validate_member_metadata(member: tarfile.TarInfo, *, mode: int) -> None:
    _safe_archive_name(member.name)
    if member.type != tarfile.REGTYPE or not member.isreg():
        raise SourceArchiveError(f"archive member is not a regular file: {member.name}")
    if member.linkname:
        raise SourceArchiveError(f"archive member has a forbidden link target: {member.name}")
    if member.pax_headers:
        raise SourceArchiveError(f"archive member has forbidden PAX metadata: {member.name}")
    if (
        member.mode != mode
        or member.uid != 0
        or member.gid != 0
        or member.mtime != 0
        or member.uname != ""
        or member.gname != ""
        or member.devmajor != 0
        or member.devminor != 0
    ):
        raise SourceArchiveError(f"archive member metadata is not canonical: {member.name}")


def _read_member_bytes(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    maximum_bytes: int,
) -> bytes:
    if member.size < 0 or member.size > maximum_bytes:
        raise SourceArchiveError(f"archive member exceeds the fixed byte bound: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise SourceArchiveError(f"archive member cannot be read: {member.name}")
    remaining = member.size
    chunks: list[bytes] = []
    while remaining:
        chunk = stream.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise SourceArchiveError(f"archive member is truncated: {member.name}")
        chunks.append(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise SourceArchiveError(f"archive member exceeds its declared size: {member.name}")
    return b"".join(chunks)


def _copy_member_to_file(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    *,
    expected_bytes: int,
    mode: int,
) -> None:
    if member.size != expected_bytes:
        raise SourceArchiveError(f"archive source byte count differs: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise SourceArchiveError(f"archive source cannot be read: {member.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, mode)
    try:
        remaining = expected_bytes
        while remaining:
            chunk = stream.read(min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise SourceArchiveError(f"archive source is truncated: {member.name}")
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SourceArchiveError(f"short write for archive source: {member.name}")
                view = view[written:]
            remaining -= len(chunk)
        if stream.read(1):
            raise SourceArchiveError(f"archive source exceeds its declared size: {member.name}")
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _file_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SourceArchiveError("source archive must be a regular file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SourceArchiveError("external path component is not a directory")
    return metadata.st_dev, metadata.st_ino


def _canonical_absolute_path(path: Path) -> Path:
    """Normalize only Darwin's fixed root aliases; preserve all other symlinks."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if sys.platform == "darwin" and len(absolute.parts) > 1:
        alias = absolute.parts[1]
        if alias in {"var", "tmp", "etc"}:
            candidate = Path("/private") / alias
            try:
                alias_status = os.lstat(Path("/") / alias)
                target_status = os.stat(candidate)
            except OSError:
                pass
            else:
                if (
                    stat.S_ISLNK(alias_status.st_mode)
                    and stat.S_ISDIR(target_status.st_mode)
                    and os.path.realpath(Path("/") / alias) == os.fspath(candidate)
                ):
                    absolute = candidate.joinpath(*absolute.parts[2:])
    return absolute


def _open_directory_no_symlinks(path: Path) -> int:
    """Open an absolute directory by descriptor-walking every component."""

    absolute = _canonical_absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        _directory_identity(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent_no_symlinks(path: Path) -> tuple[int, str]:
    absolute = _canonical_absolute_path(path)
    if not absolute.name:
        raise SourceArchiveError("external path has no final file name")
    return _open_directory_no_symlinks(absolute.parent), absolute.name


def _compare_canonical_archive(
    observed: BinaryIO,
    canonical: BinaryIO,
    *,
    maximum_archive_bytes: int,
) -> tuple[int, str]:
    observed.seek(0)
    canonical.seek(0)
    digest = hashlib.sha256()
    total = 0
    while True:
        left = observed.read(READ_CHUNK_BYTES)
        right = canonical.read(READ_CHUNK_BYTES)
        if left != right:
            raise SourceArchiveError("source archive bytes are not canonical ustar")
        if not left:
            return total, digest.hexdigest()
        total += len(left)
        if total > maximum_archive_bytes:
            raise SourceArchiveError("source archive exceeds the fixed archive byte bound")
        digest.update(left)


def _verify_source_archive(
    archive_path: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
    maximum_file_count: int,
    maximum_manifest_bytes: int,
    maximum_archive_bytes: int,
    parent_descriptor: int | None = None,
) -> SourceArchiveReport:
    owned_parent = parent_descriptor is None
    if parent_descriptor is None:
        parent_descriptor, final_name = _open_parent_no_symlinks(archive_path)
    else:
        final_name = os.fspath(archive_path)
        if os.path.basename(final_name) != final_name or not final_name:
            raise SourceArchiveError("dirfd-relative archive name is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(final_name, flags, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            before_identity = _file_identity(source.fileno())
            if before_identity[2] > maximum_archive_bytes:
                raise SourceArchiveError("source archive exceeds the fixed archive byte bound")

            with tempfile.TemporaryDirectory(prefix="corelm-source-archive-") as temporary:
                source_root = Path(temporary) / "source"
                source_root.mkdir(mode=0o700)
                try:
                    archive = tarfile.open(
                        fileobj=source,
                        mode="r:",
                        encoding="utf-8",
                        errors="strict",
                    )
                except (tarfile.TarError, UnicodeError) as error:
                    raise SourceArchiveError("source archive is not an uncompressed tar") from error
                with archive:
                    try:
                        manifest_member = archive.next()
                    except (tarfile.TarError, UnicodeError) as error:
                        raise SourceArchiveError("source archive header is invalid") from error
                    if manifest_member is None:
                        raise SourceArchiveError("source archive is empty")
                    if manifest_member.name != MANIFEST_MEMBER:
                        _safe_archive_name(manifest_member.name)
                        raise SourceArchiveError("source manifest is not the first archive member")
                    _validate_member_metadata(manifest_member, mode=0o644)
                    manifest_raw = _read_member_bytes(
                        archive,
                        manifest_member,
                        maximum_bytes=maximum_manifest_bytes,
                    )
                    manifest = load_source_manifest_bytes(manifest_raw)
                    if manifest["commit"] != expected_commit:
                        raise SourceArchiveError(
                            "source archive commit differs from the expected commit"
                        )
                    if manifest["tree"] != expected_tree:
                        raise SourceArchiveError("source archive tree differs from the expected tree")

                    entries = manifest["files"]
                    if len(entries) > maximum_file_count:
                        raise SourceArchiveError("source archive exceeds the fixed file count bound")
                    total_declared = 0
                    for entry in entries:
                        if entry["bytes"] > maximum_file_bytes:
                            raise SourceArchiveError("source archive file exceeds the fixed byte bound")
                        total_declared += entry["bytes"]
                        if total_declared > maximum_total_bytes:
                            raise SourceArchiveError(
                                "source archive exceeds the fixed total byte bound"
                            )

                        try:
                            member = archive.next()
                        except (tarfile.TarError, UnicodeError) as error:
                            raise SourceArchiveError("source archive header is invalid") from error
                        if member is None:
                            raise SourceArchiveError(
                                "source archive is missing a manifest-declared file"
                            )
                        _safe_archive_name(member.name)
                        expected_name = SOURCE_PREFIX + entry["path"]
                        if member.name != expected_name:
                            raise SourceArchiveError("source archive member order or inventory differs")
                        mode = 0o755 if entry["mode"] == "100755" else 0o644
                        _validate_member_metadata(member, mode=mode)
                        _copy_member_to_file(
                            archive,
                            member,
                            source_root.joinpath(*entry["path"].split("/")),
                            expected_bytes=entry["bytes"],
                            mode=mode,
                        )

                    try:
                        extra = archive.next()
                    except (tarfile.TarError, UnicodeError) as error:
                        raise SourceArchiveError("source archive trailer is invalid") from error
                    if extra is not None:
                        _safe_archive_name(extra.name)
                        if extra.type != tarfile.REGTYPE or not extra.isreg():
                            raise SourceArchiveError(
                                f"archive contains a forbidden non-regular entry: {extra.name}"
                            )
                        raise SourceArchiveError(f"archive contains an extra member: {extra.name}")

                verified = verify_copied_source(
                    source_root,
                    manifest_raw,
                    expected_commit=expected_commit,
                    expected_tree=expected_tree,
                    maximum_file_bytes=maximum_file_bytes,
                    maximum_total_bytes=maximum_total_bytes,
                    maximum_file_count=maximum_file_count,
                )

                with tempfile.TemporaryFile(prefix="corelm-canonical-source-archive-") as canonical:
                    _write_canonical_archive(canonical, manifest_raw, verified)
                    canonical_size = os.fstat(canonical.fileno()).st_size
                    if canonical_size > maximum_archive_bytes:
                        raise SourceArchiveError(
                            "canonical source archive exceeds the fixed archive byte bound"
                        )
                    archive_bytes, archive_sha256 = _compare_canonical_archive(
                        source,
                        canonical,
                        maximum_archive_bytes=maximum_archive_bytes,
                    )

            if _file_identity(source.fileno()) != before_identity:
                raise SourceArchiveError("source archive changed during verification")
    finally:
        if owned_parent:
            os.close(parent_descriptor)

    return SourceArchiveReport(
        commit=expected_commit,
        tree=expected_tree,
        file_count=len(verified),
        source_bytes=sum(len(entry.data) for entry in verified),
        manifest_bytes=len(manifest_raw),
        manifest_sha256=_sha256(manifest_raw),
        archive_bytes=archive_bytes,
        archive_sha256=archive_sha256,
    )


def verify_source_archive(
    archive_path: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
    maximum_manifest_bytes: int = DEFAULT_MAXIMUM_MANIFEST_BYTES,
    maximum_archive_bytes: int = DEFAULT_MAXIMUM_ARCHIVE_BYTES,
) -> SourceArchiveReport:
    """Verify one exact deterministic source archive without invoking Git."""

    maximum_file_bytes = _positive_bound(maximum_file_bytes, label="file byte bound")
    maximum_total_bytes = _positive_bound(maximum_total_bytes, label="total byte bound")
    maximum_file_count = _positive_bound(maximum_file_count, label="file count bound")
    maximum_manifest_bytes = _positive_bound(
        maximum_manifest_bytes, label="manifest byte bound"
    )
    maximum_archive_bytes = _positive_bound(
        maximum_archive_bytes, label="archive byte bound"
    )
    try:
        return _verify_source_archive(
            archive_path,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_bytes=maximum_total_bytes,
            maximum_file_count=maximum_file_count,
            maximum_manifest_bytes=maximum_manifest_bytes,
            maximum_archive_bytes=maximum_archive_bytes,
        )
    except SourceArchiveError:
        raise
    except (GitSourceError, OSError, tarfile.TarError, UnicodeError, ValueError) as error:
        raise SourceArchiveError(str(error) or "source archive verification failed") from error


def create_source_archive(
    repository: Path,
    destination: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
    maximum_manifest_bytes: int = DEFAULT_MAXIMUM_MANIFEST_BYTES,
    maximum_archive_bytes: int = DEFAULT_MAXIMUM_ARCHIVE_BYTES,
) -> SourceArchiveReport:
    """Create, re-open, and independently verify one exact source archive."""

    maximum_file_bytes = _positive_bound(maximum_file_bytes, label="file byte bound")
    maximum_total_bytes = _positive_bound(maximum_total_bytes, label="total byte bound")
    maximum_file_count = _positive_bound(maximum_file_count, label="file count bound")
    maximum_manifest_bytes = _positive_bound(
        maximum_manifest_bytes, label="manifest byte bound"
    )
    maximum_archive_bytes = _positive_bound(
        maximum_archive_bytes, label="archive byte bound"
    )
    repository = _canonical_absolute_path(repository)
    destination = _canonical_absolute_path(destination)
    repository_descriptor: int | None = None
    destination_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        repository_descriptor = _open_directory_no_symlinks(repository)
        repository_identity = _directory_identity(repository_descriptor)
        destination_descriptor, destination_name = _open_parent_no_symlinks(
            destination
        )
        try:
            os.stat(destination_name, dir_fd=destination_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SourceArchiveError("source archive output already exists")

        seal = seal_git_source(
            repository,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_bytes=maximum_total_bytes,
            maximum_file_count=maximum_file_count,
        )
        reopened_repository = _open_directory_no_symlinks(repository)
        try:
            if _directory_identity(reopened_repository) != repository_identity:
                raise SourceArchiveError(
                    "source repository path identity changed during Git sealing"
                )
        finally:
            os.close(reopened_repository)
        manifest_raw = source_manifest_bytes(build_source_manifest(seal))
        if len(manifest_raw) > maximum_manifest_bytes:
            raise SourceArchiveError("source manifest exceeds the fixed byte bound")
        expected_archive_size = _canonical_archive_size(len(manifest_raw), seal.files)
        if expected_archive_size > maximum_archive_bytes:
            raise SourceArchiveError("source archive exceeds the fixed archive byte bound")

        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        temporary_descriptor: int | None = None
        for _attempt in range(128):
            candidate = f".{destination_name}.{secrets.token_hex(16)}.tmp"
            try:
                temporary_descriptor = os.open(
                    candidate,
                    flags,
                    0o600,
                    dir_fd=destination_descriptor,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_descriptor is None or temporary_name is None:
            raise SourceArchiveError("cannot reserve a unique source archive temporary")
        with os.fdopen(temporary_descriptor, "w+b", closefd=True) as temporary_output:
            _write_canonical_archive(temporary_output, manifest_raw, seal.files)
            temporary_output.flush()
            os.fsync(temporary_output.fileno())
            if os.fstat(temporary_output.fileno()).st_size != expected_archive_size:
                raise SourceArchiveError("canonical source archive size calculation differs")

        report = _verify_source_archive(
            Path(temporary_name),
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_bytes=maximum_total_bytes,
            maximum_file_count=maximum_file_count,
            maximum_manifest_bytes=maximum_manifest_bytes,
            maximum_archive_bytes=maximum_archive_bytes,
            parent_descriptor=destination_descriptor,
        )
        os.link(
            temporary_name,
            destination_name,
            src_dir_fd=destination_descriptor,
            dst_dir_fd=destination_descriptor,
            follow_symlinks=False,
        )
        os.fsync(destination_descriptor)
        os.unlink(temporary_name, dir_fd=destination_descriptor)
        os.fsync(destination_descriptor)
        temporary_name = None
        return report
    except SourceArchiveError:
        raise
    except (GitSourceError, OSError, tarfile.TarError, UnicodeError, ValueError) as error:
        raise SourceArchiveError(str(error) or "source archive creation failed") from error
    finally:
        if temporary_name is not None:
            try:
                if destination_descriptor is not None:
                    os.unlink(temporary_name, dir_fd=destination_descriptor)
            except FileNotFoundError:
                pass
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if repository_descriptor is not None:
            os.close(repository_descriptor)


def _add_bounds(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--maximum-file-bytes", type=int, default=DEFAULT_MAXIMUM_FILE_BYTES)
    parser.add_argument("--maximum-total-bytes", type=int, default=DEFAULT_MAXIMUM_TOTAL_BYTES)
    parser.add_argument("--maximum-file-count", type=int, default=DEFAULT_MAXIMUM_FILE_COUNT)
    parser.add_argument(
        "--maximum-manifest-bytes", type=int, default=DEFAULT_MAXIMUM_MANIFEST_BYTES
    )
    parser.add_argument(
        "--maximum-archive-bytes", type=int, default=DEFAULT_MAXIMUM_ARCHIVE_BYTES
    )


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create and re-verify a source archive")
    create.add_argument("--repository", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument(
        "--commit", "--expected-commit", dest="expected_commit", required=True
    )
    create.add_argument("--tree", "--expected-tree", dest="expected_tree", required=True)
    _add_bounds(create)

    verify = subparsers.add_parser("verify", help="verify an existing source archive")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument(
        "--commit", "--expected-commit", dest="expected_commit", required=True
    )
    verify.add_argument("--tree", "--expected-tree", dest="expected_tree", required=True)
    _add_bounds(verify)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    bounds = {
        "maximum_file_bytes": arguments.maximum_file_bytes,
        "maximum_total_bytes": arguments.maximum_total_bytes,
        "maximum_file_count": arguments.maximum_file_count,
        "maximum_manifest_bytes": arguments.maximum_manifest_bytes,
        "maximum_archive_bytes": arguments.maximum_archive_bytes,
    }
    try:
        if arguments.command == "create":
            report = create_source_archive(
                arguments.repository,
                arguments.output,
                expected_commit=arguments.expected_commit,
                expected_tree=arguments.expected_tree,
                **bounds,
            )
        else:
            report = verify_source_archive(
                arguments.archive,
                expected_commit=arguments.expected_commit,
                expected_tree=arguments.expected_tree,
                **bounds,
            )
    except (SourceArchiveError, OSError) as error:
        print(f"SOURCE ARCHIVE FAIL: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(report.as_dict()) + b"\n")
    return 0


__all__ = [
    "ARCHIVE_FORMAT",
    "DEFAULT_MAXIMUM_ARCHIVE_BYTES",
    "DEFAULT_MAXIMUM_MANIFEST_BYTES",
    "MANIFEST_MEMBER",
    "SOURCE_PREFIX",
    "SourceArchiveError",
    "SourceArchiveReport",
    "create_source_archive",
    "main",
    "parse_arguments",
    "verify_source_archive",
]


if __name__ == "__main__":
    raise SystemExit(main())
