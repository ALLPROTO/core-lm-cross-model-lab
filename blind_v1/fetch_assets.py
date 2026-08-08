#!/usr/bin/env python3
"""Fetch immutable blind_v1 model assets with exact, fail-closed verification.

This module intentionally depends only on the Python standard library.  It
does not import model runtimes and never performs inference.  Tests inject a
mock transport; network access is used only by the explicit CLI entry point.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Iterable, Mapping

BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.protocol import require_scientific_schedule_open  # noqa: E402


MANIFEST_SCHEMA = "corelm-blind-crossmodel-v1-model-assets-draft-v1"
DEVELOPMENT_MANIFEST_SCHEMA = (
    "corelm-blind-crossmodel-v1-development-model-assets-v1"
)
DEFAULT_MANIFEST = Path(__file__).with_name("model-assets.draft.json")
DEFAULT_REDIRECT_HOSTS = frozenset(
    {
        "huggingface.co",
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.huggingface.co",
        "cdn-lfs-eu-1.huggingface.co",
        "cdn-lfs-us-1.hf.co",
        "cdn-lfs-eu-1.hf.co",
        "us.aws.cdn.hf.co",
        "cas-bridge.xethub.hf.co",
    }
)
MODEL_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
REPOSITORY = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$"
)
IMMUTABLE_REVISION = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ASSET_BYTES = 8 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
SMALL_FILE_EXCLUSIONS = frozenset({"model.safetensors"})
DEVELOPMENT_DATASET_MODEL_KEY = "ud-english-pud-r2.18"
DEVELOPMENT_DATASET_REPOSITORY = "UniversalDependencies/UD_English-PUD"
DEVELOPMENT_DATASET_REVISION = "e173a1be1b442faf34e7d5a502189ad5d9d1e197"
DEVELOPMENT_DATASET_FILENAME = "en_pud-ud-test.conllu"
DEVELOPMENT_DATASET_SOURCE_PATH = "en_pud-ud-test.conllu"
DEVELOPMENT_DATASET_BYTES = 1_386_858
DEVELOPMENT_DATASET_SHA256 = (
    "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa"
)
DEVELOPMENT_DATASET_HOSTS = frozenset({"raw.githubusercontent.com"})


class AssetFetchError(RuntimeError):
    """A manifest, transport, integrity, or filesystem check failed."""


@dataclass(frozen=True)
class AssetSpecification:
    model_key: str
    repository: str
    revision: str
    filename: str
    expected_bytes: int
    expected_sha256: str

    @property
    def url(self) -> str:
        repository = "/".join(
            urllib.parse.quote(part, safe="") for part in self.repository.split("/")
        )
        filename = "/".join(
            urllib.parse.quote(part, safe="") for part in self.filename.split("/")
        )
        return (
            f"https://huggingface.co/{repository}/resolve/"
            f"{self.revision}/{filename}"
        )


@dataclass(frozen=True)
class DevelopmentDatasetSpecification:
    """One byte-pinned real-data input, kept outside the model manifest."""

    model_key: str = DEVELOPMENT_DATASET_MODEL_KEY
    repository: str = DEVELOPMENT_DATASET_REPOSITORY
    revision: str = DEVELOPMENT_DATASET_REVISION
    filename: str = DEVELOPMENT_DATASET_FILENAME
    expected_bytes: int = DEVELOPMENT_DATASET_BYTES
    expected_sha256: str = DEVELOPMENT_DATASET_SHA256

    @property
    def url(self) -> str:
        repository = "/".join(
            urllib.parse.quote(part, safe="") for part in self.repository.split("/")
        )
        source_path = "/".join(
            urllib.parse.quote(part, safe="")
            for part in DEVELOPMENT_DATASET_SOURCE_PATH.split("/")
        )
        return (
            f"https://raw.githubusercontent.com/{repository}/"
            f"{self.revision}/{source_path}"
        )


@dataclass(frozen=True)
class FetchRecord:
    model_key: str
    filename: str
    bytes: int
    sha256: str
    status: str
    path: str

    def as_json(self) -> dict[str, Any]:
        return {
            "modelKey": self.model_key,
            "filename": self.filename,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "status": self.status,
            "path": self.path,
        }


Transport = Callable[[urllib.request.Request], Any]


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number is forbidden: {value}")
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_components(path: Path) -> Iterable[Path]:
    absolute = _absolute_without_resolving(path)
    current = Path(absolute.anchor)
    yield current
    for part in absolute.parts[1:]:
        current /= part
        yield current


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_directory_no_symlink(path: Path) -> Path:
    absolute = _absolute_without_resolving(path)
    for component in _path_components(absolute):
        try:
            metadata = os.lstat(component)
        except FileNotFoundError as error:
            raise AssetFetchError(f"directory component is missing: {component}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise AssetFetchError(f"symlink directory component is forbidden: {component}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise AssetFetchError(f"non-directory path component: {component}")
    return absolute


def _ensure_directory_no_symlink(path: Path) -> Path:
    absolute = _absolute_without_resolving(path)
    components = list(_path_components(absolute))
    for index, component in enumerate(components):
        try:
            metadata = os.lstat(component)
        except FileNotFoundError:
            if index == 0:
                raise AssetFetchError("filesystem anchor is missing")
            parent = components[index - 1]
            try:
                os.mkdir(component, 0o700)
            except FileExistsError:
                metadata = os.lstat(component)
            else:
                _fsync_directory(parent)
                metadata = os.lstat(component)
        if stat.S_ISLNK(metadata.st_mode):
            raise AssetFetchError(f"symlink directory component is forbidden: {component}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise AssetFetchError(f"non-directory path component: {component}")
    return absolute


def _assert_regular_file_no_symlinks(path: Path) -> Path:
    absolute = _absolute_without_resolving(path)
    _assert_directory_no_symlink(absolute.parent)
    try:
        metadata = os.lstat(absolute)
    except FileNotFoundError as error:
        raise AssetFetchError(f"file is missing: {absolute}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise AssetFetchError(f"symlink file is forbidden: {absolute}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AssetFetchError(f"regular file required: {absolute}")
    return absolute


def _read_manifest_bytes(path: Path) -> bytes:
    safe_path = _assert_regular_file_no_symlinks(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(safe_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AssetFetchError("manifest changed to a non-regular file")
        if metadata.st_size > MAX_MANIFEST_BYTES:
            raise AssetFetchError("model asset manifest exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            result = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(result) > MAX_MANIFEST_BYTES:
            raise AssetFetchError("model asset manifest exceeds the size limit")
        return result
    finally:
        os.close(descriptor)


def _validate_relative_filename(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("asset filename must be a non-empty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe asset filename: {value!r}")
    if path.as_posix() != value:
        raise ValueError(f"non-canonical asset filename: {value!r}")
    return value


def load_manifest(path: Path = DEFAULT_MANIFEST) -> list[AssetSpecification]:
    try:
        manifest = json.loads(
            _read_manifest_bytes(path),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise AssetFetchError(f"invalid model asset manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise AssetFetchError("model asset manifest must contain an object")
    if manifest.get("schemaVersion") not in {
        MANIFEST_SCHEMA,
        DEVELOPMENT_MANIFEST_SCHEMA,
    }:
        raise AssetFetchError("unexpected model asset manifest schema")
    if manifest.get("completeRuntimeFileList") is not True:
        raise AssetFetchError("manifest does not commit a complete runtime file list")
    models = manifest.get("models")
    if not isinstance(models, dict) or not models:
        raise AssetFetchError("manifest models must be a non-empty object")

    specifications: list[AssetSpecification] = []
    folded_model_keys: set[str] = set()
    for model_key, model in models.items():
        if not isinstance(model_key, str) or MODEL_KEY.fullmatch(model_key) is None:
            raise AssetFetchError(f"unsafe model key: {model_key!r}")
        folded_key = model_key.casefold()
        if folded_key in folded_model_keys:
            raise AssetFetchError("case-colliding model keys are forbidden")
        folded_model_keys.add(folded_key)
        if not isinstance(model, dict):
            raise AssetFetchError(f"model entry must be an object: {model_key}")
        repository = model.get("repository")
        revision = model.get("revision")
        if not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None:
            raise AssetFetchError(f"unsafe repository for {model_key}")
        if not isinstance(revision, str) or IMMUTABLE_REVISION.fullmatch(revision) is None:
            raise AssetFetchError(f"non-immutable revision for {model_key}")
        files = model.get("files")
        if not isinstance(files, dict) or not files:
            raise AssetFetchError(f"empty file list for {model_key}")
        folded_filenames: set[str] = set()
        for raw_filename, specification in files.items():
            try:
                filename = _validate_relative_filename(raw_filename)
            except ValueError as error:
                raise AssetFetchError(str(error)) from error
            folded_filename = filename.casefold()
            if folded_filename in folded_filenames:
                raise AssetFetchError(
                    f"case-colliding filenames for {model_key}: {filename}"
                )
            folded_filenames.add(folded_filename)
            if not isinstance(specification, dict):
                raise AssetFetchError(
                    f"asset specification must be an object: {model_key}/{filename}"
                )
            expected_bytes = specification.get("bytes")
            expected_sha256 = specification.get("sha256")
            if (
                type(expected_bytes) is not int
                or expected_bytes <= 0
                or expected_bytes > MAX_ASSET_BYTES
            ):
                raise AssetFetchError(
                    f"invalid byte count for {model_key}/{filename}"
                )
            if (
                not isinstance(expected_sha256, str)
                or SHA256.fullmatch(expected_sha256) is None
            ):
                raise AssetFetchError(f"invalid SHA-256 for {model_key}/{filename}")
            specifications.append(
                AssetSpecification(
                    model_key=model_key,
                    repository=repository,
                    revision=revision,
                    filename=filename,
                    expected_bytes=expected_bytes,
                    expected_sha256=expected_sha256,
                )
            )
    return specifications


def _validate_https_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname.lower() if parsed.hostname else None
    if parsed.scheme.lower() != "https":
        raise AssetFetchError(f"non-HTTPS asset URL is forbidden: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise AssetFetchError("credentials in asset URLs are forbidden")
    if parsed.port not in {None, 443}:
        raise AssetFetchError("non-standard HTTPS ports are forbidden")
    if hostname not in allowed_hosts:
        raise AssetFetchError(f"redirect host is not allowlisted: {hostname}")


class AllowlistedHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects outside the explicit HTTPS host allowlist."""

    def __init__(self, allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> urllib.request.Request | None:
        target = urllib.parse.urljoin(request.full_url, new_url)
        _validate_https_url(target, self.allowed_hosts)
        return super().redirect_request(
            request, file_pointer, code, message, headers, target
        )


def default_transport(
    allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS,
) -> Transport:
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        AllowlistedHTTPSRedirectHandler(allowed_hosts),
        urllib.request.HTTPSHandler(context=context),
    )

    def open_request(request: urllib.request.Request) -> Any:
        _validate_https_url(request.full_url, allowed_hosts)
        return opener.open(request, timeout=120)

    return open_request


def _open_existing_for_verification(path: Path) -> int:
    _assert_directory_no_symlink(path.parent)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode):
        raise AssetFetchError(f"symlink asset leaf is forbidden: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AssetFetchError(f"asset leaf must be a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise AssetFetchError(f"asset changed to a non-regular file: {path}")
    return descriptor


def _digest_descriptor_bounded(descriptor: int, expected_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while total <= expected_bytes:
        remaining = expected_bytes + 1 - total
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        total += len(chunk)
        if total > expected_bytes:
            break
        digest.update(chunk)
    return total, digest.hexdigest()


def _verify_existing(path: Path, specification: AssetSpecification) -> FetchRecord:
    descriptor = _open_existing_for_verification(path)
    try:
        size, digest = _digest_descriptor_bounded(
            descriptor, specification.expected_bytes
        )
    finally:
        os.close(descriptor)
    if size != specification.expected_bytes or digest != specification.expected_sha256:
        raise AssetFetchError(
            f"existing asset differs and will not be overwritten: {path}"
        )
    return FetchRecord(
        model_key=specification.model_key,
        filename=specification.filename,
        bytes=size,
        sha256=digest,
        status="verified-existing",
        path=str(path),
    )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise AssetFetchError("short write while materializing asset")
        view = view[written:]


def _response_header(response: Any, name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(name)
    return str(value) if value is not None else None


def _read_response_to_descriptor(
    response: Any,
    descriptor: int,
    specification: AssetSpecification,
    allowed_hosts: frozenset[str],
) -> tuple[int, str]:
    status_code = getattr(response, "status", None)
    if status_code != 200:
        raise AssetFetchError(f"asset response status is not 200: {status_code}")
    final_url = response.geturl()
    if not isinstance(final_url, str):
        raise AssetFetchError("asset response has no final URL")
    _validate_https_url(final_url, allowed_hosts)
    content_encoding = _response_header(response, "Content-Encoding")
    if content_encoding is not None and content_encoding.lower() not in {
        "",
        "identity",
    }:
        raise AssetFetchError("encoded asset responses are forbidden")
    content_length = _response_header(response, "Content-Length")
    if content_length is not None:
        try:
            parsed_length = int(content_length, 10)
        except ValueError as error:
            raise AssetFetchError("invalid Content-Length") from error
        if parsed_length != specification.expected_bytes:
            raise AssetFetchError(
                "Content-Length differs from the committed asset size"
            )

    digest = hashlib.sha256()
    total = 0
    while total <= specification.expected_bytes:
        request_bytes = min(
            READ_CHUNK_BYTES, specification.expected_bytes + 1 - total
        )
        chunk = response.read(request_bytes)
        if not isinstance(chunk, bytes):
            raise AssetFetchError("asset transport returned non-bytes data")
        if len(chunk) > request_bytes:
            raise AssetFetchError("asset transport exceeded the bounded read request")
        if not chunk:
            break
        total += len(chunk)
        if total > specification.expected_bytes:
            raise AssetFetchError("asset response exceeds the committed byte count")
        _write_all(descriptor, chunk)
        digest.update(chunk)
    if total != specification.expected_bytes:
        raise AssetFetchError(
            f"asset byte count mismatch: {total} != {specification.expected_bytes}"
        )
    observed_digest = digest.hexdigest()
    if observed_digest != specification.expected_sha256:
        raise AssetFetchError("asset SHA-256 differs from the committed digest")
    return total, observed_digest


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename without replacing an existing destination.

    Darwin and Linux provide native no-replace rename operations.  The
    hard-link fallback has the same atomic no-clobber publication property on
    filesystems that do not expose either operation through libc.
    """

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        renamex_np = libc.renamex_np
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        if renamex_np(source_bytes, destination_bytes, 0x00000004) == 0:
            return
        error_number = ctypes.get_errno()
        if error_number not in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
            raise OSError(error_number, os.strerror(error_number), destination)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(-100, source_bytes, -100, destination_bytes, 1) == 0:
            return
        error_number = ctypes.get_errno()
        if error_number not in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
            raise OSError(error_number, os.strerror(error_number), destination)

    os.link(source, destination, follow_symlinks=False)
    os.unlink(source)


def _remove_own_partial(path: Path, device: int, inode: int) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_dev == device
        and metadata.st_ino == inode
    ):
        os.unlink(path)
        _fsync_directory(path.parent)


def fetch_asset(
    specification: AssetSpecification | DevelopmentDatasetSpecification,
    destination_root: Path,
    *,
    transport: Transport,
    allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS,
) -> FetchRecord:
    require_scientific_schedule_open(operation="fetch one Blind V1 asset")
    return _historical_fetch_asset(
        specification,
        destination_root,
        transport=transport,
        allowed_hosts=allowed_hosts,
    )


def _historical_fetch_asset(
    specification: AssetSpecification | DevelopmentDatasetSpecification,
    destination_root: Path,
    *,
    transport: Transport,
    allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS,
) -> FetchRecord:
    """Retain exact fetch mechanics for isolated historical fixtures."""

    root = _ensure_directory_no_symlink(destination_root)
    model_directory = _ensure_directory_no_symlink(root / specification.model_key)
    relative = PurePosixPath(specification.filename)
    parent = model_directory
    for component in relative.parts[:-1]:
        parent = _ensure_directory_no_symlink(parent / component)
    destination = parent / relative.name
    partial = parent / f"{relative.name}.partial"

    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        return _verify_existing(destination, specification)

    try:
        os.lstat(partial)
    except FileNotFoundError:
        pass
    else:
        raise AssetFetchError(f"exclusive partial path already exists: {partial}")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(partial, flags, 0o600)
    partial_metadata = os.fstat(descriptor)
    if not stat.S_ISREG(partial_metadata.st_mode):
        os.close(descriptor)
        raise AssetFetchError("partial asset is not a regular file")
    published = False
    try:
        _validate_https_url(specification.url, allowed_hosts)
        request = urllib.request.Request(
            specification.url,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "corelm-blind-v1-asset-fetcher/1",
            },
            method="GET",
        )
        response = transport(request)
        manager = response if hasattr(response, "__enter__") else closing(response)
        with manager as opened_response:
            size, digest = _read_response_to_descriptor(
                opened_response,
                descriptor,
                specification,
                allowed_hosts,
            )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            _rename_noreplace(partial, destination)
        except FileExistsError:
            concurrent = _verify_existing(destination, specification)
            _remove_own_partial(
                partial, partial_metadata.st_dev, partial_metadata.st_ino
            )
            return FetchRecord(
                model_key=concurrent.model_key,
                filename=concurrent.filename,
                bytes=concurrent.bytes,
                sha256=concurrent.sha256,
                status="verified-concurrent",
                path=concurrent.path,
            )
        published = True
        _fsync_directory(parent)
        return FetchRecord(
            model_key=specification.model_key,
            filename=specification.filename,
            bytes=size,
            sha256=digest,
            status="downloaded-and-verified",
            path=str(destination),
        )
    except (AssetFetchError, OSError, urllib.error.URLError) as error:
        if isinstance(error, AssetFetchError):
            raise
        raise AssetFetchError(f"asset fetch failed: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            _remove_own_partial(
                partial, partial_metadata.st_dev, partial_metadata.st_ino
            )


def fetch_assets(
    manifest_path: Path,
    destination_root: Path,
    *,
    selected_models: set[str] | None = None,
    small_files_only: bool = False,
    transport: Transport | None = None,
    allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS,
) -> list[FetchRecord]:
    require_scientific_schedule_open(operation="fetch Blind V1 model assets")
    return _historical_fetch_assets(
        manifest_path,
        destination_root,
        selected_models=selected_models,
        small_files_only=small_files_only,
        transport=transport,
        allowed_hosts=allowed_hosts,
    )


def _historical_fetch_assets(
    manifest_path: Path,
    destination_root: Path,
    *,
    selected_models: set[str] | None = None,
    small_files_only: bool = False,
    transport: Transport | None = None,
    allowed_hosts: frozenset[str] = DEFAULT_REDIRECT_HOSTS,
) -> list[FetchRecord]:
    """Retain exact multi-asset mechanics for isolated historical fixtures."""

    specifications = load_manifest(manifest_path)
    known_models = {item.model_key for item in specifications}
    if selected_models is not None:
        unknown = sorted(selected_models - known_models)
        if unknown:
            raise AssetFetchError("unknown selected models: " + ",".join(unknown))
    chosen = [
        item
        for item in specifications
        if (selected_models is None or item.model_key in selected_models)
        and (
            not small_files_only
            or PurePosixPath(item.filename).name not in SMALL_FILE_EXCLUSIONS
        )
    ]
    if not chosen:
        raise AssetFetchError("asset selection is empty")
    active_transport = transport or default_transport(allowed_hosts)
    records: list[FetchRecord] = []
    for specification in chosen:
        records.append(
            _historical_fetch_asset(
                specification,
                destination_root,
                transport=active_transport,
                allowed_hosts=allowed_hosts,
            )
        )
    return records


def fetch_development_dataset(
    destination_root: Path,
    *,
    transport: Transport | None = None,
) -> FetchRecord:
    """Fetch or reverify the exact official UD English PUD r2.18 bytes."""

    require_scientific_schedule_open(
        operation="fetch Blind V1 development-control corpus"
    )
    return _historical_fetch_development_dataset(
        destination_root, transport=transport
    )


def _historical_fetch_development_dataset(
    destination_root: Path,
    *,
    transport: Transport | None = None,
) -> FetchRecord:
    """Retain the corpus-fetch mechanics for non-scientific fixture replay."""

    active_transport = transport or default_transport(DEVELOPMENT_DATASET_HOSTS)
    return _historical_fetch_asset(
        DevelopmentDatasetSpecification(),
        destination_root,
        transport=active_transport,
        allowed_hosts=DEVELOPMENT_DATASET_HOSTS,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--model", action="append", dest="models")
    parser.add_argument(
        "--small-files-only",
        action="store_true",
        help="verify/materialize manifest files except model.safetensors",
    )
    parser.add_argument(
        "--include-development-dataset",
        action="store_true",
        help="also fetch the exact official UD English PUD r2.18 CoNLL-U file",
    )
    parser.add_argument(
        "--development-dataset-only",
        action="store_true",
        help="fetch only the exact official UD English PUD r2.18 CoNLL-U file",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        require_scientific_schedule_open(operation="run Blind V1 asset fetcher")
        if arguments.development_dataset_only and (
            arguments.models or arguments.small_files_only
        ):
            raise AssetFetchError(
                "--development-dataset-only cannot be combined with model selection"
            )
        records = []
        if not arguments.development_dataset_only:
            records.extend(
                fetch_assets(
                    arguments.manifest,
                    arguments.destination,
                    selected_models=set(arguments.models) if arguments.models else None,
                    small_files_only=arguments.small_files_only,
                )
            )
        if (
            arguments.include_development_dataset
            or arguments.development_dataset_only
        ):
            records.append(fetch_development_dataset(arguments.destination))
    except (AssetFetchError, ValueError) as error:
        print(f"ASSET FETCH FAIL: {error}", file=sys.stderr)
        return 1
    summary = {
        "schemaVersion": "corelm-blind-v1-asset-fetch-result-v1",
        "status": (
            "DEVELOPMENT_DATASET_VERIFIED"
            if arguments.development_dataset_only
            else (
                "SMALL_ASSETS_VERIFIED"
                if arguments.small_files_only
                else "ALL_ASSETS_VERIFIED"
            )
        ),
        "smallFilesOnly": arguments.small_files_only,
        "developmentDatasetIncluded": (
            arguments.include_development_dataset
            or arguments.development_dataset_only
        ),
        "records": [record.as_json() for record in records],
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
