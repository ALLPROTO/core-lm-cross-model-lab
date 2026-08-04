#!/usr/bin/env python3
"""Hardened, auditable MediaWiki collection for blind-v3.

This module implements the request and byte-commitment rules from the local
v3 preregistration draft.  It does not import model weights, the codec, Torch,
Transformers, or perform inference.  Tokenization is supplied through a small
injected interface so a later frozen runtime can use only verified tokenizer
assets.

Primary references:

* https://www.mediawiki.org/wiki/API:RecentChanges
* https://www.mediawiki.org/wiki/API:Continue
* https://www.mediawiki.org/wiki/API:Revisions

The production transport deliberately speaks bounded HTTP/1.1 over a pinned
TLS trust bundle.  That lets the archive retain the exact received status and
header bytes rather than a library's reconstructed header mapping.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import socket
import ssl
import stat
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import quote, urlencode, urlsplit

from v3.protocol import canonical_json_bytes, load_json_strict_bytes, sha256_bytes


PROJECTS = ("de.wikipedia.org", "en.wikipedia.org", "fr.wikipedia.org")
MODEL_KEYS = ("gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py")
CORPUS_START = datetime(2026, 8, 16, tzinfo=timezone.utc)
CORPUS_END = datetime(2026, 8, 30, tzinfo=timezone.utc)
CRAWL_NOT_BEFORE = (
    datetime(2026, 8, 30, 6, tzinfo=timezone.utc),
    datetime(2026, 8, 31, 6, tzinfo=timezone.utc),
)
MINIMUM_ELIGIBLE_PER_PROJECT = 64
RECORD_MAGIC = b"CORELM-LIVEWIKI-V3-RECORD\0"
MANIFEST_SCHEMA = "corelm-crossmodel-livewiki-v3-corpus-manifest-v1"
CRAWL_STAGE_SCHEMA = "corelm-crossmodel-livewiki-v3-crawl-stage-v1"
MAX_HTTP_WIRE_BYTES = 64 * 1024 * 1024
MAX_JSON_BODY_BYTES = 32 * 1024 * 1024
MAX_CRAWL_PAGES = 100_000
USER_AGENT = (
    "CoreLMBlindV3Collector/1.0 "
    "(https://github.com/ALLPROTO/core-lm-cross-model-lab)"
)
HEX_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class SnapshotError(ValueError):
    """Raised when collection or verification cannot preserve the protocol."""


class RevisionIneligible(SnapshotError):
    """A transparently archived revision that cannot enter the eligible ledger."""

    def __init__(
        self,
        *reasons: str,
        revision_api_current_title: str | None = None,
    ) -> None:
        if not reasons or any(not isinstance(reason, str) or not reason for reason in reasons):
            raise SnapshotError("revision ineligibility reason is invalid")
        if revision_api_current_title is not None:
            _strict_utf8(
                revision_api_current_title,
                label="revision API current title",
            )
        self.reasons = tuple(reasons)
        self.revision_api_current_title = revision_api_current_title
        super().__init__(", ".join(reasons))


class TokenizerLike(Protocol):
    vocab_size: int

    def encode(self, text: str, *, add_special_tokens: bool) -> Sequence[int]: ...


@dataclass(frozen=True)
class ArchivedHTTPResponse:
    request_uri: str
    status: int
    header_bytes: bytes
    body: bytes


Transport = Callable[[str], ArchivedHTTPResponse]


def _utc_seconds(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        raise SnapshotError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise SnapshotError(f"{label} is not a real UTC timestamp") from error


def _u64(value: Any, *, label: str) -> int:
    if type(value) is not int or not 0 <= value < 2**64:
        raise SnapshotError(f"{label} is outside uint64")
    return value


def _u32(value: Any, *, label: str) -> int:
    if type(value) is not int or not 0 <= value < 2**32:
        raise SnapshotError(f"{label} is outside uint32")
    return value


def _strict_utf8(value: Any, *, label: str, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise SnapshotError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
        if encoded.decode("utf-8", errors="strict") != value:
            raise SnapshotError(f"{label} does not round-trip through strict UTF-8")
    except (UnicodeEncodeError, UnicodeDecodeError) as error:
        raise SnapshotError(f"{label} is not strict UTF-8") from error
    return encoded


def _len_u64(value: bytes) -> bytes:
    return struct.pack(">Q", len(value))


def serialize_record(
    *,
    project: str,
    pageid: int,
    revid: int,
    userid: int,
    timestamp: str,
    username: str,
    title: str,
    content: str,
) -> bytes:
    if project not in PROJECTS:
        raise SnapshotError("record project is not registered")
    project_bytes = project.encode("ascii", errors="strict")
    timestamp_bytes = _strict_utf8(timestamp, label="timestamp")
    _utc_seconds(timestamp, label="timestamp")
    username_bytes = _strict_utf8(username, label="username")
    title_bytes = _strict_utf8(title, label="title")
    content_bytes = _strict_utf8(content, label="content")
    values = (_u64(pageid, label="pageid"), _u64(revid, label="revid"), _u64(userid, label="userid"))
    return b"".join(
        (
            RECORD_MAGIC,
            _len_u64(project_bytes),
            project_bytes,
            *(struct.pack(">Q", value) for value in values),
            _len_u64(timestamp_bytes),
            timestamp_bytes,
            _len_u64(username_bytes),
            username_bytes,
            _len_u64(title_bytes),
            title_bytes,
            _len_u64(content_bytes),
            content_bytes,
        )
    )


def parse_record(record_bytes: bytes) -> dict[str, Any]:
    if not isinstance(record_bytes, bytes) or not record_bytes.startswith(RECORD_MAGIC):
        raise SnapshotError("corpus record magic differs")
    offset = len(RECORD_MAGIC)

    def take(size: int, label: str) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(record_bytes):
            raise SnapshotError(f"corpus record is truncated at {label}")
        result = record_bytes[offset : offset + size]
        offset += size
        return result

    def take_u64(label: str) -> int:
        return int.from_bytes(take(8, label), "big")

    def take_string(label: str) -> str:
        length = take_u64(f"{label} length")
        try:
            return take(length, label).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise SnapshotError(f"record {label} is not strict UTF-8") from error

    project = take_string("project")
    pageid = take_u64("pageid")
    revid = take_u64("revid")
    userid = take_u64("userid")
    timestamp = take_string("timestamp")
    username = take_string("username")
    title = take_string("title")
    content = take_string("content")
    if offset != len(record_bytes):
        raise SnapshotError("corpus record has trailing bytes")
    rebuilt = serialize_record(
        project=project,
        pageid=pageid,
        revid=revid,
        userid=userid,
        timestamp=timestamp,
        username=username,
        title=title,
        content=content,
    )
    if rebuilt != record_bytes:
        raise SnapshotError("corpus record is not canonical")
    return {
        "project": project,
        "pageid": pageid,
        "revid": revid,
        "userid": userid,
        "timestamp": timestamp,
        "username": username,
        "title": title,
        "content": content,
    }


def token_commitment(tokenizer: TokenizerLike, input_text: str) -> dict[str, Any]:
    vocab_size = getattr(tokenizer, "vocab_size", None)
    if type(vocab_size) is not int or not 1 <= vocab_size <= 2**32:
        raise SnapshotError("tokenizer vocab_size is outside the registered bounds")
    token_ids = list(tokenizer.encode(input_text, add_special_tokens=False))
    for token_id in token_ids:
        if type(token_id) is not int or not 0 <= token_id < vocab_size or token_id > 2**32 - 1:
            raise SnapshotError("tokenizer emitted an out-of-range or non-integer ID")

    def stream(ids: Sequence[int]) -> bytes:
        return struct.pack("<Q", len(ids)) + b"".join(
            struct.pack("<I", token_id) for token_id in ids
        )

    return {
        "tokenCount": len(token_ids),
        "vocabSize": vocab_size,
        "completeStreamSHA256": sha256_bytes(stream(token_ids)),
        "first512StreamSHA256": sha256_bytes(stream(token_ids[:512])),
    }


def recentchanges_uri(project: str, continuation: Mapping[str, str] | None = None) -> str:
    if project not in PROJECTS:
        raise SnapshotError("unregistered MediaWiki project")
    parameters: list[tuple[str, str]] = [
        ("action", "query"),
        ("list", "recentchanges"),
        ("rcstart", "2026-08-16T00:00:00Z"),
        ("rcend", "2026-08-30T00:00:00Z"),
        ("rcdir", "newer"),
        ("rctype", "new"),
        ("rcnamespace", "0"),
        ("rcshow", "!bot|!redirect"),
        ("rcprop", "title|ids|timestamp|redirect|sha1|user|userid"),
        ("rclimit", "max"),
        ("format", "json"),
        ("formatversion", "2"),
    ]
    if continuation is not None:
        if set(continuation) != {"continue", "rccontinue"}:
            raise SnapshotError("RecentChanges continuation fields differ")
        for key in ("continue", "rccontinue"):
            value = continuation[key]
            if not isinstance(value, str) or not value:
                raise SnapshotError("RecentChanges continuation value is empty")
            parameters.append((key, value))
    query = urlencode(parameters, quote_via=quote, safe="")
    return f"https://{project}/w/api.php?{query}"


def revision_uri(project: str, revid: int) -> str:
    if project not in PROJECTS:
        raise SnapshotError("unregistered MediaWiki project")
    _u64(revid, label="revid")
    if revid == 0:
        raise SnapshotError("revid must be positive")
    parameters = [
        ("action", "query"),
        ("prop", "revisions"),
        ("revids", str(revid)),
        ("rvslots", "main"),
        (
            "rvprop",
            "ids|timestamp|user|userid|sha1|slotsha1|contentmodel|content",
        ),
        ("format", "json"),
        ("formatversion", "2"),
    ]
    return f"https://{project}/w/api.php?{urlencode(parameters, quote_via=quote, safe='')}"


def _parse_header_block(header_bytes: bytes) -> tuple[int, dict[str, list[str]]]:
    if not header_bytes.endswith(b"\r\n\r\n") or b"\x00" in header_bytes:
        raise SnapshotError("HTTP header block is not exact CRLF framing")
    lines = header_bytes[:-4].split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [\x20-\x7e]*", lines[0]) is None:
        raise SnapshotError("HTTP status line is invalid")
    status = int(lines[0].split(b" ", 2)[1])
    result: dict[str, list[str]] = {}
    for raw in lines[1:]:
        if not raw or raw[:1] in b" \t" or b":" not in raw:
            raise SnapshotError("HTTP header line is malformed or folded")
        name, value = raw.split(b":", 1)
        if re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise SnapshotError("HTTP header name is invalid")
        try:
            decoded = value.strip(b" \t").decode("latin-1")
        except UnicodeDecodeError as error:
            raise SnapshotError("HTTP header value is invalid") from error
        result.setdefault(name.decode("ascii").lower(), []).append(decoded)
    return status, result


def response_date(response: ArchivedHTTPResponse) -> datetime:
    status, headers = _parse_header_block(response.header_bytes)
    if status != response.status:
        raise SnapshotError("archived HTTP status differs from status line")
    values = headers.get("date", [])
    if len(values) != 1:
        raise SnapshotError("HTTP response must contain exactly one Date header")
    try:
        parsed = parsedate_to_datetime(values[0])
    except (TypeError, ValueError) as error:
        raise SnapshotError("HTTP Date header is invalid") from error
    if parsed.tzinfo is None:
        raise SnapshotError("HTTP Date header has no timezone")
    return parsed.astimezone(timezone.utc)


def _validate_response(response: ArchivedHTTPResponse, *, expected_uri: str) -> None:
    if response.request_uri != expected_uri:
        raise SnapshotError("transport returned a different request URI")
    parsed = urlsplit(response.request_uri)
    if parsed.scheme != "https" or parsed.hostname not in {*PROJECTS, "beacon.nist.gov"}:
        raise SnapshotError("response request URI is not allowlisted HTTPS")
    status, headers = _parse_header_block(response.header_bytes)
    if status != 200 or response.status != 200:
        raise SnapshotError(f"HTTP request did not return 200: {response.status}")
    if "transfer-encoding" in headers:
        raise SnapshotError("transfer-coded responses are forbidden in the archive")
    lengths = headers.get("content-length", [])
    if len(lengths) != 1 or not lengths[0].isdigit():
        raise SnapshotError("response requires one decimal Content-Length")
    if int(lengths[0]) != len(response.body):
        raise SnapshotError("response Content-Length differs from body bytes")
    if len(response.body) > MAX_JSON_BODY_BYTES:
        raise SnapshotError("response body exceeds the fixed bound")


class PinnedHTTPSClient:
    """Minimal HTTP/1.1 GET transport preserving exact response headers."""

    def __init__(
        self,
        *,
        ca_bundle: Path,
        ca_bundle_sha256: str,
        allowed_hosts: Sequence[str],
        timeout_seconds: float = 30.0,
    ) -> None:
        ca_bytes = _read_direct_regular(
            ca_bundle,
            label="pinned CA bundle",
        )
        if sha256_bytes(ca_bytes) != ca_bundle_sha256:
            raise SnapshotError("pinned CA bundle SHA-256 mismatch")
        try:
            ca_text = ca_bytes.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise SnapshotError("pinned CA bundle is not ASCII PEM") from error
        if not allowed_hosts or any(host not in {*PROJECTS, "beacon.nist.gov"} for host in allowed_hosts):
            raise SnapshotError("HTTPS allowlist contains an unexpected host")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 300
        ):
            raise SnapshotError("HTTPS timeout is outside the fixed safety bound")
        self.allowed_hosts = frozenset(allowed_hosts)
        self.timeout_seconds = float(timeout_seconds)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cadata=ca_text)
        self.context.set_alpn_protocols(["http/1.1"])

    def __call__(self, uri: str) -> ArchivedHTTPResponse:
        parsed = urlsplit(uri)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.allowed_hosts
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise SnapshotError("HTTPS request URI violates the frozen allowlist")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="strict")
        raw_socket = socket.create_connection(
            (parsed.hostname, 443), timeout=self.timeout_seconds
        )
        try:
            with self.context.wrap_socket(
                raw_socket, server_hostname=parsed.hostname
            ) as tls_socket:
                if tls_socket.selected_alpn_protocol() not in (None, "http/1.1"):
                    raise SnapshotError("server negotiated an unsupported HTTP protocol")
                tls_socket.sendall(request)
                chunks: list[bytes] = []
                observed = 0
                while True:
                    chunk = tls_socket.recv(min(65536, MAX_HTTP_WIRE_BYTES + 1 - observed))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    observed += len(chunk)
                    if observed > MAX_HTTP_WIRE_BYTES:
                        raise SnapshotError("HTTP response exceeds the fixed wire bound")
        finally:
            raw_socket.close()
        wire = b"".join(chunks)
        boundary = wire.find(b"\r\n\r\n")
        if boundary < 0:
            raise SnapshotError("HTTP response has no header terminator")
        header_bytes = wire[: boundary + 4]
        body = wire[boundary + 4 :]
        status, headers = _parse_header_block(header_bytes)
        if 100 <= status < 200 or 300 <= status < 400:
            raise SnapshotError("interim responses and redirects are forbidden")
        if "transfer-encoding" in headers:
            raise SnapshotError("chunked/transfer-coded responses are forbidden")
        response = ArchivedHTTPResponse(uri, status, header_bytes, body)
        _validate_response(response, expected_uri=uri)
        return response


def _safe_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise SnapshotError("manifest relative path must be a string")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise SnapshotError("manifest contains an unsafe relative path")
    return path


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _write_new_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_path(
    path: Path,
    *,
    create: bool = False,
    label: str,
) -> tuple[int, Path]:
    """Anchor an absolute directory by walking every component without links."""

    absolute = _absolute_without_resolving(path)
    flags = _directory_flags()
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as error:
        raise SnapshotError(f"cannot anchor {label}") from error
    try:
        for component in absolute.parts[1:]:
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise SnapshotError(f"{label} component is not a directory")
            if created:
                os.fsync(child)
                os.fsync(descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise SnapshotError(
            f"{label} contains a symlink, missing component, or non-directory"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute


def _open_relative_directory(
    anchor: int,
    relative: PurePosixPath,
    *,
    create: bool = False,
    label: str,
) -> int:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SnapshotError(f"{label} is not a safe relative directory")
    flags = _directory_flags()
    try:
        descriptor = os.open(".", flags, dir_fd=anchor)
    except OSError as error:
        raise SnapshotError(f"cannot duplicate anchored {label}") from error
    try:
        for component in relative.parts:
            created = False
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise SnapshotError(f"{label} component is not a directory")
            if created:
                os.fsync(child)
                os.fsync(descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise SnapshotError(
            f"{label} contains a symlink, missing component, or non-directory"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_root_and_parent(
    root: Path,
    relative: PurePosixPath,
    *,
    create_root: bool = False,
    create_parent: bool = False,
    label: str,
) -> tuple[int, int, Path]:
    root_descriptor, absolute_root = _open_directory_path(
        root,
        create=create_root,
        label="snapshot root",
    )
    try:
        parent_descriptor = _open_relative_directory(
            root_descriptor,
            relative.parent,
            create=create_parent,
            label=f"{label} parent",
        )
    except Exception:
        os.close(root_descriptor)
        raise
    return root_descriptor, parent_descriptor, absolute_root


def _entry_metadata(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _stable_directory_entries(
    descriptor: int,
    *,
    label: str,
) -> dict[str, os.stat_result]:
    before = os.fstat(descriptor)
    try:
        names = os.listdir(descriptor)
        entries = {
            name: os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            for name in names
        }
        names_after = os.listdir(descriptor)
    except OSError as error:
        raise SnapshotError(f"cannot inspect anchored {label}") from error
    after = os.fstat(descriptor)
    directory_identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )
    if (
        directory_identity(before) != directory_identity(after)
        or set(names) != set(names_after)
        or len(entries) != len(names)
    ):
        raise SnapshotError(f"{label} changed while being inspected")
    return entries


def _open_optional_relative_directory(
    anchor: int,
    relative: PurePosixPath,
    *,
    label: str,
) -> int | None:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SnapshotError(f"{label} is not a safe relative directory")
    flags = _directory_flags()
    descriptor = os.open(".", flags, dir_fd=anchor)
    try:
        for component in relative.parts:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.close(descriptor)
                return None
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise SnapshotError(f"{label} component is not a directory")
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise SnapshotError(
            f"{label} contains a symlink or non-directory component"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _relative_entry_metadata(
    anchor: int,
    relative: PurePosixPath,
    *,
    label: str,
) -> os.stat_result | None:
    parent = _open_optional_relative_directory(
        anchor,
        relative.parent,
        label=f"{label} parent",
    )
    if parent is None:
        return None
    try:
        return _entry_metadata(parent, relative.name)
    finally:
        os.close(parent)


def _require_directory_entry(
    parent: int,
    name: str,
    *,
    label: str,
) -> os.stat_result:
    metadata = _entry_metadata(parent, name)
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotError(f"{label} is a symlink/non-directory")
    return metadata


def _require_regular_entry(
    parent: int,
    name: str,
    *,
    label: str,
) -> os.stat_result:
    metadata = _entry_metadata(parent, name)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        raise SnapshotError(f"{label} is a symlink/non-regular file")
    return metadata


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_regular_at(parent: int, name: str, *, label: str) -> bytes:
    try:
        descriptor = os.open(name, _read_flags(), dir_fd=parent)
    except OSError as error:
        raise SnapshotError(
            f"{label} is missing, symlinked, or non-regular"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotError(f"{label} is a symlink/non-regular file")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
        current = _entry_metadata(parent, name)
        if (
            _identity(before) != _identity(after)
            or observed != before.st_size
            or current is None
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise SnapshotError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_direct_regular(path: Path, *, label: str) -> bytes:
    absolute = _absolute_without_resolving(path)
    parent, _ = _open_directory_path(absolute.parent, label=f"{label} parent")
    try:
        return _read_regular_at(parent, absolute.name, label=label)
    finally:
        os.close(parent)


def _read_relative_regular(
    root: Path,
    relative: PurePosixPath,
    *,
    label: str,
) -> bytes:
    root_descriptor, parent, _ = _open_root_and_parent(
        root,
        relative,
        label=label,
    )
    try:
        return _read_regular_at(parent, relative.name, label=label)
    finally:
        os.close(parent)
        os.close(root_descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor, absolute = _open_directory_path(path, label="directory to fsync")
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise SnapshotError(f"cannot durably fsync directory: {absolute}") from error
    finally:
        os.close(descriptor)


def _ensure_directory(root: Path, relative: PurePosixPath = PurePosixPath(".")) -> Path:
    root_descriptor, absolute = _open_directory_path(
        root,
        create=True,
        label="snapshot root",
    )
    try:
        directory = _open_relative_directory(
            root_descriptor,
            relative,
            create=True,
            label="snapshot path",
        )
        os.close(directory)
    finally:
        os.close(root_descriptor)
    return absolute.joinpath(*relative.parts)


def _write_exclusive(root: Path, relative: str, value: bytes) -> dict[str, Any]:
    safe = _safe_relative_path(relative)
    root_descriptor, parent, _ = _open_root_and_parent(
        root,
        safe,
        create_root=True,
        create_parent=True,
        label="exclusive output",
    )
    try:
        descriptor = os.open(safe.name, _write_new_flags(), 0o600, dir_fd=parent)
        try:
            view = memoryview(value)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SnapshotError("short write during exclusive publication")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)
        os.close(root_descriptor)
    return {"relativePath": str(safe), "bytes": len(value), "sha256": sha256_bytes(value)}


def _commitment(relative: PurePosixPath, value: bytes) -> dict[str, Any]:
    return {
        "relativePath": str(relative),
        "bytes": len(value),
        "sha256": sha256_bytes(value),
    }


def _lstat_or_none(path: Path) -> os.stat_result | None:
    absolute = _absolute_without_resolving(path)
    parent, _ = _open_directory_path(absolute.parent, label="filesystem entry parent")
    try:
        return _entry_metadata(parent, absolute.name)
    finally:
        os.close(parent)


def _unlink_uncommitted_regular(path: Path, *, label: str) -> None:
    absolute = _absolute_without_resolving(path)
    parent, _ = _open_directory_path(absolute.parent, label=f"{label} parent")
    try:
        metadata = _entry_metadata(parent, absolute.name)
        if metadata is None:
            return
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SnapshotError(f"{label} is a symlink or non-regular file")
        os.unlink(absolute.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _write_or_reuse_exact(root: Path, relative: str, value: bytes) -> dict[str, Any]:
    """Atomically publish exact bytes, or replay an identical existing file.

    A deterministic pending file is never evidence.  If the process dies before
    the hard-link publication, the next invocation discards that bounded regular
    pending file.  If it dies after publication, the exact final file is reused
    and the pending hard link is removed.  A mismatching committed file is never
    overwritten.
    """

    safe = _safe_relative_path(relative)
    expected = _commitment(safe, value)
    pending_name = f".{safe.name}.pending"
    root_descriptor, parent, _ = _open_root_and_parent(
        root,
        safe,
        create_root=True,
        create_parent=True,
        label="exact-file publication",
    )
    try:
        target_metadata = _entry_metadata(parent, safe.name)
        if target_metadata is not None:
            if not stat.S_ISREG(target_metadata.st_mode) or stat.S_ISLNK(
                target_metadata.st_mode
            ):
                raise SnapshotError("reusable committed path is a symlink/non-regular file")
            if _read_regular_at(parent, safe.name, label="reusable committed file") != value:
                raise SnapshotError("reusable committed file differs from exact bytes")
            pending_metadata = _entry_metadata(parent, pending_name)
            if pending_metadata is not None:
                if not stat.S_ISREG(pending_metadata.st_mode) or stat.S_ISLNK(
                    pending_metadata.st_mode
                ):
                    raise SnapshotError("pending exact-file publication is invalid")
                os.unlink(pending_name, dir_fd=parent)
                os.fsync(parent)
            return expected

        pending_metadata = _entry_metadata(parent, pending_name)
        if pending_metadata is not None:
            if not stat.S_ISREG(pending_metadata.st_mode) or stat.S_ISLNK(
                pending_metadata.st_mode
            ):
                raise SnapshotError("pending exact-file publication is invalid")
            os.unlink(pending_name, dir_fd=parent)
            os.fsync(parent)
        descriptor = os.open(pending_name, _write_new_flags(), 0o600, dir_fd=parent)
        try:
            view = memoryview(value)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SnapshotError("short write during exact-file publication")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                pending_name,
                safe.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _read_regular_at(parent, safe.name, label="concurrent committed file") != value:
                raise SnapshotError("concurrent committed file differs from exact bytes")
        os.fsync(parent)
        os.unlink(pending_name, dir_fd=parent)
        os.fsync(parent)
        return expected
    finally:
        os.close(parent)
        os.close(root_descriptor)


_RESPONSE_BUNDLE_FILES = {
    "requestURIFile": "request-uri.txt",
    "responseHeaders": "response-headers.bin",
    "responseBody": "response-body.bin",
}


def _open_bundle_at(parent: int, name: str, *, label: str) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except OSError as error:
        raise SnapshotError(f"{label} is a symlink/non-directory") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise SnapshotError(f"{label} is a symlink/non-directory")
    return descriptor


def _bundle_payloads_from_fd(
    descriptor: int,
    *,
    expected_uri: str,
    pending: bool,
) -> tuple[dict[str, bytes], ArchivedHTTPResponse]:
    allowed = set(_RESPONSE_BUNDLE_FILES.values())
    observed = set(os.listdir(descriptor))
    if not observed.issubset(allowed):
        kind = "pending" if pending else "committed"
        raise SnapshotError(f"{kind} response bundle contains an unexpected file")
    if observed != allowed:
        if pending:
            raise SnapshotError(
                "pending response bundle is incomplete; restart the prospective "
                "corpus under the registered reschedule rule"
            )
        raise SnapshotError("committed response bundle file inventory differs")
    payloads = {
        filename: _read_regular_at(
            descriptor,
            filename,
            label=("pending" if pending else "committed")
            + " response bundle member",
        )
        for filename in _RESPONSE_BUNDLE_FILES.values()
    }
    request = payloads["request-uri.txt"]
    if request != expected_uri.encode("ascii", errors="strict") + b"\n":
        kind = "complete pending" if pending else "committed"
        raise SnapshotError(f"{kind} response bundle request URI differs")
    headers = payloads["response-headers.bin"]
    status, _fields = _parse_header_block(headers)
    response = ArchivedHTTPResponse(
        expected_uri,
        status,
        headers,
        payloads["response-body.bin"],
    )
    _validate_response(response, expected_uri=expected_uri)
    return payloads, response


def _read_bundle_at(
    parent: int,
    name: str,
    *,
    expected_uri: str,
    pending: bool,
) -> tuple[dict[str, bytes], ArchivedHTTPResponse]:
    descriptor = _open_bundle_at(
        parent,
        name,
        label=("pending" if pending else "committed") + " response bundle",
    )
    try:
        return _bundle_payloads_from_fd(
            descriptor,
            expected_uri=expected_uri,
            pending=pending,
        )
    finally:
        os.close(descriptor)


def _discard_bundle_at(parent: int, name: str) -> None:
    metadata = _entry_metadata(parent, name)
    if metadata is None:
        return
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SnapshotError("pending response bundle is a symlink/non-directory")
    descriptor = _open_bundle_at(parent, name, label="pending response bundle")
    try:
        if (metadata.st_dev, metadata.st_ino) != (
            os.fstat(descriptor).st_dev,
            os.fstat(descriptor).st_ino,
        ):
            raise SnapshotError("pending response bundle changed before cleanup")
        allowed = set(_RESPONSE_BUNDLE_FILES.values())
        children = set(os.listdir(descriptor))
        if not children.issubset(allowed):
            raise SnapshotError("pending response bundle contains an unexpected file")
        for child in children:
            child_metadata = _entry_metadata(descriptor, child)
            if child_metadata is None or not stat.S_ISREG(child_metadata.st_mode):
                raise SnapshotError(
                    "pending response bundle contains a symlink/special file"
                )
            os.unlink(child, dir_fd=descriptor)
        os.fsync(descriptor)
        current = _entry_metadata(parent, name)
        if current is None or (current.st_dev, current.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise SnapshotError("pending response bundle changed before cleanup")
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(descriptor)


def _discard_uncommitted_response_bundle(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    parent, _ = _open_directory_path(
        absolute.parent,
        label="pending response bundle parent",
    )
    try:
        _discard_bundle_at(parent, absolute.name)
    finally:
        os.close(parent)


def _link_or_copy_bundle_member(
    pending: int,
    target: int,
    filename: str,
    expected: bytes,
) -> None:
    metadata = _entry_metadata(pending, filename)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        raise SnapshotError("pending response bundle member is not regular")
    try:
        os.link(
            filename,
            filename,
            src_dir_fd=pending,
            dst_dir_fd=target,
            follow_symlinks=False,
        )
    except OSError as error:
        fallback_errors = {
            errno.EXDEV,
            errno.EPERM,
            getattr(errno, "EOPNOTSUPP", errno.EPERM),
            getattr(errno, "ENOTSUP", errno.EPERM),
        }
        if error.errno not in fallback_errors:
            raise SnapshotError("cannot exclusively link response bundle member") from error
        descriptor = os.open(filename, _write_new_flags(), 0o600, dir_fd=target)
        try:
            view = memoryview(expected)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SnapshotError("short copy during response-bundle publication")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if _read_regular_at(target, filename, label="new response bundle member") != expected:
        raise SnapshotError("new response bundle member differs after publication")


def _promote_bundle_at(
    parent: int,
    pending_name: str,
    target_name: str,
    *,
    expected_uri: str,
) -> bool:
    pending_metadata = _entry_metadata(parent, pending_name)
    if pending_metadata is None:
        return False
    pending_descriptor = _open_bundle_at(
        parent,
        pending_name,
        label="pending response bundle",
    )
    try:
        pending_payloads, pending_response = _bundle_payloads_from_fd(
            pending_descriptor,
            expected_uri=expected_uri,
            pending=True,
        )
        try:
            os.mkdir(target_name, 0o700, dir_fd=parent)
        except FileExistsError:
            committed_payloads, committed_response = _read_bundle_at(
                parent,
                target_name,
                expected_uri=expected_uri,
                pending=False,
            )
            if (
                committed_payloads != pending_payloads
                or committed_response != pending_response
            ):
                raise SnapshotError(
                    "concurrent response bundle differs from pending bytes"
                )
            _discard_bundle_at(parent, pending_name)
            return True
        os.fsync(parent)
        target_metadata = _entry_metadata(parent, target_name)
        target_descriptor = _open_bundle_at(
            parent,
            target_name,
            label="new response bundle",
        )
        try:
            opened = os.fstat(target_descriptor)
            if target_metadata is None or (
                target_metadata.st_dev,
                target_metadata.st_ino,
            ) != (opened.st_dev, opened.st_ino):
                raise SnapshotError("new response bundle target changed concurrently")
            for filename in _RESPONSE_BUNDLE_FILES.values():
                _link_or_copy_bundle_member(
                    pending_descriptor,
                    target_descriptor,
                    filename,
                    pending_payloads[filename],
                )
            os.fsync(target_descriptor)
            os.fsync(parent)
            committed_payloads, committed_response = _bundle_payloads_from_fd(
                target_descriptor,
                expected_uri=expected_uri,
                pending=False,
            )
            if (
                committed_payloads != pending_payloads
                or committed_response != pending_response
            ):
                raise SnapshotError("new response bundle failed exact replay")
            current = _entry_metadata(parent, target_name)
            if current is None or (current.st_dev, current.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise SnapshotError("new response bundle target changed concurrently")
        finally:
            os.close(target_descriptor)
        # A crash before this point leaves an incomplete final directory whose
        # inventory cannot pass replay.  The exact pending bundle remains as
        # forensic evidence.  Once the final replay succeeds, only an identical
        # pending directory may be removed.
        replay_payloads, replay_response = _bundle_payloads_from_fd(
            pending_descriptor,
            expected_uri=expected_uri,
            pending=True,
        )
        if replay_payloads != pending_payloads or replay_response != pending_response:
            raise SnapshotError("pending response bundle changed during publication")
    finally:
        os.close(pending_descriptor)
    _discard_bundle_at(parent, pending_name)
    return True


def _promote_complete_pending_response_bundle(
    pending: Path,
    target: Path,
    *,
    expected_uri: str,
) -> bool:
    pending_absolute = _absolute_without_resolving(pending)
    target_absolute = _absolute_without_resolving(target)
    if pending_absolute.parent != target_absolute.parent:
        raise SnapshotError("response bundle pending/final parents differ")
    parent, _ = _open_directory_path(
        pending_absolute.parent,
        label="response bundle parent",
    )
    try:
        return _promote_bundle_at(
            parent,
            pending_absolute.name,
            target_absolute.name,
            expected_uri=expected_uri,
        )
    finally:
        os.close(parent)


def _existing_file_commitment(root: Path, relative: PurePosixPath) -> dict[str, Any]:
    value = _read_relative_regular(
        root,
        relative,
        label="response bundle member",
    )
    return _commitment(relative, value)


def _load_existing_response_bundle(
    root: Path,
    prefix: str,
    *,
    expected_uri: str,
) -> tuple[dict[str, Any], ArchivedHTTPResponse] | None:
    safe = _safe_relative_path(prefix)
    pending_name = f".{safe.name}.partial"
    root_descriptor, parent, _ = _open_root_and_parent(
        root,
        safe,
        create_root=True,
        create_parent=True,
        label="response bundle",
    )
    try:
        target_metadata = _entry_metadata(parent, safe.name)
        if target_metadata is None:
            if not _promote_bundle_at(
                parent,
                pending_name,
                safe.name,
                expected_uri=expected_uri,
            ):
                return None
        payloads, response = _read_bundle_at(
            parent,
            safe.name,
            expected_uri=expected_uri,
            pending=False,
        )
        if _entry_metadata(parent, pending_name) is not None:
            pending_payloads, pending_response = _read_bundle_at(
                parent,
                pending_name,
                expected_uri=expected_uri,
                pending=True,
            )
            if pending_payloads != payloads or pending_response != response:
                raise SnapshotError(
                    "committed response bundle has a differing pending publication"
                )
            _discard_bundle_at(parent, pending_name)
        commitments = {
            role: _commitment(safe / filename, payloads[filename])
            for role, filename in _RESPONSE_BUNDLE_FILES.items()
        }
        archive = {
            "requestURI": expected_uri,
            "serverDate": response_date(response).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **commitments,
        }
        return archive, response
    finally:
        os.close(parent)
        os.close(root_descriptor)


def _publish_response_bundle(
    root: Path,
    prefix: str,
    response: ArchivedHTTPResponse,
) -> tuple[dict[str, Any], ArchivedHTTPResponse]:
    _validate_response(response, expected_uri=response.request_uri)
    safe = _safe_relative_path(prefix)
    pending_name = f".{safe.name}.partial"
    root_descriptor, parent, _ = _open_root_and_parent(
        root,
        safe,
        create_root=True,
        create_parent=True,
        label="response bundle publication",
    )
    payloads = {
        "request-uri.txt": response.request_uri.encode("ascii") + b"\n",
        "response-headers.bin": response.header_bytes,
        "response-body.bin": response.body,
    }
    try:
        if _entry_metadata(parent, safe.name) is not None:
            os.close(parent)
            os.close(root_descriptor)
            parent = root_descriptor = -1
            existing = _load_existing_response_bundle(
                root,
                prefix,
                expected_uri=response.request_uri,
            )
            if existing is None or existing[1] != response:
                raise SnapshotError("concurrent response bundle differs from fetched bytes")
            return existing
        if _entry_metadata(parent, pending_name) is not None:
            raise SnapshotError("response bundle pending path already exists")
        try:
            os.mkdir(pending_name, 0o700, dir_fd=parent)
        except FileExistsError as error:
            raise SnapshotError("response bundle pending path appeared concurrently") from error
        os.fsync(parent)
        pending_descriptor = _open_bundle_at(
            parent,
            pending_name,
            label="new pending response bundle",
        )
        for filename, value in payloads.items():
            descriptor = os.open(
                filename,
                _write_new_flags(),
                0o600,
                dir_fd=pending_descriptor,
            )
            try:
                view = memoryview(value)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SnapshotError("short write during response-bundle publication")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(pending_descriptor)
        os.close(pending_descriptor)
        pending_descriptor = -1
        os.fsync(parent)
        _promote_bundle_at(
            parent,
            pending_name,
            safe.name,
            expected_uri=response.request_uri,
        )
    except Exception:
        # Keep a bounded, visibly uncommitted directory for deterministic cleanup
        # by the next invocation.  It is never treated as evidence.
        raise
    finally:
        if "pending_descriptor" in locals() and pending_descriptor >= 0:
            os.close(pending_descriptor)
        if parent >= 0:
            os.close(parent)
        if root_descriptor >= 0:
            os.close(root_descriptor)
    existing = _load_existing_response_bundle(
        root, prefix, expected_uri=response.request_uri
    )
    if existing is None or existing[1] != response:
        raise SnapshotError("published response bundle did not replay exactly")
    return existing


def _read_committed(root: Path, commitment: Mapping[str, Any]) -> bytes:
    if set(commitment) != {"relativePath", "bytes", "sha256"}:
        raise SnapshotError("file commitment fields differ")
    safe = _safe_relative_path(commitment["relativePath"])
    value = _read_relative_regular(root, safe, label="committed file")
    if type(commitment["bytes"]) is not int or commitment["bytes"] != len(value):
        raise SnapshotError("committed file byte count differs")
    if commitment["sha256"] != sha256_bytes(value):
        raise SnapshotError("committed file SHA-256 differs")
    return value


def archive_response(root: Path, prefix: str, response: ArchivedHTTPResponse) -> dict[str, Any]:
    _validate_response(response, expected_uri=response.request_uri)
    return {
        "requestURI": response.request_uri,
        "serverDate": response_date(response).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requestURIFile": _write_exclusive(
            root, f"{prefix}/request-uri.txt", response.request_uri.encode("ascii") + b"\n"
        ),
        "responseHeaders": _write_exclusive(
            root, f"{prefix}/response-headers.bin", response.header_bytes
        ),
        "responseBody": _write_exclusive(root, f"{prefix}/response-body.bin", response.body),
    }


def _parse_recentchanges(response_body: bytes) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
    value = load_json_strict_bytes(response_body, label="MediaWiki RecentChanges")
    if not isinstance(value, dict) or "error" in value or "warnings" in value:
        raise SnapshotError("MediaWiki RecentChanges returned an error/warning")
    if not set(value).issubset({"batchcomplete", "continue", "query"}) or "query" not in value:
        raise SnapshotError("MediaWiki RecentChanges top-level fields differ")
    query = value["query"]
    if not isinstance(query, dict) or set(query) != {"recentchanges"}:
        raise SnapshotError("MediaWiki RecentChanges query fields differ")
    records = query["recentchanges"]
    if not isinstance(records, list):
        raise SnapshotError("MediaWiki RecentChanges list is invalid")
    parsed: list[dict[str, Any]] = []
    for record in records:
        base_fields = (
            "type", "ns", "title", "pageid", "revid", "old_revid", "rcid",
            "timestamp", "redirect",
        )
        if not isinstance(record, dict) or any(field not in record for field in base_fields):
            raise SnapshotError("RecentChanges record fields are incomplete")
        if record["type"] != "new" or record["ns"] != 0 or record["old_revid"] != 0:
            raise SnapshotError("RecentChanges record is not a namespace-0 creation")
        if record["redirect"] is not False or record.get("bot") is True:
            raise SnapshotError("RecentChanges record is redirect/bot flagged")
        for field in ("pageid", "revid", "rcid"):
            if _u64(record[field], label=field) == 0:
                raise SnapshotError(f"RecentChanges {field} must be positive")
        _strict_utf8(record["title"], label="title")
        timestamp = _utc_seconds(record["timestamp"], label="timestamp")
        if not (CORPUS_START <= timestamp < CORPUS_END):
            raise SnapshotError("RecentChanges record is outside the registered interval")
        user_hidden = record.get("userhidden") is True
        sha1_hidden = record.get("sha1hidden") is True
        if "userhidden" in record and not user_hidden:
            raise SnapshotError("RecentChanges userhidden flag is invalid")
        if "sha1hidden" in record and not sha1_hidden:
            raise SnapshotError("RecentChanges sha1hidden flag is invalid")
        if not user_hidden:
            if "user" not in record or "userid" not in record:
                raise SnapshotError("RecentChanges visible user fields are incomplete")
            _strict_utf8(record["user"], label="user")
            _u64(record["userid"], label="userid")
        if not sha1_hidden:
            if "sha1" not in record or not isinstance(record["sha1"], str) or HEX_SHA1.fullmatch(record["sha1"]) is None:
                raise SnapshotError("RecentChanges visible SHA-1 is invalid")
        normalized = {field: record[field] for field in base_fields}
        for optional in ("user", "userid", "sha1", "userhidden", "sha1hidden"):
            if optional in record:
                normalized[optional] = record[optional]
        parsed.append(normalized)
    continuation = value.get("continue")
    if continuation is not None:
        if not isinstance(continuation, dict) or set(continuation) != {"continue", "rccontinue"}:
            raise SnapshotError("RecentChanges continuation fields differ")
        if any(not isinstance(item, str) or not item for item in continuation.values()):
            raise SnapshotError("RecentChanges continuation value is empty")
        continuation = dict(continuation)
    return parsed, continuation


def collect_recentchanges_crawl(
    *,
    project: str,
    crawl_index: int,
    root: Path,
    transport: Transport,
    clock: Callable[[], datetime],
) -> dict[str, Any]:
    if project not in PROJECTS or crawl_index not in (0, 1):
        raise SnapshotError("crawl identity differs from the registered design")
    not_before = CRAWL_NOT_BEFORE[crawl_index]
    now = clock()
    if now.tzinfo is None or now.astimezone(timezone.utc) < not_before:
        raise SnapshotError("crawl began before its registered not-before time")
    continuation: dict[str, str] | None = None
    seen_continuations: set[tuple[str, str]] = set()
    seen_revisions: set[int] = set()
    records: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    for page_index in range(MAX_CRAWL_PAGES):
        uri = recentchanges_uri(project, continuation)
        response = transport(uri)
        _validate_response(response, expected_uri=uri)
        if response_date(response) < not_before:
            raise SnapshotError("HTTP Date precedes the crawl not-before time")
        archive = archive_response(
            root,
            f"archive/crawl-{crawl_index + 1}/{project}/page-{page_index:06d}",
            response,
        )
        page_records, next_continuation = _parse_recentchanges(response.body)
        for record in page_records:
            if record["revid"] in seen_revisions:
                raise SnapshotError("one crawl returned a duplicate revision")
            seen_revisions.add(record["revid"])
            records.append(record)
        pages.append({**archive, "records": len(page_records)})
        if next_continuation is None:
            break
        key = (next_continuation["continue"], next_continuation["rccontinue"])
        if key in seen_continuations:
            raise SnapshotError("RecentChanges continuation cycle detected")
        seen_continuations.add(key)
        continuation = next_continuation
    else:
        raise SnapshotError("RecentChanges exceeded the fixed page bound")
    return {
        "crawlIndex": crawl_index + 1,
        "project": project,
        "notBefore": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pages": pages,
        "records": records,
    }


def union_crawls(first: Mapping[str, Any], second: Mapping[str, Any]) -> list[dict[str, Any]]:
    if first.get("project") != second.get("project") or first.get("crawlIndex") != 1 or second.get("crawlIndex") != 2:
        raise SnapshotError("two crawl identities differ")
    by_revision: dict[int, dict[str, Any]] = {}
    for crawl in (first, second):
        records = crawl.get("records")
        if not isinstance(records, list):
            raise SnapshotError("crawl record list is invalid")
        for record in records:
            revid = record.get("revid") if isinstance(record, dict) else None
            if type(revid) is not int:
                raise SnapshotError("crawl record revid is invalid")
            existing = by_revision.get(revid)
            if existing is not None and existing != record:
                raise SnapshotError("the two crawls disagree about one revision")
            by_revision[revid] = dict(record)
    result = sorted(by_revision.values(), key=lambda item: (item["timestamp"], item["revid"]))
    if len({item["pageid"] for item in result}) != len(result):
        raise SnapshotError("union contains multiple creation revisions for one page")
    return result


def _parse_revision(response_body: bytes, expected: Mapping[str, Any]) -> dict[str, Any]:
    value = load_json_strict_bytes(response_body, label="MediaWiki Revisions")
    if not isinstance(value, dict) or "error" in value or "warnings" in value:
        raise SnapshotError("MediaWiki Revisions returned an error/warning")
    if not set(value).issubset({"batchcomplete", "query"}) or "query" not in value:
        raise SnapshotError("MediaWiki Revisions top-level fields differ")
    query = value["query"]
    if isinstance(query, dict) and set(query) == {"badrevids"}:
        bad = query["badrevids"]
        key = str(expected["revid"])
        if (
            not isinstance(bad, dict)
            or set(bad) != {key}
            or not isinstance(bad[key], dict)
            or bad[key].get("revid") != expected["revid"]
            or bad[key].get("missing") is not True
        ):
            raise SnapshotError("MediaWiki badrevids response differs from requested revid")
        raise RevisionIneligible("revision-unavailable-or-deleted")
    pages = query.get("pages") if isinstance(query, dict) else None
    if not isinstance(pages, list) or len(pages) != 1:
        raise SnapshotError("MediaWiki Revisions must return exactly one page")
    page = pages[0]
    if not isinstance(page, dict) or any(field not in page for field in ("pageid", "ns", "title", "revisions")):
        raise SnapshotError("MediaWiki revision page fields are incomplete")
    revisions = page["revisions"]
    if not isinstance(revisions, list) or len(revisions) != 1 or not isinstance(revisions[0], dict):
        raise SnapshotError("MediaWiki Revisions must return exactly one revision")
    revision = revisions[0]
    required = {"revid", "parentid", "timestamp", "slots"}
    if not required.issubset(revision):
        raise SnapshotError("MediaWiki revision fields are incomplete")
    comparisons = {
        "pageid": (page["pageid"], expected["pageid"]),
        "revid": (revision["revid"], expected["revid"]),
        "timestamp": (revision["timestamp"], expected["timestamp"]),
    }
    if page["ns"] != 0 or revision["parentid"] != 0:
        raise SnapshotError("revision is not a namespace-0 creation revision")
    for field, (observed, registered) in comparisons.items():
        if observed != registered:
            raise SnapshotError(f"revision identity differs from RecentChanges: {field}")
    creation_title = expected["title"]
    creation_title_bytes = _strict_utf8(
        creation_title, label="RecentChanges creation title"
    )
    current_title = page["title"]
    _strict_utf8(current_title, label="revision API current title")
    ineligible_reasons: list[str] = []
    for hidden, reason in (
        ("texthidden", "revision-content-hidden"),
        ("suppressed", "revision-content-suppressed"),
    ):
        if hidden in revision:
            if revision[hidden] is not True:
                raise SnapshotError(f"revision {hidden} flag is invalid")
            ineligible_reasons.append(reason)
    if revision.get("userhidden") is True:
        ineligible_reasons.append("revision-user-hidden")
    elif "user" not in revision or "userid" not in revision:
        raise SnapshotError("visible revision user fields are incomplete")
    else:
        _strict_utf8(revision["user"], label="revision username")
        _u64(revision["userid"], label="revision userid")
        if "user" in expected and revision["user"] != expected["user"]:
            raise SnapshotError("revision identity differs from RecentChanges: user")
        if "userid" in expected and revision["userid"] != expected["userid"]:
            raise SnapshotError("revision identity differs from RecentChanges: userid")
    if "userhidden" in revision and revision.get("userhidden") is not True:
        raise SnapshotError("revision userhidden flag is invalid")
    if revision.get("sha1hidden") is True:
        ineligible_reasons.append("revision-sha1-hidden")
    elif "sha1" not in revision:
        raise SnapshotError("visible revision SHA-1 is incomplete")
    else:
        if not isinstance(revision["sha1"], str) or HEX_SHA1.fullmatch(revision["sha1"]) is None:
            raise SnapshotError("visible revision SHA-1 is invalid")
        if "sha1" in expected and revision["sha1"] != expected["sha1"]:
            raise SnapshotError("revision identity differs from RecentChanges: sha1")
    if "sha1hidden" in revision and revision.get("sha1hidden") is not True:
        raise SnapshotError("revision sha1hidden flag is invalid")
    slots = revision["slots"]
    if not isinstance(slots, dict) or set(slots) != {"main"} or not isinstance(slots["main"], dict):
        raise SnapshotError("revision main slot fields differ")
    main = slots["main"]
    for hidden, reason in (
        ("texthidden", "revision-content-hidden"),
        ("sha1hidden", "revision-slot-sha1-hidden"),
        ("suppressed", "revision-content-suppressed"),
    ):
        if hidden in main:
            if main[hidden] is not True:
                raise SnapshotError(f"revision main-slot {hidden} flag is invalid")
            ineligible_reasons.append(reason)
    if ineligible_reasons:
        raise RevisionIneligible(
            *dict.fromkeys(ineligible_reasons),
            revision_api_current_title=current_title,
        )
    for field in ("sha1", "contentmodel", "content"):
        if field not in main:
            raise SnapshotError("visible revision main slot is incomplete")
    if main["contentmodel"] != "wikitext":
        raise RevisionIneligible(
            "revision-content-model-not-wikitext",
            revision_api_current_title=current_title,
        )
    if not isinstance(main["content"], str) or not main["content"]:
        raise RevisionIneligible(
            "revision-content-empty",
            revision_api_current_title=current_title,
        )
    content_bytes = _strict_utf8(main["content"], label="revision content")
    if hashlib.sha1(content_bytes).hexdigest() != main["sha1"] or main["sha1"] != revision["sha1"]:
        raise SnapshotError("revision API/content SHA-1 mismatch")
    _utc_seconds(revision["timestamp"], label="revision timestamp")
    return {
        "project": expected["project"],
        "pageid": page["pageid"],
        "revid": revision["revid"],
        "userid": revision["userid"],
        "timestamp": revision["timestamp"],
        "username": revision["user"],
        "title": creation_title,
        "revisionAPICurrentTitle": current_title,
        "content": main["content"],
        "mediaWikiSHA1": revision["sha1"],
        "titleBytes": len(creation_title_bytes),
        "contentBytes": len(content_bytes),
    }


def _license(project: str) -> dict[str, str]:
    return {
        "spdxLike": "CC-BY-SA-4.0",
        "licenseURL": "https://creativecommons.org/licenses/by-sa/4.0/",
        "projectTermsURL": "https://foundation.wikimedia.org/wiki/Policy:Terms_of_Use",
        "project": project,
    }


def _source_ineligibility_reasons(change: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    if change.get("userhidden") is True:
        reasons.append("recentchanges-user-hidden")
    if change.get("sha1hidden") is True:
        reasons.append("recentchanges-sha1-hidden")
    return reasons


def _excluded_inventory(
    *,
    project: str,
    change: Mapping[str, Any],
    archive: Mapping[str, Any],
    reasons: Sequence[str],
    revision_api_current_title: str | None = None,
) -> dict[str, Any]:
    unique_reasons = list(dict.fromkeys(reasons))
    if not unique_reasons:
        raise SnapshotError("excluded revision has no ineligibility reason")
    result = {
        "project": project,
        "pageid": change["pageid"],
        "revid": change["revid"],
        "timestamp": change["timestamp"],
        "title": change["title"],
        "recentChanges": dict(change),
        "revisionArchive": dict(archive),
        "exclusionStage": "source-eligibility",
        "eligible": False,
        "ineligibilityReasons": unique_reasons,
    }
    if revision_api_current_title is not None:
        _strict_utf8(
            revision_api_current_title,
            label="revision API current title",
        )
        result["revisionAPICurrentTitle"] = revision_api_current_title
    return result


def fetch_and_inventory_revision(
    *,
    project: str,
    change: Mapping[str, Any],
    root: Path,
    transport: Transport,
    tokenizers: Mapping[str, TokenizerLike],
) -> dict[str, Any]:
    if tuple(tokenizers) != MODEL_KEYS:
        raise SnapshotError("tokenizer order/set differs from the registered models")
    uri = revision_uri(project, change["revid"])
    prefix = f"archive/revisions/{project}/{change['revid']}"
    existing = _load_existing_response_bundle(root, prefix, expected_uri=uri)
    if existing is None:
        fetched = transport(uri)
        _validate_response(fetched, expected_uri=uri)
        archive, response = _publish_response_bundle(root, prefix, fetched)
    else:
        archive, response = existing
    reasons = _source_ineligibility_reasons(change)
    try:
        revision = _parse_revision(response.body, {**change, "project": project})
    except RevisionIneligible as error:
        reasons.extend(error.reasons)
        return _excluded_inventory(
            project=project,
            change=change,
            archive=archive,
            reasons=reasons,
            revision_api_current_title=error.revision_api_current_title,
        )
    if reasons:
        return _excluded_inventory(
            project=project,
            change=change,
            archive=archive,
            reasons=reasons,
            revision_api_current_title=revision["revisionAPICurrentTitle"],
        )
    input_text = revision["title"] + "\n\n" + revision["content"]
    input_bytes = input_text.encode("utf-8", errors="strict")
    commitments = {
        key: token_commitment(tokenizer, input_text)
        for key, tokenizer in tokenizers.items()
    }
    eligible = all(item["tokenCount"] >= 512 for item in commitments.values())
    common = {
        "project": project,
        "pageid": revision["pageid"],
        "revid": revision["revid"],
        "userid": revision["userid"],
        "timestamp": revision["timestamp"],
        "username": revision["username"],
        "title": revision["title"],
        "revisionAPICurrentTitle": revision["revisionAPICurrentTitle"],
        "mediaWikiSHA1": revision["mediaWikiSHA1"],
        "titleSHA256": sha256_bytes(revision["title"].encode("utf-8")),
        "contentSHA256": sha256_bytes(revision["content"].encode("utf-8")),
        "inputSHA256": sha256_bytes(input_bytes),
        "tokenizers": commitments,
        "revisionURL": f"https://{project}/w/index.php?oldid={revision['revid']}",
        "historyURL": (
            f"https://{project}/w/index.php?curid={revision['pageid']}"
            "&action=history"
        ),
        "attribution": {
            "username": revision["username"],
            "userid": revision["userid"],
            **_license(project),
        },
        "revisionArchive": archive,
        "eligible": eligible,
        "ineligibilityReasons": [] if eligible else ["fewer-than-512-tokens-under-at-least-one-tokenizer"],
    }
    if not eligible:
        return common
    record_bytes = serialize_record(
        project=project,
        pageid=revision["pageid"],
        revid=revision["revid"],
        userid=revision["userid"],
        timestamp=revision["timestamp"],
        username=revision["username"],
        title=revision["title"],
        content=revision["content"],
    )
    commitment = _write_or_reuse_exact(
        root, f"records/{project}/{revision['revid']}.bin", record_bytes
    )
    return {**common, "record": commitment}


def _ledger_record(inventory: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: inventory[key]
        for key in (
            "project", "timestamp", "pageid", "revid", "userid", "username", "title",
            "mediaWikiSHA1", "titleSHA256", "contentSHA256", "inputSHA256",
            "revisionURL", "historyURL", "attribution", "tokenizers", "record",
        )
    }


def _crawl_manifest_view(crawl: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: crawl[key] for key in ("crawlIndex", "project", "notBefore", "pages")
    }


def _require_stage_layout(root: Path, completed_crawls: int) -> Path:
    if completed_crawls not in (0, 1, 2):
        raise SnapshotError("completed crawl count is invalid")
    root_descriptor, absolute = _open_directory_path(root, label="snapshot root")
    expected_top = {"archive"} | {
        f"crawl-{index}-manifest.json" for index in range(1, completed_crawls + 1)
    }
    try:
        top = _stable_directory_entries(root_descriptor, label="snapshot stage")
        if set(top) != expected_top:
            raise SnapshotError("snapshot stage contains unexpected/missing top-level files")
        _require_directory_entry(
            root_descriptor,
            "archive",
            label="snapshot archive directory",
        )
        for index in range(1, completed_crawls + 1):
            _require_regular_entry(
                root_descriptor,
                f"crawl-{index}-manifest.json",
                label="crawl stage manifest",
            )
        archive = _open_relative_directory(
            root_descriptor,
            PurePosixPath("archive"),
            label="snapshot archive",
        )
        try:
            archive_entries = _stable_directory_entries(
                archive,
                label="snapshot archive",
            )
            expected_archive = {
                f"crawl-{index}" for index in range(1, completed_crawls + 1)
            }
            if set(archive_entries) != expected_archive:
                raise SnapshotError(
                    "snapshot stage contains unexpected/missing crawl archives"
                )
            if any(
                not stat.S_ISDIR(metadata.st_mode)
                for metadata in archive_entries.values()
            ):
                raise SnapshotError("snapshot crawl archive is not a real directory")
        finally:
            os.close(archive)
    finally:
        os.close(root_descriptor)
    return absolute


def _require_real_directory(path: Path, *, label: str) -> None:
    descriptor, _ = _open_directory_path(path, label=label)
    os.close(descriptor)


def _require_real_regular(path: Path, *, label: str) -> None:
    absolute = _absolute_without_resolving(path)
    parent, _ = _open_directory_path(absolute.parent, label=f"{label} parent")
    try:
        _require_regular_entry(parent, absolute.name, label=label)
    finally:
        os.close(parent)


def _require_finalize_layout(root: Path) -> Path:
    """Accept only the two crawls plus a bounded, resumable finalize contour."""

    root_descriptor, absolute = _open_directory_path(root, label="snapshot root")
    required = {
        "archive",
        "crawl-1-manifest.json",
        "crawl-2-manifest.json",
    }
    optional = {
        "records",
        "ledgers",
        "corpus-manifest.json",
        ".corpus-manifest.json.pending",
    }
    try:
        top = _stable_directory_entries(root_descriptor, label="snapshot finalize root")
        observed = set(top)
        if not required.issubset(observed) or not observed.issubset(required | optional):
            raise SnapshotError(
                "snapshot finalize layout contains unexpected/missing top-level files"
            )
        _require_directory_entry(root_descriptor, "archive", label="snapshot archive")
        for name in ("crawl-1-manifest.json", "crawl-2-manifest.json"):
            _require_regular_entry(root_descriptor, name, label="crawl stage manifest")
        for name in ("records", "ledgers"):
            if name in top:
                _require_directory_entry(root_descriptor, name, label=f"snapshot {name}")
        for name in ("corpus-manifest.json", ".corpus-manifest.json.pending"):
            if name in top:
                _require_regular_entry(root_descriptor, name, label=name)
        archive = _open_relative_directory(
            root_descriptor,
            PurePosixPath("archive"),
            label="snapshot archive",
        )
        try:
            archive_entries = _stable_directory_entries(
                archive,
                label="snapshot finalize archive",
            )
            archive_names = set(archive_entries)
            if not {"crawl-1", "crawl-2"}.issubset(
                archive_names
            ) or not archive_names.issubset({"crawl-1", "crawl-2", "revisions"}):
                raise SnapshotError("snapshot finalize archive layout differs")
            if any(
                not stat.S_ISDIR(metadata.st_mode)
                for metadata in archive_entries.values()
            ):
                raise SnapshotError("snapshot finalize archive contains a non-directory")
        finally:
            os.close(archive)
    finally:
        os.close(root_descriptor)
    return absolute


def _validate_partial_finalize_entries(
    root: Path,
    unions: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    expected = {
        project: {int(item["revid"]) for item in unions[project]}
        for project in PROJECTS
    }
    root_descriptor, _ = _open_directory_path(root, label="snapshot root")
    try:
        revision_root = _open_optional_relative_directory(
            root_descriptor,
            PurePosixPath("archive/revisions"),
            label="revision archive root",
        )
        if revision_root is not None:
            try:
                revision_projects = _stable_directory_entries(
                    revision_root,
                    label="revision archive root",
                )
                for project, metadata in revision_projects.items():
                    if project not in PROJECTS:
                        raise SnapshotError(
                            "revision archive contains an unexpected project"
                        )
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise SnapshotError("revision archive project is not a directory")
                    project_descriptor = _open_relative_directory(
                        revision_root,
                        PurePosixPath(project),
                        label="revision archive project",
                    )
                    try:
                        entries = _stable_directory_entries(
                            project_descriptor,
                            label="revision archive project",
                        )
                        allowed = {
                            name
                            for revid in expected[project]
                            for name in (str(revid), f".{revid}.partial")
                        }
                        if not set(entries).issubset(allowed):
                            raise SnapshotError(
                                "revision archive contains an unexpected revision"
                            )
                        if any(
                            not stat.S_ISDIR(value.st_mode)
                            for value in entries.values()
                        ):
                            raise SnapshotError(
                                "revision response bundle is not a directory"
                            )
                    finally:
                        os.close(project_descriptor)
            finally:
                os.close(revision_root)

        record_root = _open_optional_relative_directory(
            root_descriptor,
            PurePosixPath("records"),
            label="record root",
        )
        if record_root is not None:
            try:
                record_projects = _stable_directory_entries(
                    record_root,
                    label="record root",
                )
                for project, metadata in record_projects.items():
                    if project not in PROJECTS:
                        raise SnapshotError("record root contains an unexpected project")
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise SnapshotError("record project is not a directory")
                    project_descriptor = _open_relative_directory(
                        record_root,
                        PurePosixPath(project),
                        label="record project",
                    )
                    try:
                        entries = _stable_directory_entries(
                            project_descriptor,
                            label="record project",
                        )
                        allowed = {
                            name
                            for revid in expected[project]
                            for name in (f"{revid}.bin", f".{revid}.bin.pending")
                        }
                        if not set(entries).issubset(allowed):
                            raise SnapshotError(
                                "record root contains an unexpected revision"
                            )
                        if any(
                            not stat.S_ISREG(value.st_mode)
                            for value in entries.values()
                        ):
                            raise SnapshotError("record or pending record is not regular")
                    finally:
                        os.close(project_descriptor)
            finally:
                os.close(record_root)

        ledger_root = _open_optional_relative_directory(
            root_descriptor,
            PurePosixPath("ledgers"),
            label="ledger root",
        )
        if ledger_root is not None:
            try:
                entries = _stable_directory_entries(
                    ledger_root,
                    label="ledger root",
                )
                allowed = {
                    name
                    for project in PROJECTS
                    for name in (f"{project}.json", f".{project}.json.pending")
                }
                if not set(entries).issubset(allowed):
                    raise SnapshotError("ledger root contains an unexpected file")
                if any(
                    not stat.S_ISREG(value.st_mode) for value in entries.values()
                ):
                    raise SnapshotError("ledger or pending ledger is not regular")
            finally:
                os.close(ledger_root)
    finally:
        os.close(root_descriptor)


def _require_exact_tree_files(
    root: Path,
    subtree: PurePosixPath,
    expected_files: set[str],
) -> None:
    root_descriptor, _ = _open_directory_path(root, label="snapshot root")
    base = _open_optional_relative_directory(
        root_descriptor,
        subtree,
        label=f"finalized subtree {subtree}",
    )
    if base is None:
        os.close(root_descriptor)
        if expected_files:
            raise SnapshotError(f"finalized subtree is missing: {subtree}")
        return
    if not expected_files:
        os.close(base)
        os.close(root_descriptor)
        raise SnapshotError(f"unexpected empty finalized subtree: {subtree}")
    observed_files: set[str] = set()
    observed_directories = {"."}

    def inspect(directory: int, prefix: PurePosixPath) -> None:
        entries = _stable_directory_entries(
            directory,
            label=f"finalized subtree {subtree}",
        )
        for name, metadata in entries.items():
            relative = PurePosixPath(name) if str(prefix) == "." else prefix / name
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(str(relative))
                child = _open_relative_directory(
                    directory,
                    PurePosixPath(name),
                    label="finalized subtree directory",
                )
                try:
                    inspect(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(str(relative))
            else:
                raise SnapshotError("finalized subtree contains a symlink/special file")

    try:
        inspect(base, PurePosixPath("."))
    finally:
        os.close(base)
        os.close(root_descriptor)
    expected_directories = {"."}
    for value in expected_files:
        parent = PurePosixPath(value).parent
        while str(parent) != ".":
            expected_directories.add(str(parent))
            parent = parent.parent
    if observed_files != expected_files or observed_directories != expected_directories:
        raise SnapshotError(f"finalized subtree inventory differs: {subtree}")


def _require_complete_finalize_layout(
    root: Path,
    manifest: Mapping[str, Any],
) -> None:
    projects = manifest.get("projects")
    if not isinstance(projects, dict) or tuple(projects) != PROJECTS:
        raise SnapshotError("completed corpus project inventory differs")
    expected_top = {
        "archive",
        "crawl-1-manifest.json",
        "crawl-2-manifest.json",
        "ledgers",
        "corpus-manifest.json",
    }
    expected_revision_files: set[str] = set()
    expected_record_files: set[str] = set()
    for project in PROJECTS:
        entry = projects[project]
        inventory = entry.get("inventory") if isinstance(entry, dict) else None
        if not isinstance(inventory, list):
            raise SnapshotError("completed corpus inventory is invalid")
        for item in inventory:
            if not isinstance(item, dict) or type(item.get("revid")) is not int:
                raise SnapshotError("completed corpus revision identity is invalid")
            revid = item["revid"]
            for filename in _RESPONSE_BUNDLE_FILES.values():
                expected_revision_files.add(f"{project}/{revid}/{filename}")
            if item.get("eligible") is True:
                expected_record_files.add(f"{project}/{revid}.bin")
    if expected_record_files:
        expected_top.add("records")
    root_descriptor, _ = _open_directory_path(root, label="snapshot root")
    try:
        top = _stable_directory_entries(
            root_descriptor,
            label="completed corpus root",
        )
        if set(top) != expected_top:
            raise SnapshotError("completed corpus top-level inventory differs")
        archive = _open_relative_directory(
            root_descriptor,
            PurePosixPath("archive"),
            label="completed corpus archive",
        )
        try:
            archive_names = set(
                _stable_directory_entries(
                    archive,
                    label="completed corpus archive",
                )
            )
        finally:
            os.close(archive)
    finally:
        os.close(root_descriptor)
    expected_archive_names = {"crawl-1", "crawl-2"}
    if expected_revision_files:
        expected_archive_names.add("revisions")
    if archive_names != expected_archive_names:
        raise SnapshotError("completed corpus archive inventory differs")
    _require_exact_tree_files(
        root,
        PurePosixPath("archive/revisions"),
        expected_revision_files,
    )
    _require_exact_tree_files(
        root,
        PurePosixPath("records"),
        expected_record_files,
    )
    _require_exact_tree_files(
        root,
        PurePosixPath("ledgers"),
        {f"{project}.json" for project in PROJECTS},
    )


def _require_exact_crawl_archive_layout(
    root: Path,
    staged: Sequence[Mapping[str, Mapping[str, Any]]],
) -> None:
    if len(staged) != 2:
        raise SnapshotError("exactly two replayed crawl stages are required")
    for crawl_index, projects in enumerate(staged, start=1):
        expected: set[str] = set()
        for project in PROJECTS:
            crawl = projects[project]
            pages = crawl.get("pages") if isinstance(crawl, Mapping) else None
            if not isinstance(pages, list):
                raise SnapshotError("replayed crawl page inventory is invalid")
            for page in pages:
                if not isinstance(page, dict):
                    raise SnapshotError("replayed crawl page is invalid")
                for role in _RESPONSE_BUNDLE_FILES:
                    commitment = page.get(role)
                    if not isinstance(commitment, dict):
                        raise SnapshotError("replayed crawl commitment is invalid")
                    relative = _safe_relative_path(commitment.get("relativePath"))
                    prefix = PurePosixPath(f"archive/crawl-{crawl_index}")
                    try:
                        within = relative.relative_to(prefix)
                    except ValueError as error:
                        raise SnapshotError(
                            "crawl archive commitment escapes its stage"
                        ) from error
                    expected.add(str(within))
        _require_exact_tree_files(
            root,
            PurePosixPath(f"archive/crawl-{crawl_index}"),
            expected,
        )


def load_crawl_stage(root: Path, crawl_index: int) -> dict[str, dict[str, Any]]:
    """Verify and replay one persisted all-project crawl stage."""

    if crawl_index not in (0, 1):
        raise SnapshotError("crawl index differs from the registered design")
    root_descriptor, absolute = _open_directory_path(root, label="snapshot root")
    try:
        encoded = _read_regular_at(
            root_descriptor,
            f"crawl-{crawl_index + 1}-manifest.json",
            label="crawl stage manifest",
        )
    finally:
        os.close(root_descriptor)
    manifest = load_json_strict_bytes(encoded, label="crawl stage manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion", "countsTowardScientificVerdict", "crawlIndex",
        "notBefore", "projects",
    }:
        raise SnapshotError("crawl stage manifest fields differ")
    if canonical_json_bytes(manifest) != encoded:
        raise SnapshotError("crawl stage manifest is not canonical JSON")
    expected_not_before = CRAWL_NOT_BEFORE[crawl_index].strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    if (
        manifest["schemaVersion"] != CRAWL_STAGE_SCHEMA
        or manifest["countsTowardScientificVerdict"] is not False
        or manifest["crawlIndex"] != crawl_index + 1
        or manifest["notBefore"] != expected_not_before
    ):
        raise SnapshotError("crawl stage identity differs")
    projects = manifest["projects"]
    if not isinstance(projects, dict) or tuple(projects) != PROJECTS:
        raise SnapshotError("crawl stage projects/order differ")
    return {
        project: _replay_crawl(absolute, project, projects[project], crawl_index)
        for project in PROJECTS
    }


def collect_crawl_stage(
    *,
    root: Path,
    crawl_index: int,
    transport: Transport,
    clock: Callable[[], datetime],
) -> dict[str, Any]:
    """Persist one complete all-project crawl at its registered not-before time.

    Stage 1 can be run on/after 2026-08-30T06:00Z.  Stage 2 requires a fully
    verified stage 1 and can be run on/after 2026-08-31T06:00Z.  A partial
    failed stage has no completion manifest and must not be resumed in place.
    """

    if crawl_index not in (0, 1):
        raise SnapshotError("crawl index differs from the registered design")
    if crawl_index == 0:
        root_descriptor, absolute = _open_directory_path(
            root,
            create=True,
            label="snapshot root",
        )
        try:
            if _stable_directory_entries(root_descriptor, label="first crawl root"):
                raise SnapshotError("first crawl output root must be new or empty")
            archive = _open_relative_directory(
                root_descriptor,
                PurePosixPath("archive"),
                create=True,
                label="first crawl archive",
            )
            try:
                if _stable_directory_entries(archive, label="first crawl archive"):
                    raise SnapshotError("first crawl archive directory is not empty")
            finally:
                os.close(archive)
        finally:
            os.close(root_descriptor)
        root = absolute
    else:
        _require_stage_layout(root, 1)
        load_crawl_stage(root, 0)
    crawls = {
        project: collect_recentchanges_crawl(
            project=project,
            crawl_index=crawl_index,
            root=root,
            transport=transport,
            clock=clock,
        )
        for project in PROJECTS
    }
    manifest = {
        "schemaVersion": CRAWL_STAGE_SCHEMA,
        "countsTowardScientificVerdict": False,
        "crawlIndex": crawl_index + 1,
        "notBefore": CRAWL_NOT_BEFORE[crawl_index].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "projects": {
            project: _crawl_manifest_view(crawls[project]) for project in PROJECTS
        },
    }
    _write_exclusive(
        root,
        f"crawl-{crawl_index + 1}-manifest.json",
        canonical_json_bytes(manifest),
    )
    return manifest


def finalize_snapshot(
    *,
    root: Path,
    transport: Transport,
    tokenizers: Mapping[str, TokenizerLike],
) -> dict[str, Any]:
    """Resume/replay both crawls, revision bundles, records, and final ledgers.

    A complete committed revision bundle is never requested from the network a
    second time.  Existing records, ledgers, and the final manifest are accepted
    only when their bytes are exactly the deterministic bytes recomputed from the
    two crawls and archived responses.
    """

    if tuple(tokenizers) != MODEL_KEYS:
        raise SnapshotError("tokenizer order/set differs from the registered models")
    resolved_root = _require_finalize_layout(root)
    staged = [load_crawl_stage(resolved_root, index) for index in (0, 1)]
    _require_exact_crawl_archive_layout(resolved_root, staged)
    unions = {
        project: union_crawls(staged[0][project], staged[1][project])
        for project in PROJECTS
    }
    _validate_partial_finalize_entries(resolved_root, unions)

    root_descriptor, _ = _open_directory_path(
        resolved_root,
        label="snapshot root",
    )
    try:
        manifest_metadata = _entry_metadata(root_descriptor, "corpus-manifest.json")
        if manifest_metadata is not None and not stat.S_ISREG(manifest_metadata.st_mode):
            raise SnapshotError("completed corpus manifest is a symlink/non-regular file")
    finally:
        os.close(root_descriptor)
    if manifest_metadata is not None:
        manifest_bytes = _read_relative_regular(
            resolved_root,
            PurePosixPath("corpus-manifest.json"),
            label="completed corpus manifest",
        )
        manifest = load_json_strict_bytes(manifest_bytes, label="corpus manifest")
        if (
            not isinstance(manifest, dict)
            or canonical_json_bytes(manifest) != manifest_bytes
        ):
            raise SnapshotError("completed corpus manifest is not canonical")
        _write_or_reuse_exact(
            resolved_root,
            "corpus-manifest.json",
            manifest_bytes,
        )
        verify_corpus_snapshot(resolved_root, tokenizers=tokenizers)
        _require_complete_finalize_layout(resolved_root, manifest)
        return manifest

    projects: dict[str, Any] = {}
    for project in PROJECTS:
        crawls = [staged[index][project] for index in (0, 1)]
        union = unions[project]
        inventory = [
            fetch_and_inventory_revision(
                project=project,
                change=change,
                root=resolved_root,
                transport=transport,
                tokenizers=tokenizers,
            )
            for change in union
        ]
        eligible = [_ledger_record(item) for item in inventory if item["eligible"]]
        eligible.sort(key=lambda item: (item["timestamp"], item["revid"]))
        ledger_bytes = canonical_json_bytes(eligible)
        ledger = _write_or_reuse_exact(
            resolved_root, f"ledgers/{project}.json", ledger_bytes
        )
        projects[project] = {
            "crawls": [
                _crawl_manifest_view(crawl)
                for crawl in crawls
            ],
            "unionRevisionCount": len(union),
            "inventory": inventory,
            "eligibleRevisionCount": len(eligible),
            "ledger": ledger,
        }
    ready = all(
        projects[project]["eligibleRevisionCount"] >= MINIMUM_ELIGIBLE_PER_PROJECT
        for project in PROJECTS
    )
    manifest = {
        "schemaVersion": MANIFEST_SCHEMA,
        "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
        "status": "SNAPSHOT_READY_FOR_FREEZE" if ready else "INSUFFICIENT_ELIGIBLE_REVISIONS",
        "countsTowardScientificVerdict": False,
        "projects": projects,
    }
    manifest_bytes = canonical_json_bytes(manifest)
    _write_or_reuse_exact(resolved_root, "corpus-manifest.json", manifest_bytes)
    verify_corpus_snapshot(resolved_root, tokenizers=tokenizers)
    _require_complete_finalize_layout(resolved_root, manifest)
    return manifest


def collect_snapshot(
    *,
    root: Path,
    transport: Transport,
    tokenizers: Mapping[str, TokenizerLike],
    clock: Callable[[], datetime],
) -> dict[str, Any]:
    """Post-25-Aug convenience wrapper around the two durable crawl stages."""

    collect_crawl_stage(
        root=root, crawl_index=0, transport=transport, clock=clock
    )
    collect_crawl_stage(
        root=root, crawl_index=1, transport=transport, clock=clock
    )
    return finalize_snapshot(root=root, transport=transport, tokenizers=tokenizers)


def load_record_bytes(
    manifest: Mapping[str, Any], project: str, revid: int, root: Path
) -> bytes:
    """Resolve one selected record only through the verified manifest mapping."""

    if (
        not isinstance(manifest, Mapping)
        or manifest.get("schemaVersion") != MANIFEST_SCHEMA
        or project not in PROJECTS
        or type(revid) is not int
        or revid <= 0
    ):
        raise SnapshotError("corpus manifest/project is invalid")
    projects = manifest.get("projects")
    project_entry = projects.get(project) if isinstance(projects, dict) else None
    inventory = project_entry.get("inventory") if isinstance(project_entry, dict) else None
    if not isinstance(inventory, list):
        raise SnapshotError("corpus manifest inventory is invalid")
    matches = [
        item for item in inventory
        if isinstance(item, dict) and item.get("revid") == revid and item.get("eligible") is True
    ]
    if len(matches) != 1 or "record" not in matches[0]:
        raise SnapshotError("selected project/revid has no unique eligible record")
    value = _read_committed(root, matches[0]["record"])
    parsed = parse_record(value)
    if parsed["project"] != project or parsed["revid"] != revid:
        raise SnapshotError("record identity differs from manifest lookup")
    if sha256_bytes(parsed["title"].encode("utf-8")) != matches[0]["titleSHA256"]:
        raise SnapshotError("record title digest differs")
    if sha256_bytes(parsed["content"].encode("utf-8")) != matches[0]["contentSHA256"]:
        raise SnapshotError("record content digest differs")
    input_bytes = (parsed["title"] + "\n\n" + parsed["content"]).encode("utf-8")
    if sha256_bytes(input_bytes) != matches[0]["inputSHA256"]:
        raise SnapshotError("record input digest differs")
    return value


def load_archived_response(
    root: Path, archive: Mapping[str, Any], *, expected_uri: str
) -> ArchivedHTTPResponse:
    required = {
        "requestURI", "serverDate", "requestURIFile", "responseHeaders",
        "responseBody",
    }
    if not isinstance(archive, dict) or not required.issubset(archive):
        raise SnapshotError("archived HTTP response fields are incomplete")
    if archive["requestURI"] != expected_uri:
        raise SnapshotError("archived request URI differs from replay")
    try:
        expected_request_bytes = expected_uri.encode("ascii", errors="strict") + b"\n"
    except UnicodeEncodeError as error:
        raise SnapshotError("archived request URI is not ASCII") from error
    request_bytes = _read_committed(root, archive["requestURIFile"])
    if request_bytes != expected_request_bytes:
        raise SnapshotError("archived request URI bytes differ")
    headers = _read_committed(root, archive["responseHeaders"])
    body = _read_committed(root, archive["responseBody"])
    status, _ = _parse_header_block(headers)
    response = ArchivedHTTPResponse(expected_uri, status, headers, body)
    _validate_response(response, expected_uri=expected_uri)
    observed_date = response_date(response).strftime("%Y-%m-%dT%H:%M:%SZ")
    if archive["serverDate"] != observed_date:
        raise SnapshotError("archived server Date differs")
    return response


def _replay_crawl(
    root: Path, project: str, crawl: Mapping[str, Any], crawl_index: int
) -> dict[str, Any]:
    if not isinstance(crawl, dict) or set(crawl) != {
        "crawlIndex", "project", "notBefore", "pages"
    }:
        raise SnapshotError("crawl manifest fields differ")
    expected_not_before = CRAWL_NOT_BEFORE[crawl_index]
    expected_not_before_text = expected_not_before.strftime("%Y-%m-%dT%H:%M:%SZ")
    if (
        crawl["crawlIndex"] != crawl_index + 1
        or crawl["project"] != project
        or crawl["notBefore"] != expected_not_before_text
    ):
        raise SnapshotError("crawl identity/not-before differs")
    pages = crawl["pages"]
    if not isinstance(pages, list) or not pages or len(pages) > MAX_CRAWL_PAGES:
        raise SnapshotError("crawl page count is invalid")
    continuation: dict[str, str] | None = None
    seen_continuations: set[tuple[str, str]] = set()
    seen_revisions: set[int] = set()
    records: list[dict[str, Any]] = []
    for page_index, page in enumerate(pages):
        if not isinstance(page, dict) or set(page) != {
            "requestURI", "serverDate", "requestURIFile", "responseHeaders",
            "responseBody", "records",
        }:
            raise SnapshotError("crawl page archive fields differ")
        expected_uri = recentchanges_uri(project, continuation)
        response = load_archived_response(root, page, expected_uri=expected_uri)
        if response_date(response) < expected_not_before:
            raise SnapshotError("archived crawl Date precedes its not-before time")
        page_records, next_continuation = _parse_recentchanges(response.body)
        if type(page["records"]) is not int or page["records"] != len(page_records):
            raise SnapshotError("crawl page record count differs")
        for record in page_records:
            if record["revid"] in seen_revisions:
                raise SnapshotError("archived crawl contains a duplicate revision")
            seen_revisions.add(record["revid"])
            records.append(record)
        last = page_index == len(pages) - 1
        if next_continuation is None:
            if not last:
                raise SnapshotError("crawl archive has pages after completion")
            continuation = None
            continue
        if last:
            raise SnapshotError("crawl archive stops before continuation completion")
        key = (next_continuation["continue"], next_continuation["rccontinue"])
        if key in seen_continuations:
            raise SnapshotError("archived RecentChanges continuation cycle detected")
        seen_continuations.add(key)
        continuation = next_continuation
    return {
        "crawlIndex": crawl_index + 1,
        "project": project,
        "notBefore": crawl["notBefore"],
        "pages": crawl["pages"],
        "records": records,
    }


def _validate_token_commitments(
    commitments: Any,
    *,
    input_text: str,
    tokenizers: Mapping[str, TokenizerLike] | None,
) -> bool:
    if not isinstance(commitments, dict) or tuple(commitments) != MODEL_KEYS:
        raise SnapshotError("inventory tokenizer order/set differs")
    for model_key in MODEL_KEYS:
        commitment = commitments[model_key]
        if not isinstance(commitment, dict) or set(commitment) != {
            "tokenCount", "vocabSize", "completeStreamSHA256", "first512StreamSHA256"
        }:
            raise SnapshotError("inventory token commitment fields differ")
        if type(commitment["tokenCount"]) is not int or commitment["tokenCount"] < 0:
            raise SnapshotError("inventory token count is invalid")
        if type(commitment["vocabSize"]) is not int or not 1 <= commitment["vocabSize"] <= 2**32:
            raise SnapshotError("inventory tokenizer vocabulary size is invalid")
        for field in ("completeStreamSHA256", "first512StreamSHA256"):
            if not isinstance(commitment[field], str) or re.fullmatch(r"[0-9a-f]{64}", commitment[field]) is None:
                raise SnapshotError("inventory token digest is invalid")
        if tokenizers is not None:
            observed = token_commitment(tokenizers[model_key], input_text)
            if observed != commitment:
                raise SnapshotError(f"token commitment differs for {model_key}")
    return all(commitments[key]["tokenCount"] >= 512 for key in MODEL_KEYS)


def _verify_inventory_item(
    root: Path,
    project: str,
    change: Mapping[str, Any],
    item: Any,
    *,
    tokenizers: Mapping[str, TokenizerLike] | None,
) -> None:
    common_fields = {
        "project", "pageid", "revid", "userid", "timestamp", "username", "title",
        "revisionAPICurrentTitle",
        "mediaWikiSHA1", "titleSHA256", "contentSHA256", "inputSHA256",
        "tokenizers", "revisionURL", "historyURL", "attribution",
        "revisionArchive", "eligible", "ineligibilityReasons",
    }
    excluded_fields = {
        "project", "pageid", "revid", "timestamp", "title", "recentChanges",
        "revisionArchive", "exclusionStage", "eligible", "ineligibilityReasons",
    }
    if not isinstance(item, dict):
        raise SnapshotError("revision inventory fields differ")
    minimal_identity = {
        "project": project,
        "pageid": change["pageid"],
        "revid": change["revid"],
        "timestamp": change["timestamp"],
        "title": change["title"],
    }
    if any(item.get(field) != value for field, value in minimal_identity.items()):
        raise SnapshotError("inventory identity differs from replayed RecentChanges")
    expected_uri = revision_uri(project, change["revid"])
    archive = item.get("revisionArchive")
    if not isinstance(archive, dict) or set(archive) != {
        "requestURI", "serverDate", "requestURIFile", "responseHeaders", "responseBody"
    }:
        raise SnapshotError("revision archive fields differ")
    response = load_archived_response(root, archive, expected_uri=expected_uri)
    if set(item) in (excluded_fields, excluded_fields | {"revisionAPICurrentTitle"}):
        if (
            item["exclusionStage"] != "source-eligibility"
            or item["eligible"] is not False
            or item["recentChanges"] != dict(change)
        ):
            raise SnapshotError("source exclusion inventory fields differ")
        expected_reasons = _source_ineligibility_reasons(change)
        expected_current_title: str | None = None
        try:
            parsed_revision = _parse_revision(
                response.body, {**change, "project": project}
            )
            expected_current_title = parsed_revision["revisionAPICurrentTitle"]
        except RevisionIneligible as error:
            expected_reasons.extend(error.reasons)
            expected_current_title = error.revision_api_current_title
        expected_reasons = list(dict.fromkeys(expected_reasons))
        if not expected_reasons or item["ineligibilityReasons"] != expected_reasons:
            raise SnapshotError("source exclusion reasons differ from archived response")
        if expected_current_title is None:
            if "revisionAPICurrentTitle" in item:
                raise SnapshotError("deleted revision invents a current API title")
        elif item.get("revisionAPICurrentTitle") != expected_current_title:
            raise SnapshotError("excluded revision current API title differs")
        return
    if set(item) not in (common_fields, common_fields | {"record"}):
        raise SnapshotError("revision inventory fields differ")
    if any(field not in change for field in ("userid", "user", "sha1")):
        raise SnapshotError("visible inventory came from hidden RecentChanges fields")
    visible_identity = {
        "userid": change["userid"],
        "username": change["user"],
        "mediaWikiSHA1": change["sha1"],
    }
    if any(item[field] != value for field, value in visible_identity.items()):
        raise SnapshotError("inventory visible identity differs from RecentChanges")
    try:
        revision = _parse_revision(response.body, {**change, "project": project})
    except RevisionIneligible as error:
        raise SnapshotError(
            "ordinary inventory item wraps an ineligible archived revision"
        ) from error
    content_bytes = revision["content"].encode("utf-8", errors="strict")
    title_bytes = revision["title"].encode("utf-8", errors="strict")
    input_text = revision["title"] + "\n\n" + revision["content"]
    input_bytes = input_text.encode("utf-8", errors="strict")
    expected_digests = {
        "titleSHA256": sha256_bytes(title_bytes),
        "contentSHA256": sha256_bytes(content_bytes),
        "inputSHA256": sha256_bytes(input_bytes),
    }
    if any(item[field] != digest for field, digest in expected_digests.items()):
        raise SnapshotError("inventory title/content/input digest differs")
    if item["revisionAPICurrentTitle"] != revision["revisionAPICurrentTitle"]:
        raise SnapshotError("revision API current-title provenance differs")
    expected_revision_url = f"https://{project}/w/index.php?oldid={revision['revid']}"
    expected_history_url = (
        f"https://{project}/w/index.php?curid={revision['pageid']}"
        "&action=history"
    )
    if item["revisionURL"] != expected_revision_url or item["historyURL"] != expected_history_url:
        raise SnapshotError("inventory attribution URL differs")
    expected_attribution = {
        "username": revision["username"],
        "userid": revision["userid"],
        **_license(project),
    }
    if item["attribution"] != expected_attribution:
        raise SnapshotError("inventory attribution fields differ")
    eligible = _validate_token_commitments(
        item["tokenizers"], input_text=input_text, tokenizers=tokenizers
    )
    if type(item["eligible"]) is not bool or item["eligible"] != eligible:
        raise SnapshotError("inventory eligibility differs from token commitments")
    expected_reasons = [] if eligible else [
        "fewer-than-512-tokens-under-at-least-one-tokenizer"
    ]
    if item["ineligibilityReasons"] != expected_reasons:
        raise SnapshotError("inventory ineligibility reasons differ")
    if eligible:
        if "record" not in item:
            raise SnapshotError("eligible inventory item has no record")
        record_bytes = _read_committed(root, item["record"])
        expected_record = serialize_record(
            project=project,
            pageid=revision["pageid"],
            revid=revision["revid"],
            userid=revision["userid"],
            timestamp=revision["timestamp"],
            username=revision["username"],
            title=revision["title"],
            content=revision["content"],
        )
        if record_bytes != expected_record:
            raise SnapshotError("corpus record differs from archived revision bytes")
    elif "record" in item:
        raise SnapshotError("ineligible inventory item unexpectedly has a record")


def verify_corpus_snapshot(
    root: Path, *, tokenizers: Mapping[str, TokenizerLike] | None = None
) -> dict[str, Any]:
    """Replay every archived request and byte commitment, without inference.

    Supplying the three frozen tokenizers additionally recomputes every token
    stream commitment.  Omitting them still verifies all raw MediaWiki bytes,
    continuation chains, revisions, records, ledgers, and structural token
    commitments, and reports that token streams were not recomputed.
    """

    if tokenizers is not None and tuple(tokenizers) != MODEL_KEYS:
        raise SnapshotError("tokenizer order/set differs from the registered models")
    resolved_root = _require_finalize_layout(root)
    staged = [load_crawl_stage(resolved_root, index) for index in (0, 1)]
    _require_exact_crawl_archive_layout(resolved_root, staged)
    manifest_bytes = _read_relative_regular(
        resolved_root,
        PurePosixPath("corpus-manifest.json"),
        label="corpus manifest",
    )
    manifest = load_json_strict_bytes(manifest_bytes, label="corpus manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion", "suiteId", "status", "countsTowardScientificVerdict",
        "projects",
    }:
        raise SnapshotError("corpus manifest fields differ")
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise SnapshotError("corpus manifest bytes are not canonical JSON")
    if manifest["schemaVersion"] != MANIFEST_SCHEMA:
        raise SnapshotError("unexpected corpus manifest schema")
    if manifest["suiteId"] != "corelm-voidtoken-crossmodel-livewiki-v3-author-verified":
        raise SnapshotError("unexpected corpus manifest suite")
    if manifest["countsTowardScientificVerdict"] is not False:
        raise SnapshotError("snapshot inventory must not claim a scientific verdict")
    projects = manifest["projects"]
    if not isinstance(projects, dict) or tuple(projects) != PROJECTS:
        raise SnapshotError("corpus manifest projects/order differ")
    total = 0
    for project in PROJECTS:
        entry = projects[project]
        if not isinstance(entry, dict) or set(entry) != {
            "crawls", "unionRevisionCount", "inventory", "eligibleRevisionCount",
            "ledger",
        }:
            raise SnapshotError("project manifest entry fields differ")
        crawls = entry["crawls"]
        if not isinstance(crawls, list) or len(crawls) != 2:
            raise SnapshotError("project must contain exactly two complete crawls")
        replayed = [staged[index][project] for index in (0, 1)]
        expected_crawls = [_crawl_manifest_view(crawl) for crawl in replayed]
        if crawls != expected_crawls:
            raise SnapshotError("corpus manifest crawl views differ from stage manifests")
        union = union_crawls(replayed[0], replayed[1])
        if type(entry["unionRevisionCount"]) is not int or entry["unionRevisionCount"] != len(union):
            raise SnapshotError("union revision count differs from crawl replay")
        inventory = entry["inventory"]
        if not isinstance(inventory, list) or len(inventory) != len(union):
            raise SnapshotError("inventory count differs from crawl union")
        for change, item in zip(union, inventory):
            _verify_inventory_item(
                resolved_root, project, change, item, tokenizers=tokenizers
            )
        eligible_inventory = [item for item in inventory if item["eligible"] is True]
        if (
            type(entry["eligibleRevisionCount"]) is not int
            or entry["eligibleRevisionCount"] != len(eligible_inventory)
        ):
            raise SnapshotError("eligible inventory count differs")
        ledger_bytes = _read_committed(resolved_root, entry["ledger"])
        ledger = load_json_strict_bytes(ledger_bytes, label=f"ledger {project}")
        expected_ledger = [_ledger_record(item) for item in eligible_inventory]
        expected_ledger.sort(key=lambda item: (item["timestamp"], item["revid"]))
        if ledger != expected_ledger or canonical_json_bytes(expected_ledger) != ledger_bytes:
            raise SnapshotError("ledger bytes are not the canonical eligible inventory")
        for record in expected_ledger:
            value = load_record_bytes(manifest, project, record["revid"], resolved_root)
            parsed = parse_record(value)
            if hashlib.sha1(parsed["content"].encode("utf-8")).hexdigest() != record["mediaWikiSHA1"]:
                raise SnapshotError("record content no longer matches MediaWiki SHA-1")
        total += len(expected_ledger)
    ready = all(
        projects[project]["eligibleRevisionCount"] >= MINIMUM_ELIGIBLE_PER_PROJECT
        for project in PROJECTS
    )
    expected_status = (
        "SNAPSHOT_READY_FOR_FREEZE" if ready else "INSUFFICIENT_ELIGIBLE_REVISIONS"
    )
    if manifest["status"] != expected_status:
        raise SnapshotError("corpus manifest status differs from verified counts")
    _require_complete_finalize_layout(resolved_root, manifest)
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-corpus-verification-v1",
        "status": "VERIFIED_SNAPSHOT_BYTES",
        "readyForFreeze": ready,
        "eligibleRecords": total,
        "manifestSHA256": sha256_bytes(manifest_bytes),
        "tokenCommitmentsRecomputed": tokenizers is not None,
        "modelInferenceUsed": False,
    }


__all__ = [
    "ArchivedHTTPResponse",
    "CRAWL_NOT_BEFORE",
    "CRAWL_STAGE_SCHEMA",
    "MANIFEST_SCHEMA",
    "MODEL_KEYS",
    "PinnedHTTPSClient",
    "PROJECTS",
    "SnapshotError",
    "archive_response",
    "collect_crawl_stage",
    "collect_recentchanges_crawl",
    "collect_snapshot",
    "finalize_snapshot",
    "fetch_and_inventory_revision",
    "load_archived_response",
    "load_crawl_stage",
    "load_record_bytes",
    "parse_record",
    "recentchanges_uri",
    "revision_uri",
    "serialize_record",
    "token_commitment",
    "union_crawls",
    "verify_corpus_snapshot",
]
