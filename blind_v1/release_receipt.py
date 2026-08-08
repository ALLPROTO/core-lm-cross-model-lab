#!/usr/bin/env python3
"""Fail-closed verification for archived GitHub release receipts.

This module verifies exact archived bytes and their internal bindings.  It does
not claim that an archived HTTP response is a cryptographic server attestation.
For SSH-signed annotated tags it re-verifies the exact archived signed payload
and signature with the tracked public key, tracked ``allowed_signers``, and
``ssh-keygen -Y verify`` under the Git ``git`` namespace.  The archived GitHub
``verification`` fields and release timestamps remain API observations bound
to captured response bytes; they are not substituted for local cryptographic
verification.

The offline replay performs no network access.  It re-hashes the raw commit and tag
objects, binds the tag to the exact commit and tree, parses four archived
GitHub API responses, enforces server publication time and immutable-release
state, streams every required release asset from a no-follow directory, and
replays every semantic binding in the GitHub immutable-release Sigstore bundle.
An explicitly supplied pinned Cosign verifier must independently verify the
archived DSSE, X.509 chain, RFC3161 timestamp, release SAN, and one signed asset
digest before this module returns success.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import quote

from blind_v1.github_release_attestation import (
    ReleaseAttestationError,
    verify_attestation_record,
)
from blind_v1.release_attestation_crypto import (
    ReleaseAttestationCryptoError,
    VerifiedCryptographicAttestation,
    validate_cryptographic_verification_record,
)


SCHEMA_VERSION = "corelm-github-release-receipt-v2"
SUITE_ID = "corelm-blind-crossmodel-v1"
GITHUB_API_VERSION = "2026-03-10"
KINDS = frozenset(
    (
        "development-control",
        "design",
        "snapshot",
        "reservation",
        "evidence",
        "closeout",
    )
)
API_ROLES = ("commit", "release", "tag-object", "tag-ref")
REQUIRED_ASSET_ROLES: dict[str, tuple[str, ...]] = {
    "development-control": (
        "development-control-report",
        "development-control-artifacts",
        "sha256-manifest",
    ),
    "design": (
        "asset-source-manifest",
        "design-registration",
        "development-control-report",
        "development-control-archive-receipt",
        "freeze-manifest",
        "full-asset-receipt",
        "github-gate-receipt",
        "linux-ci-artifact",
        "macos-arm64-ci-artifact",
        "runtime-manifest",
        "sbom",
        "sha256-manifest",
    ),
    "snapshot": (
        "attribution",
        "corpus-bytes",
        "design-publication-receipt",
        "sha256-manifest",
        "snapshot-registration",
    ),
    "reservation": (
        "execution-reservation",
        "snapshot-publication-receipt",
        "sha256-manifest",
    ),
    "evidence": (
        "evidence-package",
        "evidence-release-manifest",
        "evidence-package-verifier-report",
        "sha256-manifest",
    ),
    "closeout": (
        "closeout-statement",
        "closeout-basis",
        "closeout-verifier-report",
        "sha256-manifest",
    ),
}
REQUIRED_ROLE_FILENAMES = {
    "development-control-report": "development-control-report.json",
    "development-control-artifacts": "development-control-artifacts.zip",
    "development-control-archive-receipt": "development-control-archive-receipt.json",
    "linux-ci-artifact": "linux-ci-artifact.zip",
    "macos-arm64-ci-artifact": "macos-arm64-ci-artifact.zip",
}
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
OWNER_OR_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z")
TAG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
ASSET_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,190}[A-Za-z0-9])?\Z")
SSH_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MAXIMUM_RECEIPT_BYTES = 64 * 1024 * 1024
MAXIMUM_API_BODY_BYTES = 16 * 1024 * 1024
MAXIMUM_HEADER_BYTES = 256 * 1024
MAXIMUM_COMMIT_BYTES = 16 * 1024 * 1024
MAXIMUM_TAG_BYTES = 16 * 1024 * 1024
MAXIMUM_TRANSCRIPT_BYTES = 4 * 1024 * 1024
MAXIMUM_ASSET_BYTES = 2 * 1024 * 1024 * 1024 * 1024
MAXIMUM_CAPTURE_SPAN_SECONDS = 300
READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_PUBLIC_KEY_BYTES = 16 * 1024
MAXIMUM_ALLOWED_SIGNERS_BYTES = 64 * 1024
MAXIMUM_SIGNATURE_TOOL_OUTPUT_BYTES = 1024 * 1024
SSH_KEYGEN_PATH = Path("/usr/bin/ssh-keygen")
SSH_SIGNATURE_NAMESPACE = "git"
BLIND_V1_ROOT = Path(__file__).resolve().parent
TRACKED_SSH_PUBLIC_KEY_PATH = (
    BLIND_V1_ROOT / "signing/corelm-blind-crossmodel-v1-signing.pub"
)
TRACKED_SSH_ALLOWED_SIGNERS_PATH = BLIND_V1_ROOT / "signing/allowed_signers"


class ReleaseReceiptError(ValueError):
    """The publication receipt is incomplete, mutable, late, or inconsistent."""


class ReleaseAttestationCryptographicVerifier(Protocol):
    def verify(
        self,
        *,
        attestation_record: Any,
        asset_root: Path,
        expected_assets: Sequence[tuple[str, str]],
    ) -> VerifiedCryptographicAttestation: ...


@dataclass(frozen=True)
class VerifiedReleaseReceipt:
    repository: str
    kind: str
    tag: str
    release_id: int
    commit: str
    tree: str
    signature_type: str
    key_fingerprint: str
    public_key_sha256: str
    published_at: str
    attested_at: str
    attestation_bundle_sha256: str
    attestation_output_sha256: str
    receipt_sha256: str
    asset_sha256: tuple[tuple[str, str], ...]


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise ReleaseReceiptError("release receipt is not canonical JSON data") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha1(value: bytes) -> str:
    try:
        return hashlib.sha1(value, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - older Python compatibility
        return hashlib.sha1(value).hexdigest()


def _git_object_oid(kind: str, payload: bytes) -> str:
    if kind not in {"commit", "tag"}:
        raise ReleaseReceiptError("unsupported Git object type")
    header = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0"
    return _sha1(header + payload)


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ReleaseReceiptError(f"{label} is absent or unsafe") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ReleaseReceiptError(f"{label} metadata differs")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise ReleaseReceiptError(f"{label} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if identity(before) != identity(after):
            raise ReleaseReceiptError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_ed25519_public_key(raw: bytes) -> tuple[bytes, str]:
    if (
        raw.count(b"\n") != 1
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\0" in raw
    ):
        raise ReleaseReceiptError("trusted SSH public key text is non-canonical")
    line = raw[:-1]
    fields = line.split(b" ", 2)
    if len(fields) < 2 or fields[0] != b"ssh-ed25519" or not fields[1]:
        raise ReleaseReceiptError("trusted SSH public key must be one Ed25519 key")
    encoded = fields[1]
    try:
        blob = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ReleaseReceiptError("trusted SSH public key base64 is invalid") from error
    if base64.b64encode(blob) != encoded:
        raise ReleaseReceiptError("trusted SSH public key base64 is non-canonical")

    offset = 0

    def take_string(label: str) -> bytes:
        nonlocal offset
        if offset + 4 > len(blob):
            raise ReleaseReceiptError(f"trusted SSH public key is truncated: {label}")
        size = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4
        if size > len(blob) - offset:
            raise ReleaseReceiptError(f"trusted SSH public key is truncated: {label}")
        value = blob[offset : offset + size]
        offset += size
        return value

    if (
        take_string("algorithm") != b"ssh-ed25519"
        or len(take_string("key")) != 32
        or offset != len(blob)
    ):
        raise ReleaseReceiptError("trusted SSH public key wire format differs")
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).decode("ascii").rstrip("=")
    return b"ssh-ed25519 " + encoded, fingerprint


def _parse_allowed_signers(
    raw: bytes,
    *,
    expected_public_key_line: bytes,
) -> str:
    if (
        raw.count(b"\n") != 1
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\0" in raw
        or b"\t" in raw
    ):
        raise ReleaseReceiptError("trusted SSH allowed_signers is non-canonical")
    fields = raw[:-1].split(b" ")
    if len(fields) != 3 or not fields[0] or b" " in fields[0]:
        raise ReleaseReceiptError("trusted SSH allowed_signers fields differ")
    if fields[1] + b" " + fields[2] != expected_public_key_line:
        raise ReleaseReceiptError(
            "trusted SSH allowed_signers does not bind the public key"
        )
    if re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9_.+@-]{0,253}", fields[0]) is None:
        raise ReleaseReceiptError("trusted SSH allowed_signers principal is invalid")
    return fields[0].decode("ascii")


def _write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReleaseReceiptError("short write in SSH verification workspace")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_archived_ssh_signature(
    *,
    signed_payload: bytes,
    signature: bytes,
    trusted_public_key_path: Path,
    trusted_allowed_signers_path: Path,
    expected_public_key_sha256: str,
    expected_key_fingerprint: str,
) -> None:
    """Cryptographically verify the exact archived Git SSH signature."""

    public_key_raw = _read_stable_regular_file(
        trusted_public_key_path,
        label="trusted SSH public key",
        maximum_bytes=MAXIMUM_PUBLIC_KEY_BYTES,
    )
    if _sha256(public_key_raw) != expected_public_key_sha256:
        raise ReleaseReceiptError("trusted SSH public-key SHA-256 differs")
    public_key_line, observed_fingerprint = _parse_ed25519_public_key(public_key_raw)
    if observed_fingerprint != expected_key_fingerprint:
        raise ReleaseReceiptError("trusted SSH public-key fingerprint differs")
    allowed_signers_raw = _read_stable_regular_file(
        trusted_allowed_signers_path,
        label="trusted SSH allowed_signers",
        maximum_bytes=MAXIMUM_ALLOWED_SIGNERS_BYTES,
    )
    signer_principal = _parse_allowed_signers(
        allowed_signers_raw,
        expected_public_key_line=public_key_line,
    )

    try:
        before = os.stat(SSH_KEYGEN_PATH, follow_symlinks=False)
    except OSError as error:
        raise ReleaseReceiptError("/usr/bin/ssh-keygen is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111 == 0:
        raise ReleaseReceiptError("/usr/bin/ssh-keygen is not an executable file")

    try:
        with tempfile.TemporaryDirectory(
            prefix="corelm-release-signature-"
        ) as temporary_value:
            temporary = Path(temporary_value)
            os.chmod(temporary, 0o700)
            allowed_signers = temporary / "allowed_signers"
            signature_path = temporary / "tag.sig"
            _write_exclusive(allowed_signers, allowed_signers_raw)
            _write_exclusive(signature_path, signature)
            completed = subprocess.run(
                [
                    os.fspath(SSH_KEYGEN_PATH),
                    "-Y",
                    "verify",
                    "-f",
                    os.fspath(allowed_signers),
                    "-I",
                    signer_principal,
                    "-n",
                    SSH_SIGNATURE_NAMESPACE,
                    "-s",
                    os.fspath(signature_path),
                ],
                input=signed_payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=temporary,
                env={
                    "HOME": os.fspath(temporary),
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                },
                check=False,
                close_fds=True,
                start_new_session=True,
                timeout=30,
            )
    except subprocess.TimeoutExpired as error:
        raise ReleaseReceiptError("SSH tag verification timed out") from error
    except OSError as error:
        raise ReleaseReceiptError("SSH tag verification could not execute") from error
    if len(completed.stdout) > MAXIMUM_SIGNATURE_TOOL_OUTPUT_BYTES:
        raise ReleaseReceiptError("SSH tag verification output exceeds bound")
    try:
        after = os.stat(SSH_KEYGEN_PATH, follow_symlinks=False)
    except OSError as error:
        raise ReleaseReceiptError("/usr/bin/ssh-keygen changed during verification") from error
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise ReleaseReceiptError("/usr/bin/ssh-keygen changed during verification")
    if completed.returncode != 0:
        raise ReleaseReceiptError("annotated SSH tag cryptographic verification failed")


def _mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseReceiptError(f"{label} fields differ from the canonical contract")
    return value


def _oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID.fullmatch(value) is None:
        raise ReleaseReceiptError(f"{label} must be a full lowercase SHA-1 Git OID")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ReleaseReceiptError(f"{label} must be lowercase SHA-256")
    return value


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise ReleaseReceiptError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ReleaseReceiptError(f"{label} is not a real timestamp") from error


def _parse_json(raw: bytes, *, label: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseReceiptError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicates)
    except UnicodeDecodeError as error:
        raise ReleaseReceiptError(f"{label} is not strict UTF-8") from error
    except json.JSONDecodeError as error:
        raise ReleaseReceiptError(f"{label} is not JSON") from error


def _archived_bytes(
    value: Any,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    record = _mapping(
        value,
        {"encoding", "bytes", "sha256", "dataBase64"},
        label=label,
    )
    if record["encoding"] != "base64":
        raise ReleaseReceiptError(f"{label} encoding must be base64")
    if type(record["bytes"]) is not int or not 0 <= record["bytes"] <= maximum_bytes:
        raise ReleaseReceiptError(f"{label} byte count is invalid")
    expected_digest = _digest(record["sha256"], label=f"{label} SHA-256")
    encoded = record["dataBase64"]
    if not isinstance(encoded, str) or len(encoded) > ((maximum_bytes + 2) // 3) * 4:
        raise ReleaseReceiptError(f"{label} base64 payload is invalid")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise ReleaseReceiptError(f"{label} base64 payload is invalid") from error
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ReleaseReceiptError(f"{label} base64 payload is not canonical")
    if len(raw) != record["bytes"] or _sha256(raw) != expected_digest:
        raise ReleaseReceiptError(f"{label} archived bytes differ from their digest")
    return raw


def _load_canonical_receipt(raw: bytes) -> dict[str, Any]:
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= MAXIMUM_RECEIPT_BYTES
        or not raw.endswith(b"\n")
        or raw.endswith(b"\n\n")
    ):
        raise ReleaseReceiptError("release receipt must be bounded and end in exactly one LF")
    value = _parse_json(raw, label="release receipt")
    if not isinstance(value, dict):
        raise ReleaseReceiptError("release receipt root must be an object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise ReleaseReceiptError("release receipt bytes are not canonical")
    return value


def _parse_commit_object(payload: bytes) -> str:
    header, separator, _message = payload.partition(b"\n\n")
    if not separator or b"\0" in header:
        raise ReleaseReceiptError("raw commit object has malformed headers")
    lines = header.split(b"\n")
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    if not lines or lines[0] not in tree_lines or len(tree_lines) != 1:
        raise ReleaseReceiptError("raw commit must have one leading tree header")
    try:
        return _oid(tree_lines[0][5:].decode("ascii"), label="commit tree")
    except UnicodeDecodeError as error:
        raise ReleaseReceiptError("raw commit tree is not ASCII") from error


def _parse_signed_tag(
    payload: bytes,
    *,
    expected_tag: str,
    signature_type: str,
) -> tuple[str, bytes, bytes]:
    header, separator, message = payload.partition(b"\n\n")
    if not separator or b"\0" in payload:
        raise ReleaseReceiptError("raw annotated tag has malformed headers")
    lines = header.split(b"\n")
    if len(lines) != 4:
        raise ReleaseReceiptError("raw annotated tag headers differ")
    expected_prefixes = (b"object ", b"type ", b"tag ", b"tagger ")
    if any(not line.startswith(prefix) for line, prefix in zip(lines, expected_prefixes)):
        raise ReleaseReceiptError("raw annotated tag headers are not canonical")
    if lines[1] != b"type commit":
        raise ReleaseReceiptError("annotated tag does not target a commit")
    try:
        raw_target = lines[0][7:].decode("ascii")
        tag_name = lines[2][4:].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ReleaseReceiptError("raw annotated tag identity is not portable text") from error
    target = _oid(raw_target, label="tag target")
    if tag_name != expected_tag:
        raise ReleaseReceiptError("raw annotated tag name differs")
    if signature_type != "SSH":
        raise ReleaseReceiptError("declared tag signature type is unsupported")
    begin = b"-----BEGIN SSH SIGNATURE-----\n"
    end = b"-----END SSH SIGNATURE-----\n"
    signature_offset = message.find(begin)
    if signature_offset < 0:
        raise ReleaseReceiptError("annotated tag is unsigned")
    signed_payload = header + separator + message[:signature_offset]
    signature = message[signature_offset:]
    if (
        signature.count(begin) != 1
        or signature.count(end) != 1
        or not signature.endswith(end)
    ):
        raise ReleaseReceiptError(
            f"annotated tag {signature_type} signature block is malformed"
        )
    try:
        signed_payload.decode("utf-8", "strict")
        signature.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ReleaseReceiptError("annotated tag payload is not portable text") from error
    return target, signed_payload, signature


def _parse_http_headers(raw: bytes, *, expected_status: int) -> dict[str, list[str]]:
    if not raw.endswith(b"\r\n\r\n") or b"\0" in raw:
        raise ReleaseReceiptError("archived GitHub response headers are not a complete CRLF block")
    lines = raw[:-4].split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/(?:1\.1|2) [0-9]{3}(?: [^\r\n]*)?", lines[0]) is None:
        raise ReleaseReceiptError("archived GitHub response status line is invalid")
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (ValueError, IndexError) as error:
        raise ReleaseReceiptError("archived GitHub status code is invalid") from error
    if status != expected_status:
        raise ReleaseReceiptError("archived GitHub status code differs")
    fields: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or HEADER_NAME.fullmatch(name) is None or value[:1] not in {b"", b" "}:
            raise ReleaseReceiptError("archived GitHub response header is malformed")
        try:
            key = name.decode("ascii").lower()
            text = value.lstrip(b" ").decode("latin-1")
        except UnicodeDecodeError as error:  # pragma: no cover - latin-1 is total
            raise ReleaseReceiptError("archived GitHub response header is invalid") from error
        if "\r" in text or "\n" in text:
            raise ReleaseReceiptError("archived GitHub response header is folded")
        fields.setdefault(key, []).append(text)
    for required in ("date", "content-type", "x-github-api-version-selected", "x-github-request-id"):
        if len(fields.get(required, [])) != 1:
            raise ReleaseReceiptError(f"archived GitHub header {required} must occur once")
    if not fields["content-type"][0].lower().startswith("application/json"):
        raise ReleaseReceiptError("archived GitHub response is not JSON")
    if fields["x-github-api-version-selected"][0] != GITHUB_API_VERSION:
        raise ReleaseReceiptError("archived GitHub API version differs")
    if not fields["x-github-request-id"][0].strip():
        raise ReleaseReceiptError("archived GitHub request ID is empty")
    return fields


def _server_date(value: str) -> datetime:
    try:
        observed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as error:
        raise ReleaseReceiptError("GitHub Date header is invalid") from error
    if observed.tzinfo is None:
        raise ReleaseReceiptError("GitHub Date header has no timezone")
    observed = observed.astimezone(timezone.utc)
    if observed.microsecond:
        raise ReleaseReceiptError("GitHub Date header is not whole-second")
    return observed


def _repository(value: Any, *, expected: str) -> tuple[str, str, str, str]:
    record = _mapping(
        value,
        {"slug", "htmlURL", "apiURL"},
        label="repository",
    )
    if not isinstance(expected, str) or expected.count("/") != 1:
        raise ReleaseReceiptError("expected repository must be OWNER/REPO")
    owner, name = expected.split("/")
    if (
        OWNER_OR_REPOSITORY.fullmatch(owner) is None
        or OWNER_OR_REPOSITORY.fullmatch(name) is None
        or name.endswith(".git")
    ):
        raise ReleaseReceiptError("expected repository is invalid")
    html = f"https://github.com/{owner}/{name}"
    api = f"https://api.github.com/repos/{owner}/{name}"
    if record != {"slug": expected, "htmlURL": html, "apiURL": api}:
        raise ReleaseReceiptError("repository identity or URLs differ")
    return owner, name, html, api


def _response_endpoint(
    role: str,
    *,
    api_base: str,
    tag: str,
    tag_oid: str,
    commit: str,
    release_id: int,
) -> str:
    if role == "release":
        return f"{api_base}/releases/{release_id}"
    if role == "tag-ref":
        return f"{api_base}/git/ref/tags/{quote(tag, safe='')}"
    if role == "tag-object":
        return f"{api_base}/git/tags/{tag_oid}"
    if role == "commit":
        return f"{api_base}/git/commits/{commit}"
    raise ReleaseReceiptError("unknown GitHub API response role")


def _validate_api_responses(
    value: Any,
    *,
    api_base: str,
    tag: str,
    tag_oid: str,
    commit: str,
    release_id: int,
    receipt_created: datetime,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(API_ROLES):
        raise ReleaseReceiptError("exactly four GitHub API responses are required")
    results: dict[str, dict[str, Any]] = {}
    observed_roles: list[str] = []
    server_dates: list[datetime] = []
    captured_dates: list[datetime] = []
    for index, raw_record in enumerate(value):
        record = _mapping(
            raw_record,
            {
                "role",
                "requestURL",
                "statusCode",
                "serverDate",
                "capturedAt",
                "responseHeaders",
                "responseBody",
            },
            label=f"GitHub API response {index}",
        )
        role = record["role"]
        if role not in API_ROLES or role in results:
            raise ReleaseReceiptError("GitHub API response roles are invalid or duplicated")
        observed_roles.append(role)
        if record["statusCode"] != 200:
            raise ReleaseReceiptError("GitHub API response was not HTTP 200")
        expected_url = _response_endpoint(
            role,
            api_base=api_base,
            tag=tag,
            tag_oid=tag_oid,
            commit=commit,
            release_id=release_id,
        )
        if record["requestURL"] != expected_url:
            raise ReleaseReceiptError(f"GitHub {role} request URL differs")
        header_bytes = _archived_bytes(
            record["responseHeaders"],
            label=f"GitHub {role} response headers",
            maximum_bytes=MAXIMUM_HEADER_BYTES,
        )
        fields = _parse_http_headers(header_bytes, expected_status=200)
        raw_server_date = _server_date(fields["date"][0])
        declared_server_date = _utc(record["serverDate"], label=f"GitHub {role} serverDate")
        captured_at = _utc(record["capturedAt"], label=f"GitHub {role} capturedAt")
        if raw_server_date != declared_server_date:
            raise ReleaseReceiptError(f"GitHub {role} serverDate differs from Date header")
        if captured_at < declared_server_date or captured_at > receipt_created:
            raise ReleaseReceiptError(f"GitHub {role} capture chronology is invalid")
        server_dates.append(declared_server_date)
        captured_dates.append(captured_at)
        body_bytes = _archived_bytes(
            record["responseBody"],
            label=f"GitHub {role} response body",
            maximum_bytes=MAXIMUM_API_BODY_BYTES,
        )
        body = _parse_json(body_bytes, label=f"GitHub {role} response body")
        if not isinstance(body, dict):
            raise ReleaseReceiptError(f"GitHub {role} response body is not an object")
        results[role] = {"body": body, "serverDate": declared_server_date}
    if tuple(observed_roles) != API_ROLES:
        raise ReleaseReceiptError("GitHub API responses are not in canonical role order")
    if server_dates != sorted(server_dates) or captured_dates != sorted(captured_dates):
        raise ReleaseReceiptError("GitHub API capture timestamps are not monotonic")
    if (
        server_dates[-1] - server_dates[0]
    ).total_seconds() > MAXIMUM_CAPTURE_SPAN_SECONDS or (
        captured_dates[-1] - captured_dates[0]
    ).total_seconds() > MAXIMUM_CAPTURE_SPAN_SECONDS:
        raise ReleaseReceiptError("GitHub API capture span exceeds five minutes")
    return results


def _verify_release_body(
    body: Mapping[str, Any],
    *,
    repository_html: str,
    api_base: str,
    tag: str,
    release_id: int,
    published_at: str,
    assets: list[Mapping[str, Any]],
) -> None:
    expected_api_url = f"{api_base}/releases/{release_id}"
    expected_html_url = f"{repository_html}/releases/tag/{quote(tag, safe='')}"
    required = {
        "id": release_id,
        "url": expected_api_url,
        "html_url": expected_html_url,
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "published_at": published_at,
    }
    if any(body.get(key) != expected for key, expected in required.items()):
        raise ReleaseReceiptError("GitHub release identity/state/timestamp differs")
    api_assets = body.get("assets")
    if not isinstance(api_assets, list) or len(api_assets) != len(assets):
        raise ReleaseReceiptError("GitHub release asset inventory differs")
    by_id: dict[int, Mapping[str, Any]] = {}
    for item in api_assets:
        if not isinstance(item, dict) or type(item.get("id")) is not int:
            raise ReleaseReceiptError("GitHub release asset record is invalid")
        if item["id"] in by_id:
            raise ReleaseReceiptError("GitHub release asset ID is duplicated")
        by_id[item["id"]] = item
    publication_time = _utc(published_at, label="release publishedAt")
    for asset in assets:
        item = by_id.get(asset["assetId"])
        if item is None:
            raise ReleaseReceiptError("required asset is absent from GitHub release")
        expected = {
            "id": asset["assetId"],
            "name": asset["name"],
            "url": asset["apiURL"],
            "browser_download_url": asset["downloadURL"],
            "state": "uploaded",
            "size": asset["bytes"],
            "digest": f"sha256:{asset['sha256']}",
        }
        if any(item.get(key) != wanted for key, wanted in expected.items()):
            raise ReleaseReceiptError("GitHub release asset bytes/digest/URL differ")
        created = _utc(item.get("created_at"), label="GitHub asset created_at")
        updated = _utc(item.get("updated_at"), label="GitHub asset updated_at")
        if created > updated or updated > publication_time:
            raise ReleaseReceiptError("GitHub release asset chronology is invalid")


def _verify_tag_api(
    responses: Mapping[str, Mapping[str, Any]],
    *,
    api_base: str,
    tag: str,
    tag_oid: str,
    commit: str,
    signed_payload: bytes,
    signature: bytes,
) -> None:
    ref = responses["tag-ref"]["body"]
    ref_object = ref.get("object") if isinstance(ref, dict) else None
    if (
        ref.get("ref") != f"refs/tags/{tag}"
        or not isinstance(ref_object, dict)
        or ref_object.get("type") != "tag"
        or ref_object.get("sha") != tag_oid
        or ref_object.get("url") != f"{api_base}/git/tags/{tag_oid}"
    ):
        raise ReleaseReceiptError("GitHub tag ref is missing, lightweight, or retargeted")

    tag_body = responses["tag-object"]["body"]
    target = tag_body.get("object") if isinstance(tag_body, dict) else None
    verification = tag_body.get("verification") if isinstance(tag_body, dict) else None
    if (
        tag_body.get("sha") != tag_oid
        or tag_body.get("tag") != tag
        or tag_body.get("url") != f"{api_base}/git/tags/{tag_oid}"
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != commit
        or target.get("url") != f"{api_base}/git/commits/{commit}"
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        raise ReleaseReceiptError("GitHub annotated-tag verification is not valid")
    try:
        api_payload = verification.get("payload").encode("utf-8", "strict")
        api_signature = verification.get("signature").encode("ascii", "strict")
    except (AttributeError, UnicodeEncodeError) as error:
        raise ReleaseReceiptError("GitHub tag signature/payload archive is invalid") from error
    if api_payload != signed_payload or api_signature != signature:
        raise ReleaseReceiptError("GitHub verified signature bytes differ from raw tag object")
    verified_at = _utc(
        verification.get("verified_at"), label="GitHub signature verified_at"
    )
    if verified_at > responses["tag-object"]["serverDate"]:
        raise ReleaseReceiptError("GitHub signature verification timestamp is in the future")

    commit_body = responses["commit"]["body"]
    tree_body = commit_body.get("tree") if isinstance(commit_body, dict) else None
    if (
        commit_body.get("sha") != commit
        or commit_body.get("url") != f"{api_base}/git/commits/{commit}"
        or not isinstance(tree_body, dict)
    ):
        raise ReleaseReceiptError("GitHub commit identity differs")


def _validate_asset_records(
    value: Any,
    *,
    kind: str,
    repository_html: str,
    api_base: str,
    tag: str,
) -> list[Mapping[str, Any]]:
    expected_roles = REQUIRED_ASSET_ROLES[kind]
    if not isinstance(value, list) or len(value) != len(expected_roles):
        raise ReleaseReceiptError("required release asset role set is incomplete")
    assets: list[Mapping[str, Any]] = []
    observed_roles: list[str] = []
    ids: set[int] = set()
    names: set[str] = set()
    for index, raw in enumerate(value):
        asset = _mapping(
            raw,
            {"role", "assetId", "name", "apiURL", "downloadURL", "bytes", "sha256"},
            label=f"required asset {index}",
        )
        role = asset["role"]
        observed_roles.append(role)
        if type(asset["assetId"]) is not int or asset["assetId"] <= 0:
            raise ReleaseReceiptError("release asset ID must be a positive integer")
        if asset["assetId"] in ids:
            raise ReleaseReceiptError("release asset ID is duplicated")
        ids.add(asset["assetId"])
        name = asset["name"]
        if not isinstance(name, str) or ASSET_NAME.fullmatch(name) is None or name in {".", ".."}:
            raise ReleaseReceiptError("release asset name is not portable")
        required_name = REQUIRED_ROLE_FILENAMES.get(role)
        if required_name is not None and name != required_name:
            raise ReleaseReceiptError(
                f"release asset filename differs for role {role}"
            )
        if name in names:
            raise ReleaseReceiptError("release asset name is duplicated")
        names.add(name)
        if type(asset["bytes"]) is not int or not 0 <= asset["bytes"] <= MAXIMUM_ASSET_BYTES:
            raise ReleaseReceiptError("release asset byte count is invalid")
        _digest(asset["sha256"], label="release asset SHA-256")
        expected_api = f"{api_base}/releases/assets/{asset['assetId']}"
        expected_download = (
            f"{repository_html}/releases/download/{quote(tag, safe='')}/{quote(name, safe='')}"
        )
        if asset["apiURL"] != expected_api or asset["downloadURL"] != expected_download:
            raise ReleaseReceiptError("release asset URL differs")
        assets.append(asset)
    if tuple(observed_roles) != expected_roles:
        raise ReleaseReceiptError("required release assets are not in the exact role order")
    return assets


def _verify_local_assets(root: Path, assets: list[Mapping[str, Any]]) -> tuple[tuple[str, str], ...]:
    absolute = Path(os.path.abspath(os.fspath(root)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ReleaseReceiptError("release asset root is not a safe directory") from error
    try:
        observed_names = os.listdir(descriptor)
        expected_names = {asset["name"] for asset in assets}
        if set(observed_names) != expected_names or len(observed_names) != len(expected_names):
            raise ReleaseReceiptError("local release asset inventory differs")
        verified: list[tuple[str, str]] = []
        verified_identities: dict[str, tuple[int, int, int, int]] = {}
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        for asset in assets:
            name = asset["name"]
            try:
                file_descriptor = os.open(name, file_flags, dir_fd=descriptor)
            except OSError as error:
                raise ReleaseReceiptError(f"release asset is not a no-follow file: {name}") from error
            try:
                before = os.fstat(file_descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_size != asset["bytes"]:
                    raise ReleaseReceiptError(f"release asset size/type differs: {name}")
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = os.read(file_descriptor, READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
                    observed += len(chunk)
                    if observed > asset["bytes"]:
                        raise ReleaseReceiptError(f"release asset grew while reading: {name}")
                after = os.fstat(file_descriptor)
                before_identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                )
                after_identity = (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
                if before_identity != after_identity or observed != before.st_size:
                    raise ReleaseReceiptError(f"release asset changed while reading: {name}")
                if digest.hexdigest() != asset["sha256"]:
                    raise ReleaseReceiptError(f"release asset SHA-256 differs: {name}")
                verified_identities[name] = after_identity
                verified.append((name, digest.hexdigest()))
            finally:
                os.close(file_descriptor)
        if set(os.listdir(descriptor)) != expected_names:
            raise ReleaseReceiptError("release asset directory changed during verification")
        for name, expected_identity in verified_identities.items():
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise ReleaseReceiptError(
                    f"release asset disappeared after verification: {name}"
                ) from error
            observed_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            )
            if not stat.S_ISREG(metadata.st_mode) or observed_identity != expected_identity:
                raise ReleaseReceiptError(
                    f"release asset was replaced after verification: {name}"
                )
        return tuple(verified)
    finally:
        os.close(descriptor)


def _verify_release_receipt(
    raw_receipt: bytes,
    asset_root: Path,
    *,
    expected_repository: str,
    expected_kind: str,
    expected_tag: str,
    expected_commit: str,
    expected_tree: str,
    expected_deadline: str,
    expected_signature_type: str,
    expected_key_fingerprint: str,
    expected_public_key_sha256: str,
    trusted_ssh_public_key_path: Path | None,
    trusted_ssh_allowed_signers_path: Path | None,
    expected_publication_relation: str,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ),
) -> VerifiedReleaseReceipt:
    """Common verifier with one explicit, fail-closed publication relation."""

    receipt = _load_canonical_receipt(raw_receipt)
    root = _mapping(
        receipt,
        {
            "schemaVersion",
            "suiteId",
            "githubAPIVersion",
            "repository",
            "kind",
            "tag",
            "release",
            "source",
            "annotatedTag",
            "signatureVerification",
            "githubReleaseAttestation",
            "requiredAssets",
            "githubAPIResponses",
            "receiptCreatedAt",
            "contentSHA256",
        },
        label="release receipt",
    )
    if (
        root["schemaVersion"] != SCHEMA_VERSION
        or root["suiteId"] != SUITE_ID
        or root["githubAPIVersion"] != GITHUB_API_VERSION
    ):
        raise ReleaseReceiptError("release receipt schema/suite/API version differs")
    digest = _digest(root["contentSHA256"], label="release receipt contentSHA256")
    unsigned = dict(root)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != digest:
        raise ReleaseReceiptError("release receipt contentSHA256 mismatch")
    _owner, _name, repository_html, api_base = _repository(
        root["repository"], expected=expected_repository
    )
    if expected_kind not in KINDS or root["kind"] != expected_kind:
        raise ReleaseReceiptError("release kind differs")
    tag = root["tag"]
    if (
        not isinstance(expected_tag, str)
        or TAG.fullmatch(expected_tag) is None
        or expected_tag.endswith(".lock")
        or tag != expected_tag
    ):
        raise ReleaseReceiptError("release tag differs or is unsafe")
    commit = _oid(expected_commit, label="expected commit")
    tree = _oid(expected_tree, label="expected tree")
    deadline = _utc(expected_deadline, label="expected release deadline")
    if expected_signature_type != "SSH":
        raise ReleaseReceiptError(
            "offline cryptographic release verification supports only SSH"
        )
    fingerprint_pattern = SSH_FINGERPRINT
    if (
        not isinstance(expected_key_fingerprint, str)
        or fingerprint_pattern.fullmatch(expected_key_fingerprint) is None
    ):
        raise ReleaseReceiptError("expected signing-key fingerprint is invalid")
    public_key_sha256 = _digest(
        expected_public_key_sha256, label="expected signing public-key SHA-256"
    )
    trusted_public_key = (
        TRACKED_SSH_PUBLIC_KEY_PATH
        if trusted_ssh_public_key_path is None
        else trusted_ssh_public_key_path
    )
    if not isinstance(trusted_public_key, (str, os.PathLike)):
        raise ReleaseReceiptError("trusted SSH public-key path is invalid")
    trusted_public_key = Path(trusted_public_key)
    trusted_allowed_signers = (
        TRACKED_SSH_ALLOWED_SIGNERS_PATH
        if trusted_ssh_allowed_signers_path is None
        else trusted_ssh_allowed_signers_path
    )
    if not isinstance(trusted_allowed_signers, (str, os.PathLike)):
        raise ReleaseReceiptError("trusted SSH allowed_signers path is invalid")
    trusted_allowed_signers = Path(trusted_allowed_signers)
    receipt_created = _utc(root["receiptCreatedAt"], label="receiptCreatedAt")

    release = _mapping(
        root["release"],
        {"id", "apiURL", "htmlURL", "publishedAt", "deadline"},
        label="release",
    )
    release_id = release["id"]
    if type(release_id) is not int or release_id <= 0:
        raise ReleaseReceiptError("release ID must be a positive immutable ID")
    expected_release_api = f"{api_base}/releases/{release_id}"
    expected_release_html = f"{repository_html}/releases/tag/{quote(tag, safe='')}"
    if release["apiURL"] != expected_release_api or release["htmlURL"] != expected_release_html:
        raise ReleaseReceiptError("release ID/URLs differ")
    if release["deadline"] != expected_deadline:
        raise ReleaseReceiptError("release deadline differs from preregistration")
    published = _utc(release["publishedAt"], label="release publishedAt")
    if expected_publication_relation == "STRICTLY_BEFORE_DEADLINE":
        pass
    elif expected_publication_relation == "AT_OR_AFTER_DEADLINE":
        if expected_kind != "evidence":
            raise ReleaseReceiptError(
                "late-publication observation is permitted only for evidence"
            )
    else:
        raise ReleaseReceiptError("publication relation is unsupported")

    source = _mapping(
        root["source"],
        {"commit", "tree", "commitObject"},
        label="source",
    )
    if source["commit"] != commit or source["tree"] != tree:
        raise ReleaseReceiptError("release source commit/tree differs")
    commit_record = _mapping(
        source["commitObject"],
        {"oid", "rawPayload"},
        label="commit object",
    )
    if commit_record["oid"] != commit:
        raise ReleaseReceiptError("raw commit object OID differs")
    commit_payload = _archived_bytes(
        commit_record["rawPayload"],
        label="raw commit object payload",
        maximum_bytes=MAXIMUM_COMMIT_BYTES,
    )
    if _git_object_oid("commit", commit_payload) != commit:
        raise ReleaseReceiptError("raw commit object hash differs")
    if _parse_commit_object(commit_payload) != tree:
        raise ReleaseReceiptError("raw commit object tree differs")

    annotated_tag = _mapping(
        root["annotatedTag"],
        {"objectOID", "targetType", "targetCommit", "rawPayload"},
        label="annotated tag",
    )
    tag_oid = _oid(annotated_tag["objectOID"], label="annotated tag object OID")
    if annotated_tag["targetType"] != "commit" or annotated_tag["targetCommit"] != commit:
        raise ReleaseReceiptError("annotated tag target differs")
    tag_payload = _archived_bytes(
        annotated_tag["rawPayload"],
        label="raw annotated tag payload",
        maximum_bytes=MAXIMUM_TAG_BYTES,
    )
    if _git_object_oid("tag", tag_payload) != tag_oid:
        raise ReleaseReceiptError("raw annotated tag object hash differs")
    signature_receipt = _mapping(
        root["signatureVerification"],
        {
            "status",
            "signatureType",
            "method",
            "toolVersion",
            "exitCode",
            "trustPolicy",
            "keyFingerprint",
            "publicKeySHA256",
            "tagObjectOID",
            "targetCommit",
            "verifiedAt",
            "transcript",
        },
        label="signature verification receipt",
    )
    if (
        signature_receipt["status"] != "VERIFIED"
        or signature_receipt["signatureType"] != expected_signature_type
        or signature_receipt["method"] != "git verify-tag"
        or signature_receipt["exitCode"] != 0
        or signature_receipt["trustPolicy"]
        != "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH"
        or signature_receipt["keyFingerprint"] != expected_key_fingerprint
        or signature_receipt["publicKeySHA256"] != public_key_sha256
        or signature_receipt["tagObjectOID"] != tag_oid
        or signature_receipt["targetCommit"] != commit
    ):
        raise ReleaseReceiptError("annotated tag signature is unsigned or unverified")
    tag_target, signed_payload, signature = _parse_signed_tag(
        tag_payload,
        expected_tag=tag,
        signature_type=expected_signature_type,
    )
    if tag_target != commit:
        raise ReleaseReceiptError("raw annotated tag targets another commit")
    _verify_archived_ssh_signature(
        signed_payload=signed_payload,
        signature=signature,
        trusted_public_key_path=trusted_public_key,
        trusted_allowed_signers_path=trusted_allowed_signers,
        expected_public_key_sha256=public_key_sha256,
        expected_key_fingerprint=expected_key_fingerprint,
    )
    tool_version = signature_receipt["toolVersion"]
    if not isinstance(tool_version, str) or not 1 <= len(tool_version) <= 256:
        raise ReleaseReceiptError("signature verifier version is invalid")
    verified_at = _utc(signature_receipt["verifiedAt"], label="signature verifiedAt")
    if verified_at > receipt_created:
        raise ReleaseReceiptError("signature verification occurred after receipt creation")
    transcript = _archived_bytes(
        signature_receipt["transcript"],
        label="signature verification transcript",
        maximum_bytes=MAXIMUM_TRANSCRIPT_BYTES,
    )
    if not transcript:
        raise ReleaseReceiptError("signature verification transcript is empty")

    assets = _validate_asset_records(
        root["requiredAssets"],
        kind=expected_kind,
        repository_html=repository_html,
        api_base=api_base,
        tag=tag,
    )
    responses = _validate_api_responses(
        root["githubAPIResponses"],
        api_base=api_base,
        tag=tag,
        tag_oid=tag_oid,
        commit=commit,
        release_id=release_id,
        receipt_created=receipt_created,
    )
    _verify_tag_api(
        responses,
        api_base=api_base,
        tag=tag,
        tag_oid=tag_oid,
        commit=commit,
        signed_payload=signed_payload,
        signature=signature,
    )
    commit_tree = responses["commit"]["body"].get("tree")
    if not isinstance(commit_tree, dict) or commit_tree.get("sha") != tree:
        raise ReleaseReceiptError("GitHub commit response tree differs")
    _verify_release_body(
        responses["release"]["body"],
        repository_html=repository_html,
        api_base=api_base,
        tag=tag,
        release_id=release_id,
        published_at=release["publishedAt"],
        assets=assets,
    )
    if published > responses["release"]["serverDate"]:
        raise ReleaseReceiptError("GitHub release publication time is after response server time")
    asset_digests = _verify_local_assets(asset_root, assets)
    try:
        release_attestation = verify_attestation_record(
            root["githubReleaseAttestation"],
            expected_repository=expected_repository,
            expected_release_id=release_id,
            expected_tag=tag,
            expected_commit=commit,
            expected_tag_oid=tag_oid,
            expected_assets=asset_digests,
            expected_published_at=release["publishedAt"],
            expected_receipt_created_at=root["receiptCreatedAt"],
            expected_deadline=expected_deadline,
            expected_attestation_relation=expected_publication_relation,
        )
    except ReleaseAttestationError as error:
        raise ReleaseReceiptError(
            "GitHub immutable-release attestation failed binding replay"
        ) from error
    if cryptographic_attestation_verifier is None or not hasattr(
        cryptographic_attestation_verifier, "verify"
    ):
        raise ReleaseReceiptError(
            "independent cryptographic release-attestation verifier is required"
        )
    try:
        validate_cryptographic_verification_record(
            root["githubReleaseAttestation"][
                "offlineCryptographicVerification"
            ],
            expected_bundle_sha256=release_attestation.bundle_sha256,
            expected_attested_at=release_attestation.attested_at,
            expected_assets=asset_digests,
        )
        cryptographic = cryptographic_attestation_verifier.verify(
            attestation_record=root["githubReleaseAttestation"],
            asset_root=asset_root,
            expected_assets=asset_digests,
        )
        validate_cryptographic_verification_record(
            cryptographic.record,
            expected_bundle_sha256=release_attestation.bundle_sha256,
            expected_attested_at=release_attestation.attested_at,
            expected_assets=asset_digests,
        )
    except ReleaseAttestationCryptoError as error:
        raise ReleaseReceiptError(
            "GitHub immutable-release attestation failed cryptographic verification"
        ) from error
    if (
        cryptographic.bundle_sha256 != release_attestation.bundle_sha256
        or cryptographic.raw_output_sha256
        != release_attestation.raw_output_sha256
        or cryptographic.attested_at != release_attestation.attested_at
        or (cryptographic.verified_asset_name, cryptographic.verified_asset_sha256)
        not in asset_digests
    ):
        raise ReleaseReceiptError(
            "cryptographic release-attestation result differs from semantic replay"
        )
    return VerifiedReleaseReceipt(
        repository=expected_repository,
        kind=expected_kind,
        tag=tag,
        release_id=release_id,
        commit=commit,
        tree=tree,
        signature_type=expected_signature_type,
        key_fingerprint=expected_key_fingerprint,
        public_key_sha256=public_key_sha256,
        published_at=release["publishedAt"],
        attested_at=release_attestation.attested_at,
        attestation_bundle_sha256=release_attestation.bundle_sha256,
        attestation_output_sha256=release_attestation.raw_output_sha256,
        receipt_sha256=_sha256(raw_receipt),
        asset_sha256=asset_digests,
    )


def verify_release_receipt(
    raw_receipt: bytes,
    asset_root: Path,
    *,
    expected_repository: str,
    expected_kind: str,
    expected_tag: str,
    expected_commit: str,
    expected_tree: str,
    expected_deadline: str,
    expected_signature_type: str,
    expected_key_fingerprint: str,
    expected_public_key_sha256: str,
    trusted_ssh_public_key_path: Path | None = None,
    trusted_ssh_allowed_signers_path: Path | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedReleaseReceipt:
    """Verify an SSH-signed, GitHub-attested release before its fixed deadline.

    ``publishedAt`` remains an archived API observation.  The normative release
    time is the RFC3161 timestamp verified inside ``githubReleaseAttestation``.
    """

    return _verify_release_receipt(
        raw_receipt,
        asset_root,
        expected_repository=expected_repository,
        expected_kind=expected_kind,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_deadline=expected_deadline,
        expected_signature_type=expected_signature_type,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        trusted_ssh_public_key_path=trusted_ssh_public_key_path,
        trusted_ssh_allowed_signers_path=trusted_ssh_allowed_signers_path,
        expected_publication_relation="STRICTLY_BEFORE_DEADLINE",
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )


def verify_late_release_receipt_for_closeout(
    raw_receipt: bytes,
    asset_root: Path,
    *,
    expected_repository: str,
    expected_tag: str,
    expected_commit: str,
    expected_tree: str,
    expected_deadline: str,
    expected_signature_type: str,
    expected_key_fingerprint: str,
    expected_public_key_sha256: str,
    trusted_ssh_public_key_path: Path | None = None,
    trusted_ssh_allowed_signers_path: Path | None = None,
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> VerifiedReleaseReceipt:
    """Verify an evidence release specifically as invalid due to lateness.

    This entry point requires ``attestedAt >= deadline`` and is deliberately
    named and typed for public closeout only.  It never returns a valid
    scientific evidence-release classification; the ordinary verifier above
    continues to reject the same canonical receipt.
    """

    return _verify_release_receipt(
        raw_receipt,
        asset_root,
        expected_repository=expected_repository,
        expected_kind="evidence",
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_deadline=expected_deadline,
        expected_signature_type=expected_signature_type,
        expected_key_fingerprint=expected_key_fingerprint,
        expected_public_key_sha256=expected_public_key_sha256,
        trusted_ssh_public_key_path=trusted_ssh_public_key_path,
        trusted_ssh_allowed_signers_path=trusted_ssh_allowed_signers_path,
        expected_publication_relation="AT_OR_AFTER_DEADLINE",
        cryptographic_attestation_verifier=cryptographic_attestation_verifier,
    )


__all__ = [
    "API_ROLES",
    "GITHUB_API_VERSION",
    "KINDS",
    "REQUIRED_ASSET_ROLES",
    "REQUIRED_ROLE_FILENAMES",
    "ReleaseReceiptError",
    "SCHEMA_VERSION",
    "SUITE_ID",
    "VerifiedReleaseReceipt",
    "canonical_json_bytes",
    "verify_late_release_receipt_for_closeout",
    "verify_release_receipt",
]
