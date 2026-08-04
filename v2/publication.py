#!/usr/bin/env python3
"""Offline publication gates for the registered design and snapshot releases.

The GitHub receipt verifier establishes the archived release/API/Git-object
contract.  This module adds the two bindings needed by the scientific runner:

* the semantic release-asset roles must contain the exact local inputs that
  will enter the one-shot; and
* the archived SSH signature is cryptographically reverified with the public
  key whose fingerprint and exact bytes were committed in the frozen design.

No network access is performed.  The design release has one Git source
identity: its signed annotated tag must target the exact reviewed and
CI-approved implementation commit/tree recorded in ``labSource``.  The frozen
design and freeze manifest are external immutable release assets, so no later
publication commit is needed or permitted.  This module returns the receipt's
source identity; callers must compare a design receipt to ``labSource`` rather
than accepting a second publication identity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from v2.protocol import canonical_json_bytes, load_json_strict_bytes
from v2.release_receipt import (
    REQUIRED_ASSET_ROLES,
    ReleaseAttestationCryptographicVerifier,
    VerifiedReleaseReceipt,
    verify_release_receipt,
)


REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SSH_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_BOUND_INPUT_BYTES = 2 * 1024 * 1024 * 1024 * 1024
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
SIGNER_IDENTITY = "corelm-crossmodel-livewiki-v2-release"
SOURCE_POLICY = "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE"


class PublicationError(ValueError):
    """A public release is absent, late, unsigned, or byte-inconsistent."""


@dataclass(frozen=True)
class VerifiedPublication:
    receipt: VerifiedReleaseReceipt
    receipt_sha256: str
    source_commit: str
    source_tree: str
    role_sha256: tuple[tuple[str, str], ...]


def require_frozen_lab_publication_source(
    publication: VerifiedPublication,
    design: Mapping[str, Any],
    *,
    kind: str,
) -> None:
    """Require one release tag to target the exact frozen lab commit and tree."""

    release_fields = {
        "design": "designRelease",
        "snapshot": "snapshotRelease",
        "evidence": "evidenceRelease",
        "closeout": "closeoutRelease",
    }
    field = release_fields.get(kind)
    if field is None:
        raise PublicationError("publication source-policy kind is unsupported")
    release = design.get(field)
    if not isinstance(release, dict) or release.get("sourcePolicy") != SOURCE_POLICY:
        raise PublicationError(f"frozen {kind} release source policy differs")
    lab_source = design.get("labSource")
    if not isinstance(lab_source, dict) or lab_source.get("status") != "FROZEN_BOUND":
        raise PublicationError("frozen design lab source binding is absent")
    commit, tree = lab_source.get("commit"), lab_source.get("tree")
    if (
        not isinstance(commit, str)
        or GIT_OID.fullmatch(commit) is None
        or not isinstance(tree, str)
        or GIT_OID.fullmatch(tree) is None
    ):
        raise PublicationError("frozen design lab source commit/tree is invalid")
    if publication.source_commit != commit or publication.source_tree != tree:
        raise PublicationError(
            f"{kind} publication tag does not target the frozen lab commit/tree"
        )


def _physical_absolute_path(path: Path) -> Path:
    """Return an absolute path without resolving caller-controlled symlinks.

    macOS exposes ``/etc``, ``/tmp``, and ``/var`` as fixed system aliases into
    ``/private``.  Translate only those exact, OS-owned aliases so the strict
    component walker remains usable with ordinary macOS temporary paths.  No
    other symlink is resolved or accepted.
    """

    absolute = Path(os.path.abspath(os.fspath(path)))
    if sys.platform != "darwin" or len(absolute.parts) < 2:
        return absolute
    first = absolute.parts[1]
    if first not in {"etc", "tmp", "var"}:
        return absolute
    alias = Path("/") / first
    try:
        metadata = os.lstat(alias)
        target = os.readlink(alias)
    except OSError:
        return absolute
    expected = f"private/{first}"
    if stat.S_ISLNK(metadata.st_mode) and target in {expected, f"/{expected}"}:
        return Path("/private") / first / Path(*absolute.parts[2:])
    return absolute


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _open_parent_chain(
    path: Path, *, label: str
) -> tuple[Path, list[int], list[tuple[int, int, int]]]:
    """Open every parent from ``/`` using anchored no-follow directory FDs."""

    absolute = _physical_absolute_path(path)
    if absolute == Path("/") or not absolute.name:
        raise PublicationError(f"{label} has no regular-file leaf")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: list[int] = []
    identities: list[tuple[int, int, int]] = []
    try:
        descriptor = os.open("/", directory_flags)
        descriptors.append(descriptor)
        root_metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise PublicationError(f"{label} filesystem anchor is not a directory")
        identities.append(_directory_identity(root_metadata))
        for component in absolute.parent.parts[1:]:
            try:
                descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptors[-1],
                )
            except OSError as error:
                raise PublicationError(
                    f"{label} parent component is not a no-follow directory: "
                    f"{component}"
                ) from error
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise PublicationError(
                    f"{label} parent component is not a directory: {component}"
                )
            identities.append(_directory_identity(metadata))
        return absolute, descriptors, identities
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _parents_unchanged(
    descriptors: list[int], identities: list[tuple[int, int, int]], *, label: str
) -> None:
    if len(descriptors) != len(identities):  # pragma: no cover - internal invariant
        raise PublicationError(f"{label} parent-chain invariant failed")
    for descriptor, before in zip(descriptors, identities):
        after = os.fstat(descriptor)
        if not stat.S_ISDIR(after.st_mode) or _directory_identity(after) != before:
            raise PublicationError(f"{label} parent chain changed while being read")


def _close_descriptors(descriptors: list[int]) -> None:
    for descriptor in reversed(descriptors):
        os.close(descriptor)


def _read_regular(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    absolute, parents, parent_identities = _open_parent_chain(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parents[-1])
    except OSError as error:
        _close_descriptors(parents)
        raise PublicationError(f"{label} is not a no-follow regular file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            raise PublicationError(f"{label} size/type is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise PublicationError(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if identity(before) != identity(after) or observed != before.st_size:
            raise PublicationError(f"{label} changed while being read")
        _parents_unchanged(parents, parent_identities, label=label)
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        _close_descriptors(parents)


def _receipt_document(raw: bytes) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label="publication receipt")
    except ValueError as error:
        raise PublicationError(str(error)) from error
    if not isinstance(value, dict) or canonical_json_bytes(value) + b"\n" != raw:
        raise PublicationError("publication receipt is not canonical JSON plus LF")
    return value


def _source_identity(receipt: Mapping[str, Any]) -> tuple[str, str]:
    source = receipt.get("source")
    if not isinstance(source, dict):
        raise PublicationError("publication receipt source binding is absent")
    commit, tree = source.get("commit"), source.get("tree")
    if (
        not isinstance(commit, str)
        or GIT_OID.fullmatch(commit) is None
        or not isinstance(tree, str)
        or GIT_OID.fullmatch(tree) is None
    ):
        raise PublicationError("publication receipt source commit/tree is invalid")
    return commit, tree


def _role_records(receipt: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    records = receipt.get("requiredAssets")
    if not isinstance(records, list):
        raise PublicationError("publication receipt asset inventory is absent")
    result: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("role"), str):
            raise PublicationError("publication receipt asset role is invalid")
        role = record["role"]
        if role in result:
            raise PublicationError("publication receipt asset role is duplicated")
        result[role] = record
    return result


def _require_exact_role_paths(
    kind: str,
    records: Mapping[str, Mapping[str, Any]],
    expected_role_paths: Mapping[str, Path],
) -> None:
    """Require callers to reopen every canonical release role, not a subset."""

    required = REQUIRED_ASSET_ROLES.get(kind)
    if required is None:
        raise PublicationError("publication kind is unsupported")
    required_roles = set(required)
    if set(records) != required_roles or set(expected_role_paths) != required_roles:
        raise PublicationError("expected semantic release-asset roles differ")


def _digest_path(path: Path, *, label: str) -> tuple[int, str]:
    absolute, parents, parent_identities = _open_parent_chain(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parents[-1])
    except OSError as error:
        _close_descriptors(parents)
        raise PublicationError(f"{label} is not a no-follow regular file") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > MAX_BOUND_INPUT_BYTES
        ):
            raise PublicationError(f"{label} size/type is invalid")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > MAX_BOUND_INPUT_BYTES:
                raise PublicationError(f"{label} exceeds its byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
        )
        if identity(before) != identity(after) or observed != before.st_size:
            raise PublicationError(f"{label} changed while hashing")
        _parents_unchanged(parents, parent_identities, label=label)
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)
        _close_descriptors(parents)


def _ssh_signature_parts(receipt: Mapping[str, Any]) -> tuple[bytes, bytes]:
    annotated = receipt.get("annotatedTag")
    raw_record = annotated.get("rawPayload") if isinstance(annotated, dict) else None
    encoded = raw_record.get("dataBase64") if isinstance(raw_record, dict) else None
    if not isinstance(encoded, str):
        raise PublicationError("archived annotated-tag payload is absent")
    try:
        payload = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise PublicationError("archived annotated-tag payload is invalid base64") from error
    if base64.b64encode(payload).decode("ascii") != encoded:
        raise PublicationError("archived annotated-tag payload is noncanonical base64")
    begin = b"-----BEGIN SSH SIGNATURE-----\n"
    end = b"-----END SSH SIGNATURE-----\n"
    offset = payload.find(begin)
    if offset < 0:
        raise PublicationError("annotated tag has no SSH signature")
    signed_payload, signature = payload[:offset], payload[offset:]
    if signature.count(begin) != 1 or signature.count(end) != 1 or not signature.endswith(end):
        raise PublicationError("annotated tag SSH signature armor is malformed")
    return signed_payload, signature


def verify_ssh_signing_key(
    public_key_path: Path,
    *,
    expected_sha256: str,
    expected_fingerprint: str,
) -> bytes:
    """Verify exact public-key bytes and return one normalized authorized-key line."""

    if SHA256.fullmatch(expected_sha256) is None:
        raise PublicationError("expected signing public-key SHA-256 is invalid")
    if SSH_FINGERPRINT.fullmatch(expected_fingerprint) is None:
        raise PublicationError("expected SSH signing-key fingerprint is invalid")
    raw = _read_regular(
        public_key_path,
        maximum_bytes=MAX_PUBLIC_KEY_BYTES,
        label="release signing public key",
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise PublicationError("release signing public-key bytes differ from the design")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise PublicationError("release signing public key is not ASCII") from error
    if not text.endswith("\n") or text.count("\n") != 1:
        raise PublicationError("release signing public key must be one LF-terminated line")
    fields = text[:-1].split()
    if len(fields) not in (2, 3) or fields[0] not in {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "ssh-rsa",
    }:
        raise PublicationError("release signing public-key format is unsupported")
    key_line = (fields[0] + " " + fields[1] + "\n").encode("ascii")
    if not SSH_KEYGEN.is_file():
        raise PublicationError("/usr/bin/ssh-keygen is required for signature verification")
    with tempfile.TemporaryDirectory(prefix="corelm-v2-key-check-") as temporary:
        checked_key = Path(temporary) / "signing-key.pub"
        checked_key.write_bytes(key_line)
        os.chmod(checked_key, 0o400)
        completed = subprocess.run(
            [str(SSH_KEYGEN), "-lf", str(checked_key), "-E", "sha256"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    if completed.returncode != 0:
        raise PublicationError("ssh-keygen rejected the release signing public key")
    output = completed.stdout.decode("ascii", "strict").split()
    if len(output) < 2 or output[1] != expected_fingerprint:
        raise PublicationError("release signing-key fingerprint differs from the design")
    return key_line


def verify_archived_ssh_tag_signature(
    receipt: Mapping[str, Any],
    *,
    public_key_line: bytes,
) -> None:
    """Cryptographically reverify the archived Git SSH signature offline."""

    signed_payload, signature = _ssh_signature_parts(receipt)
    with tempfile.TemporaryDirectory(prefix="corelm-v2-ssh-verify-") as temporary:
        root = Path(temporary)
        allowed = root / "allowed_signers"
        signature_path = root / "tag.sig"
        allowed.write_bytes(SIGNER_IDENTITY.encode("ascii") + b" " + public_key_line)
        signature_path.write_bytes(signature)
        os.chmod(allowed, 0o400)
        os.chmod(signature_path, 0o400)
        completed = subprocess.run(
            [
                str(SSH_KEYGEN),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                SIGNER_IDENTITY,
                "-n",
                "git",
                "-s",
                str(signature_path),
            ],
            input=signed_payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    if completed.returncode != 0:
        raise PublicationError("archived annotated-tag SSH signature is not valid")


def verify_publication(
    receipt_path: Path,
    asset_root: Path,
    *,
    kind: str,
    tag: str,
    deadline: str,
    signing_public_key_path: Path,
    signing_key_fingerprint: str,
    signing_public_key_sha256: str,
    expected_role_paths: Mapping[str, Path],
    cryptographic_attestation_verifier: ReleaseAttestationCryptographicVerifier,
) -> VerifiedPublication:
    """Verify one release receipt, SSH signature, and semantic input bindings."""

    raw = _read_regular(
        receipt_path,
        maximum_bytes=MAX_RECEIPT_BYTES,
        label=f"{kind} publication receipt",
    )
    document = _receipt_document(raw)
    commit, tree = _source_identity(document)
    try:
        verified = verify_release_receipt(
            raw,
            asset_root,
            expected_repository=REPOSITORY,
            expected_kind=kind,
            expected_tag=tag,
            expected_commit=commit,
            expected_tree=tree,
            expected_deadline=deadline,
            expected_signature_type="SSH",
            expected_key_fingerprint=signing_key_fingerprint,
            expected_public_key_sha256=signing_public_key_sha256,
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
    except ValueError as error:
        raise PublicationError(f"{kind} release receipt failed: {error}") from error
    public_key_line = verify_ssh_signing_key(
        signing_public_key_path,
        expected_sha256=signing_public_key_sha256,
        expected_fingerprint=signing_key_fingerprint,
    )
    verify_archived_ssh_tag_signature(document, public_key_line=public_key_line)

    records = _role_records(document)
    _require_exact_role_paths(kind, records, expected_role_paths)
    observed: list[tuple[str, str]] = []
    for role, path in sorted(expected_role_paths.items()):
        size, digest = _digest_path(path, label=f"{kind} release role {role}")
        record = records[role]
        if record.get("bytes") != size or record.get("sha256") != digest:
            raise PublicationError(f"{kind} release role does not bind exact input: {role}")
        observed.append((role, digest))
    return VerifiedPublication(
        receipt=verified,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        source_commit=commit,
        source_tree=tree,
        role_sha256=tuple(observed),
    )


__all__ = [
    "PublicationError",
    "REPOSITORY",
    "SOURCE_POLICY",
    "VerifiedPublication",
    "require_frozen_lab_publication_source",
    "verify_archived_ssh_tag_signature",
    "verify_publication",
    "verify_ssh_signing_key",
]
