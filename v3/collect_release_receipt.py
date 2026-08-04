#!/usr/bin/env python3
"""Collect and self-verify one canonical immutable GitHub release receipt.

The collector deliberately uses a direct TLS connection to ``api.github.com``.
It does not consult proxy variables, follow redirects, retry requests, or use a
GitHub client library.  The four canonical endpoints are each requested once.

The output combines an exact archive of the observed API bytes, local Git
object bytes, controlled ``git verify-tag --raw`` transcript, and locally
re-hashed release assets with a GitHub immutable-release attestation.  One
exact pinned GitHub CLI binary performs fresh Sigstore verification and the
collector archives its complete bundle/result output without retry.
``release_receipt.py`` then replays every archived semantic binding offline
before this program creates output; that replay does not claim to recompute
the Sigstore cryptography.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import quote, urlsplit

V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.release_receipt import (
    API_ROLES,
    GITHUB_API_VERSION,
    KINDS,
    REQUIRED_ASSET_ROLES,
    SCHEMA_VERSION,
    SUITE_ID,
    ReleaseReceiptError,
    canonical_json_bytes,
    verify_late_release_receipt_for_closeout,
    verify_release_receipt,
)
from v3.github_release_attestation import (
    GH_CLI_BINARY_BYTES,
    GH_CLI_BINARY_SHA256,
    GH_CLI_VERSION_OUTPUT,
    MAXIMUM_RAW_OUTPUT_BYTES as MAXIMUM_ATTESTATION_OUTPUT_BYTES,
    build_attestation_record,
)
from v3.release_attestation_crypto import (
    PinnedCosignReleaseAttestationVerifier,
)


GITHUB_API_HOST = "api.github.com"
GITHUB_API_PORT = 443
USER_AGENT = "core-lm-release-receipt-collector/1"
ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
OWNER_OR_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z"
)
TAG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
SSH_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
ASSET_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,190}[A-Za-z0-9])?\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MAXIMUM_HEADER_BYTES = 256 * 1024
MAXIMUM_API_BODY_BYTES = 16 * 1024 * 1024
MAXIMUM_PUBLIC_KEY_BYTES = 16 * 1024 * 1024
MAXIMUM_GIT_OBJECT_BYTES = 16 * 1024 * 1024
MAXIMUM_TRANSCRIPT_BYTES = 4 * 1024 * 1024
MAXIMUM_ASSET_BYTES = 2 * 1024 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
SSH_KEYGEN_PATH = Path("/usr/bin/ssh-keygen")


class ReleaseReceiptCollectionError(RuntimeError):
    """Collection failed before a self-verified receipt could be published."""


class SignatureVerificationError(ReleaseReceiptCollectionError):
    """The controlled Git verification did not produce a valid signature."""

    def __init__(self, message: str, record: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.record = dict(record)


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    output: bytes


@dataclass(frozen=True)
class HTTPSCapture:
    status_code: int
    response_headers: bytes
    response_body: bytes
    captured_at: str


class ReleaseAttestationVerifier(Protocol):
    def verify(
        self, *, repository: str, tag: str, token: str | None
    ) -> bytes: ...


class GitRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        merge_stderr: bool = False,
    ) -> CommandResult: ...


class GitHubTransport(Protocol):
    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture: ...


class PinnedGitHubCLIAttestationVerifier:
    """Run the one preregistered GitHub CLI release verifier without ambient state."""

    def __init__(self, executable: Path, *, timeout_seconds: float = 120.0) -> None:
        self._executable = Path(os.path.abspath(os.fspath(executable)))
        if not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 300:
            raise ReleaseReceiptCollectionError("GitHub CLI timeout is invalid")
        self._timeout_seconds = float(timeout_seconds)

    def _identity(self) -> tuple[int, int, int, int]:
        try:
            metadata = os.stat(self._executable, follow_symlinks=False)
        except OSError as error:
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI is unavailable"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
            or metadata.st_size != GH_CLI_BINARY_BYTES
        ):
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI metadata differs"
            )
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    def _verify_binary(self) -> tuple[int, int, int, int]:
        before = self._identity()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._executable, flags)
        except OSError as error:
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI cannot be opened safely"
            ) from error
        try:
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
                if observed > GH_CLI_BINARY_BYTES:
                    raise ReleaseReceiptCollectionError(
                        "pinned GitHub CLI grew while hashing"
                    )
            after_file = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = self._identity()
        after_identity = (
            after_file.st_dev,
            after_file.st_ino,
            after_file.st_size,
            after_file.st_mtime_ns,
        )
        if (
            before != after
            or before != after_identity
            or observed != GH_CLI_BINARY_BYTES
            or digest.hexdigest() != GH_CLI_BINARY_SHA256
        ):
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI bytes or identity differ"
            )
        return before

    def _run(
        self,
        executable: Path,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str],
        maximum_output_bytes: int,
    ) -> bytes:
        try:
            completed = subprocess.run(
                [os.fspath(executable), *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=environment["HOME"],
                env=dict(environment),
                check=False,
                close_fds=True,
                start_new_session=True,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI could not complete"
            ) from error
        if (
            completed.returncode != 0
            or completed.stderr
            or not completed.stdout
            or len(completed.stdout) > maximum_output_bytes
        ):
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI release verification failed"
            )
        return completed.stdout

    def _copy_verified_binary(self, destination: Path) -> tuple[int, int, int, int]:
        before = self._identity()
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        source_flags |= getattr(os, "O_NOFOLLOW", 0)
        source: int | None = None
        try:
            source = os.open(self._executable, source_flags)
            target = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o700,
            )
        except OSError as error:
            if source is not None:
                os.close(source)
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI cannot be copied safely"
            ) from error
        try:
            source_before = os.fstat(source)
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(source, READ_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    if written <= 0:
                        raise ReleaseReceiptCollectionError(
                            "private GitHub CLI copy stalled"
                        )
                    view = view[written:]
                if observed > GH_CLI_BINARY_BYTES:
                    raise ReleaseReceiptCollectionError(
                        "pinned GitHub CLI grew while copying"
                    )
            os.fsync(target)
            source_after = os.fstat(source)
        finally:
            os.close(target)
            os.close(source)
        source_before_identity = (
            source_before.st_dev,
            source_before.st_ino,
            source_before.st_size,
            source_before.st_mtime_ns,
        )
        source_after_identity = (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_mtime_ns,
        )
        if (
            before != source_before_identity
            or before != source_after_identity
            or before != self._identity()
            or observed != GH_CLI_BINARY_BYTES
            or digest.hexdigest() != GH_CLI_BINARY_SHA256
        ):
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI changed while copying"
            )
        return before

    def verify(self, *, repository: str, tag: str, token: str | None) -> bytes:
        with tempfile.TemporaryDirectory(prefix="corelm-gh-release-verify-") as value:
            temporary = Path(value)
            os.chmod(temporary, 0o700)
            private_executable = temporary / "gh"
            before = self._copy_verified_binary(private_executable)
            environment = {
                "HOME": os.fspath(temporary),
                "GH_CONFIG_DIR": os.fspath(temporary / "gh-config"),
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "NO_COLOR": "1",
            }
            if token is not None:
                environment["GH_TOKEN"] = token
            version = self._run(
                private_executable,
                ("--version",),
                environment=environment,
                maximum_output_bytes=4096,
            )
            try:
                version_text = version.decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise ReleaseReceiptCollectionError(
                    "pinned GitHub CLI version output is not ASCII"
                ) from error
            if version_text != GH_CLI_VERSION_OUTPUT:
                raise ReleaseReceiptCollectionError(
                    "pinned GitHub CLI version differs"
                )
            raw = self._run(
                private_executable,
                ("release", "verify", tag, "-R", repository, "--format", "json"),
                environment=environment,
                maximum_output_bytes=MAXIMUM_ATTESTATION_OUTPUT_BYTES,
            )
        if self._identity() != before:
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI changed during verification"
            )
        if token is not None and token.encode("ascii", "strict") in raw:
            raise ReleaseReceiptCollectionError(
                "GitHub CLI echoed the authorization secret"
            )
        return raw


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _archived_bytes(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _strict_json(raw: bytes, *, label: str) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseReceiptCollectionError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseReceiptCollectionError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise ReleaseReceiptCollectionError(f"{label} root is not an object")
    return value


def _validate_repository(repository: str) -> tuple[str, str]:
    if not isinstance(repository, str) or repository.count("/") != 1:
        raise ReleaseReceiptCollectionError("repository must be exact OWNER/REPO")
    owner, name = repository.split("/", 1)
    if (
        OWNER_OR_REPOSITORY.fullmatch(owner) is None
        or OWNER_OR_REPOSITORY.fullmatch(name) is None
        or name.endswith(".git")
    ):
        raise ReleaseReceiptCollectionError("repository is not a portable OWNER/REPO")
    return owner, name


def _validate_common_inputs(
    *,
    repository: str,
    kind: str,
    tag: str,
    commit: str,
    tree: str,
    deadline: str,
    signature_type: str,
    key_fingerprint: str,
    release_id: int,
) -> None:
    _validate_repository(repository)
    if kind not in KINDS:
        raise ReleaseReceiptCollectionError("release kind is unsupported")
    if TAG.fullmatch(tag) is None or tag.endswith(".lock"):
        raise ReleaseReceiptCollectionError("tag is unsafe or non-portable")
    if GIT_OID.fullmatch(commit) is None or GIT_OID.fullmatch(tree) is None:
        raise ReleaseReceiptCollectionError("commit and tree must be full lowercase SHA-1 OIDs")
    if UTC_SECOND.fullmatch(deadline) is None:
        raise ReleaseReceiptCollectionError("deadline must be UTC with whole seconds")
    try:
        datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ReleaseReceiptCollectionError("deadline is not a real timestamp") from error
    if signature_type != "SSH":
        raise ReleaseReceiptCollectionError("signature type must be SSH")
    if SSH_FINGERPRINT.fullmatch(key_fingerprint) is None:
        raise ReleaseReceiptCollectionError("signing-key fingerprint is malformed")
    if type(release_id) is not int or release_id <= 0:
        raise ReleaseReceiptCollectionError("release ID must be a positive integer")


def load_token_from_environment(name: str | None) -> str | None:
    """Read an optional token without copying the ambient environment onward."""

    if name is None:
        return None
    if ENVIRONMENT_NAME.fullmatch(name) is None:
        raise ReleaseReceiptCollectionError("token environment-variable name is invalid")
    token = os.environ.get(name)
    if token is None or not token or "\r" in token or "\n" in token:
        raise ReleaseReceiptCollectionError(
            "requested token environment variable is absent or invalid"
        )
    try:
        token.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ReleaseReceiptCollectionError("GitHub token must be ASCII") from error
    return token


def _safe_read_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ReleaseReceiptCollectionError(f"{label} is not a no-follow file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            raise ReleaseReceiptCollectionError(f"{label} type or size is invalid")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise ReleaseReceiptCollectionError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or observed != before.st_size:
            raise ReleaseReceiptCollectionError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class SubprocessGitRunner:
    """Run only an absolute Git executable with explicit byte capture."""

    def __init__(self, repository_root: Path, *, git_executable: str | None = None) -> None:
        executable = git_executable or shutil.which("git")
        if not executable:
            raise ReleaseReceiptCollectionError("git executable was not found")
        self._executable = os.path.abspath(executable)
        self._repository_root = os.path.abspath(os.fspath(repository_root))
        self._home = tempfile.TemporaryDirectory(prefix="corelm-git-read-")
        clean_home = Path(self._home.name)
        (clean_home / "xdg").mkdir(mode=0o700)
        (clean_home / "gnupg").mkdir(mode=0o700)
        self._default_environment = _minimal_git_environment(clean_home)

    def run(
        self,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        merge_stderr: bool = False,
    ) -> CommandResult:
        if any(not isinstance(argument, str) or "\0" in argument for argument in arguments):
            raise ReleaseReceiptCollectionError("Git argument is invalid")
        command = [self._executable, "-C", self._repository_root, *arguments]
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                env=dict(
                    environment
                    if environment is not None
                    else self._default_environment
                ),
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseReceiptCollectionError("Git command could not complete") from error
        output = completed.stdout
        if not merge_stderr and completed.stderr:
            output += completed.stderr
        if len(output) > MAXIMUM_TRANSCRIPT_BYTES:
            raise ReleaseReceiptCollectionError("Git command output exceeds its byte limit")
        return CommandResult(completed.returncode, output)


def _git_checked(
    runner: GitRunner,
    arguments: Sequence[str],
    *,
    maximum_bytes: int,
) -> bytes:
    result = runner.run(arguments)
    if result.exit_code != 0:
        raise ReleaseReceiptCollectionError("required local Git object is unavailable")
    if not 0 < len(result.output) <= maximum_bytes:
        raise ReleaseReceiptCollectionError("local Git object/identity byte count is invalid")
    return result.output


def _git_identity(
    runner: GitRunner,
    *,
    tag: str,
    expected_commit: str,
    expected_tree: str,
) -> tuple[str, bytes, bytes]:
    tag_oid_raw = _git_checked(
        runner,
        ["rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}"],
        maximum_bytes=128,
    )
    try:
        tag_oid = tag_oid_raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise ReleaseReceiptCollectionError("annotated tag OID is not ASCII") from error
    if GIT_OID.fullmatch(tag_oid) is None:
        raise ReleaseReceiptCollectionError("tag is not one exact annotated SHA-1 object")
    resolved_tree_raw = _git_checked(
        runner,
        ["rev-parse", "--verify", f"{expected_commit}^{{tree}}"],
        maximum_bytes=128,
    )
    try:
        resolved_tree = resolved_tree_raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise ReleaseReceiptCollectionError("commit tree OID is not ASCII") from error
    if resolved_tree != expected_tree:
        raise ReleaseReceiptCollectionError("local commit tree differs from the expected tree")
    commit_payload = _git_checked(
        runner,
        ["cat-file", "commit", expected_commit],
        maximum_bytes=MAXIMUM_GIT_OBJECT_BYTES,
    )
    tag_payload = _git_checked(
        runner,
        ["cat-file", "tag", tag_oid],
        maximum_bytes=MAXIMUM_GIT_OBJECT_BYTES,
    )
    return tag_oid, commit_payload, tag_payload


def _minimal_git_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.defpath,
        "HOME": os.fspath(home),
        "XDG_CONFIG_HOME": os.fspath(home / "xdg"),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _ssh_public_key(public_key: bytes) -> tuple[str, str]:
    try:
        text = public_key.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ReleaseReceiptCollectionError("SSH public key must be ASCII") from error
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReleaseReceiptCollectionError("SSH public-key file must contain one key")
    fields = lines[0].split()
    if len(fields) < 2 or not fields[0].startswith(("ssh-", "ecdsa-")):
        raise ReleaseReceiptCollectionError("SSH public-key record is malformed")
    try:
        blob = base64.b64decode(fields[1].encode("ascii"), validate=True)
    except ValueError as error:
        raise ReleaseReceiptCollectionError("SSH public-key blob is malformed") from error
    if not blob or base64.b64encode(blob).decode("ascii") != fields[1]:
        raise ReleaseReceiptCollectionError("SSH public-key blob is not canonical")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    allowed = f"release-signer {fields[0]} {fields[1]}\n"
    return fingerprint, allowed


def _signature_failure_record(
    *,
    signature_type: str,
    tool_version: str,
    exit_code: int,
    key_fingerprint: str,
    public_key_sha256: str,
    tag_oid: str,
    commit: str,
    verified_at: str,
    transcript: bytes,
) -> dict[str, Any]:
    return {
        "status": "FAILED",
        "signatureType": signature_type,
        "method": "git verify-tag",
        "toolVersion": tool_version,
        "exitCode": exit_code,
        "trustPolicy": "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH",
        "keyFingerprint": key_fingerprint,
        "publicKeySHA256": public_key_sha256,
        "tagObjectOID": tag_oid,
        "targetCommit": commit,
        "verifiedAt": verified_at,
        "transcript": _archived_bytes(transcript),
    }


def _verify_tag_signature(
    runner: GitRunner,
    *,
    tag_oid: str,
    commit: str,
    signature_type: str,
    key_fingerprint: str,
    public_key: bytes,
    public_key_sha256: str,
    now: Callable[[], str],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="corelm-tag-verify-") as raw_home:
        home = Path(raw_home)
        (home / "xdg").mkdir(mode=0o700)
        environment = _minimal_git_environment(home)
        if signature_type != "SSH":
            raise ReleaseReceiptCollectionError("signature type must be SSH")
        observed_fingerprint, allowed_signers = _ssh_public_key(public_key)
        if observed_fingerprint != key_fingerprint:
            raise ReleaseReceiptCollectionError(
                "SSH public key does not match the preregistered fingerprint"
            )
        allowed_path = home / "allowed_signers"
        allowed_path.write_bytes(allowed_signers.encode("ascii"))
        os.chmod(allowed_path, 0o600)
        revocations_path = home / "revoked_signers"
        revocations_path.write_bytes(b"")
        os.chmod(revocations_path, 0o600)
        try:
            ssh_keygen_metadata = os.stat(SSH_KEYGEN_PATH, follow_symlinks=False)
        except OSError as error:
            raise ReleaseReceiptCollectionError(
                "/usr/bin/ssh-keygen is unavailable"
            ) from error
        if (
            not stat.S_ISREG(ssh_keygen_metadata.st_mode)
            or ssh_keygen_metadata.st_mode & 0o111 == 0
        ):
            raise ReleaseReceiptCollectionError(
                "/usr/bin/ssh-keygen is not an executable file"
            )
        arguments = [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_path}",
            "-c",
            f"gpg.ssh.revocationFile={revocations_path}",
            "-c",
            f"gpg.ssh.program={SSH_KEYGEN_PATH}",
        ]
        version_result = runner.run(["--version"], environment=environment)
        try:
            tool_version = version_result.output.decode("utf-8", "strict").strip()
        except UnicodeDecodeError as error:
            raise ReleaseReceiptCollectionError("Git version is not UTF-8") from error
        if version_result.exit_code != 0 or not 0 < len(tool_version) <= 256:
            raise ReleaseReceiptCollectionError("Git version could not be recorded")
        verification = runner.run(
            [*arguments, "verify-tag", "--raw", tag_oid],
            environment=environment,
            merge_stderr=True,
        )
        try:
            ssh_keygen_after = os.stat(SSH_KEYGEN_PATH, follow_symlinks=False)
        except OSError as error:
            raise ReleaseReceiptCollectionError(
                "/usr/bin/ssh-keygen became unavailable"
            ) from error
        ssh_keygen_identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )
        if ssh_keygen_identity(ssh_keygen_after) != ssh_keygen_identity(
            ssh_keygen_metadata
        ):
            raise ReleaseReceiptCollectionError(
                "/usr/bin/ssh-keygen changed during verification"
            )
        transcript = verification.output
        verified_at = now()
        if not transcript or len(transcript) > MAXIMUM_TRANSCRIPT_BYTES:
            raise ReleaseReceiptCollectionError(
                "signature verification transcript is empty or oversized"
            )
        failed = verification.exit_code != 0
        try:
            transcript_text = transcript.decode("utf-8", "strict")
        except UnicodeDecodeError:
            transcript_text = ""
        failed = failed or key_fingerprint not in transcript_text
        if failed:
            failure = _signature_failure_record(
                signature_type=signature_type,
                tool_version=tool_version,
                exit_code=verification.exit_code,
                key_fingerprint=key_fingerprint,
                public_key_sha256=public_key_sha256,
                tag_oid=tag_oid,
                commit=commit,
                verified_at=verified_at,
                transcript=transcript,
            )
            raise SignatureVerificationError(
                "git verify-tag did not verify the preregistered signing key", failure
            )
        return {
            "status": "VERIFIED",
            "signatureType": signature_type,
            "method": "git verify-tag",
            "toolVersion": tool_version,
            "exitCode": 0,
            "trustPolicy": "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH",
            "keyFingerprint": key_fingerprint,
            "publicKeySHA256": public_key_sha256,
            "tagObjectOID": tag_oid,
            "targetCommit": commit,
            "verifiedAt": verified_at,
            "transcript": _archived_bytes(transcript),
        }


def _validate_github_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise ReleaseReceiptCollectionError("GitHub API URL is malformed") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != GITHUB_API_HOST
        or parsed.port not in (None, GITHUB_API_PORT)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/repos/")
    ):
        raise ReleaseReceiptCollectionError("request is outside the exact GitHub API allowlist")
    return parsed.path


def _parse_wire_headers(raw: bytes, *, expected_status: int) -> dict[str, list[str]]:
    if not raw.endswith(b"\r\n\r\n") or len(raw) > MAXIMUM_HEADER_BYTES:
        raise ReleaseReceiptCollectionError("GitHub response header block is incomplete")
    lines = raw[:-4].split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/1\.1 [0-9]{3}(?: [^\r\n]*)?", lines[0]) is None:
        raise ReleaseReceiptCollectionError("GitHub response status line is invalid")
    if int(lines[0].split(b" ", 2)[1]) != expected_status:
        raise ReleaseReceiptCollectionError("GitHub response status differs")
    fields: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or HEADER_NAME.fullmatch(name) is None or value[:1] not in {b"", b" "}:
            raise ReleaseReceiptCollectionError("GitHub response header is malformed")
        key = name.decode("ascii").lower()
        fields.setdefault(key, []).append(value.lstrip(b" ").decode("latin-1"))
    return fields


class DirectGitHubTransport:
    """One direct HTTP/1.1 request per call; no proxy, redirect, or retry path."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        if not 0 < timeout_seconds <= 120:
            raise ReleaseReceiptCollectionError("HTTP timeout must be in (0, 120] seconds")
        self._timeout_seconds = timeout_seconds
        self._now = now

    @staticmethod
    def _read_more(connection: ssl.SSLSocket, deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReleaseReceiptCollectionError("GitHub request exceeded total timeout")
        connection.settimeout(remaining)
        try:
            return connection.recv(READ_CHUNK_BYTES)
        except (OSError, TimeoutError) as error:
            raise ReleaseReceiptCollectionError("GitHub TLS response read failed") from error

    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture:
        path = _validate_github_url(url)
        if token is not None:
            try:
                token.encode("ascii", "strict")
            except UnicodeEncodeError as error:
                raise ReleaseReceiptCollectionError("GitHub token is invalid") from error
            if not token or "\r" in token or "\n" in token:
                raise ReleaseReceiptCollectionError("GitHub token is invalid")
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {GITHUB_API_HOST}",
            f"User-Agent: {USER_AGENT}",
            "Accept: application/vnd.github+json",
            "Accept-Encoding: identity",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "Connection: close",
        ]
        if token is not None:
            headers.append(f"Authorization: Bearer {token}")
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        deadline = time.monotonic() + self._timeout_seconds
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["http/1.1"])
        try:
            raw_socket = socket.create_connection(
                (GITHUB_API_HOST, GITHUB_API_PORT), timeout=self._timeout_seconds
            )
            with raw_socket:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReleaseReceiptCollectionError(
                        "GitHub request exceeded total timeout"
                    )
                raw_socket.settimeout(remaining)
                with context.wrap_socket(raw_socket, server_hostname=GITHUB_API_HOST) as tls:
                    selected = tls.selected_alpn_protocol()
                    if selected not in (None, "http/1.1"):
                        raise ReleaseReceiptCollectionError(
                            "GitHub TLS negotiated an unexpected application protocol"
                        )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReleaseReceiptCollectionError(
                            "GitHub request exceeded total timeout"
                        )
                    tls.settimeout(remaining)
                    tls.sendall(request_bytes)
                    received = bytearray()
                    while b"\r\n\r\n" not in received:
                        chunk = self._read_more(tls, deadline)
                        if not chunk:
                            raise ReleaseReceiptCollectionError(
                                "GitHub response ended before its headers"
                            )
                        received.extend(chunk)
                        if len(received) > MAXIMUM_HEADER_BYTES + MAXIMUM_API_BODY_BYTES:
                            raise ReleaseReceiptCollectionError("GitHub response is oversized")
                    raw_header, initial = bytes(received).split(b"\r\n\r\n", 1)
                    raw_header += b"\r\n\r\n"
                    status_match = re.match(rb"HTTP/1\.1 ([0-9]{3})(?: [^\r\n]*)?\r\n", raw_header)
                    if status_match is None:
                        raise ReleaseReceiptCollectionError("GitHub status line is invalid")
                    status = int(status_match.group(1))
                    fields = _parse_wire_headers(raw_header, expected_status=status)
                    if status != 200:
                        raise ReleaseReceiptCollectionError(
                            "GitHub returned non-200; redirects and retries are forbidden"
                        )
                    content_encoding = fields.get("content-encoding", ["identity"])
                    if len(content_encoding) != 1 or content_encoding[0].lower() not in {
                        "",
                        "identity",
                    }:
                        raise ReleaseReceiptCollectionError(
                            "compressed GitHub responses are not accepted"
                        )
                    transfer = fields.get("transfer-encoding", [])
                    lengths = fields.get("content-length", [])
                    if transfer and lengths:
                        raise ReleaseReceiptCollectionError(
                            "GitHub response has ambiguous body framing"
                        )
                    if transfer:
                        if len(transfer) != 1 or transfer[0].lower() != "chunked":
                            raise ReleaseReceiptCollectionError(
                                "unsupported GitHub transfer encoding"
                            )
                        body = self._read_chunked(tls, bytearray(initial), deadline)
                    elif lengths:
                        if len(lengths) != 1 or not lengths[0].isdigit():
                            raise ReleaseReceiptCollectionError(
                                "GitHub Content-Length is invalid"
                            )
                        length = int(lengths[0])
                        if length > MAXIMUM_API_BODY_BYTES:
                            raise ReleaseReceiptCollectionError("GitHub body is oversized")
                        body_buffer = bytearray(initial)
                        while len(body_buffer) < length:
                            chunk = self._read_more(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                            if len(body_buffer) > length:
                                raise ReleaseReceiptCollectionError(
                                    "GitHub sent bytes beyond Content-Length"
                                )
                        if len(body_buffer) != length:
                            raise ReleaseReceiptCollectionError(
                                "GitHub body ended before Content-Length"
                            )
                        body = bytes(body_buffer)
                    else:
                        body_buffer = bytearray(initial)
                        while True:
                            chunk = self._read_more(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                            if len(body_buffer) > MAXIMUM_API_BODY_BYTES:
                                raise ReleaseReceiptCollectionError("GitHub body is oversized")
                        body = bytes(body_buffer)
        except ReleaseReceiptCollectionError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as error:
            raise ReleaseReceiptCollectionError("direct GitHub TLS request failed") from error
        return HTTPSCapture(status, raw_header, body, self._now())

    def _read_chunked(
        self,
        connection: ssl.SSLSocket,
        buffer: bytearray,
        deadline: float,
    ) -> bytes:
        body = bytearray()

        def ensure(marker: bytes) -> None:
            while marker not in buffer:
                chunk = self._read_more(connection, deadline)
                if not chunk:
                    raise ReleaseReceiptCollectionError("chunked GitHub body is truncated")
                buffer.extend(chunk)
                if len(buffer) + len(body) > MAXIMUM_API_BODY_BYTES + MAXIMUM_HEADER_BYTES:
                    raise ReleaseReceiptCollectionError("chunked GitHub body is oversized")

        while True:
            ensure(b"\r\n")
            raw_size, _, remainder = bytes(buffer).partition(b"\r\n")
            buffer[:] = remainder
            raw_size = raw_size.split(b";", 1)[0]
            if not raw_size or re.fullmatch(rb"[0-9A-Fa-f]+", raw_size) is None:
                raise ReleaseReceiptCollectionError("GitHub chunk size is invalid")
            size = int(raw_size, 16)
            if size == 0:
                ensure(b"\r\n")
                trailer, _, remainder = bytes(buffer).partition(b"\r\n")
                if trailer or remainder:
                    raise ReleaseReceiptCollectionError(
                        "GitHub chunk trailers/extra bytes are not accepted"
                    )
                break
            if len(body) + size > MAXIMUM_API_BODY_BYTES:
                raise ReleaseReceiptCollectionError("chunked GitHub body is oversized")
            while len(buffer) < size + 2:
                chunk = self._read_more(connection, deadline)
                if not chunk:
                    raise ReleaseReceiptCollectionError("GitHub chunk is truncated")
                buffer.extend(chunk)
            body.extend(buffer[:size])
            if buffer[size : size + 2] != b"\r\n":
                raise ReleaseReceiptCollectionError("GitHub chunk terminator is invalid")
            del buffer[: size + 2]
        return bytes(body)


def _response_record(role: str, url: str, capture: HTTPSCapture) -> dict[str, Any]:
    if capture.status_code != 200:
        raise ReleaseReceiptCollectionError(
            "GitHub returned non-200; redirects and retries are forbidden"
        )
    fields = _parse_wire_headers(capture.response_headers, expected_status=200)
    for required in (
        "date",
        "content-type",
        "x-github-api-version-selected",
        "x-github-request-id",
    ):
        if len(fields.get(required, [])) != 1:
            raise ReleaseReceiptCollectionError(
                f"GitHub response header {required} must occur exactly once"
            )
    if not fields["content-type"][0].lower().startswith("application/json"):
        raise ReleaseReceiptCollectionError("GitHub response content type is not JSON")
    if fields["x-github-api-version-selected"][0] != GITHUB_API_VERSION:
        raise ReleaseReceiptCollectionError("GitHub selected another API version")
    if not fields["x-github-request-id"][0].strip():
        raise ReleaseReceiptCollectionError("GitHub request ID is empty")
    try:
        server_date = parsedate_to_datetime(fields["date"][0])
    except (TypeError, ValueError) as error:
        raise ReleaseReceiptCollectionError("GitHub Date header is invalid") from error
    if server_date.tzinfo is None:
        raise ReleaseReceiptCollectionError("GitHub Date header has no timezone")
    server_date = server_date.astimezone(timezone.utc)
    if server_date.microsecond:
        raise ReleaseReceiptCollectionError("GitHub Date header is not whole-second")
    if UTC_SECOND.fullmatch(capture.captured_at) is None:
        raise ReleaseReceiptCollectionError("capture timestamp is invalid")
    _strict_json(capture.response_body, label=f"GitHub {role} response")
    return {
        "role": role,
        "requestURL": url,
        "statusCode": 200,
        "serverDate": server_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "capturedAt": capture.captured_at,
        "responseHeaders": _archived_bytes(capture.response_headers),
        "responseBody": _archived_bytes(capture.response_body),
    }


def _parse_asset_bindings(kind: str, values: Sequence[str]) -> dict[str, str]:
    expected = REQUIRED_ASSET_ROLES[kind]
    result: dict[str, str] = {}
    for value in values:
        role, separator, name = value.partition("=")
        if not separator or role not in expected or role in result:
            raise ReleaseReceiptCollectionError(
                "asset binding must be one unique required ROLE=NAME"
            )
        if ASSET_NAME.fullmatch(name) is None or name in {".", ".."}:
            raise ReleaseReceiptCollectionError("asset filename is unsafe or non-portable")
        result[role] = name
    if tuple(role for role in expected if role in result) != expected or len(result) != len(expected):
        raise ReleaseReceiptCollectionError("asset role set is incomplete")
    if len(set(result.values())) != len(result):
        raise ReleaseReceiptCollectionError("asset filenames are duplicated")
    return result


def _hash_asset_directory(
    asset_root: Path,
    *,
    names_by_role: Mapping[str, str],
    release_body: Mapping[str, Any],
    repository: str,
    tag: str,
    kind: str,
) -> list[dict[str, Any]]:
    absolute = Path(os.path.abspath(os.fspath(asset_root)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ReleaseReceiptCollectionError("asset root is not a no-follow directory") from error
    try:
        expected_names = set(names_by_role.values())
        if set(os.listdir(root_descriptor)) != expected_names:
            raise ReleaseReceiptCollectionError("asset directory inventory differs")
        api_assets = release_body.get("assets")
        if not isinstance(api_assets, list):
            raise ReleaseReceiptCollectionError("GitHub release has no asset inventory")
        by_name: dict[str, Mapping[str, Any]] = {}
        for item in api_assets:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise ReleaseReceiptCollectionError("GitHub release asset is malformed")
            if item["name"] in by_name:
                raise ReleaseReceiptCollectionError("GitHub release asset name is duplicated")
            by_name[item["name"]] = item
        result: list[dict[str, Any]] = []
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        html_base = f"https://github.com/{repository}"
        api_base = f"https://api.github.com/repos/{repository}"
        for role in REQUIRED_ASSET_ROLES[kind]:
            name = names_by_role[role]
            api_asset = by_name.get(name)
            if api_asset is None or type(api_asset.get("id")) is not int or api_asset["id"] <= 0:
                raise ReleaseReceiptCollectionError(
                    f"required asset is absent from the GitHub release: {role}"
                )
            try:
                descriptor = os.open(name, file_flags, dir_fd=root_descriptor)
            except OSError as error:
                raise ReleaseReceiptCollectionError(
                    f"asset is not a no-follow file: {name}"
                ) from error
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size < 0
                    or before.st_size > MAXIMUM_ASSET_BYTES
                ):
                    raise ReleaseReceiptCollectionError(f"asset type/size differs: {name}")
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = os.read(descriptor, READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
                    observed += len(chunk)
                    if observed > before.st_size:
                        raise ReleaseReceiptCollectionError(f"asset grew while reading: {name}")
                after = os.fstat(descriptor)
                identity_before = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                )
                identity_after = (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
                if identity_before != identity_after or observed != before.st_size:
                    raise ReleaseReceiptCollectionError(f"asset changed while reading: {name}")
                asset_id = api_asset["id"]
                result.append(
                    {
                        "role": role,
                        "assetId": asset_id,
                        "name": name,
                        "apiURL": f"{api_base}/releases/assets/{asset_id}",
                        "downloadURL": (
                            f"{html_base}/releases/download/{quote(tag, safe='')}/"
                            f"{quote(name, safe='')}"
                        ),
                        "bytes": observed,
                        "sha256": digest.hexdigest(),
                    }
                )
            finally:
                os.close(descriptor)
        if set(os.listdir(root_descriptor)) != expected_names:
            raise ReleaseReceiptCollectionError("asset directory changed during hashing")
        return result
    finally:
        os.close(root_descriptor)


def _exclusive_write(path: Path, raw: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(absolute.parent, parent_flags)
    except OSError as error:
        raise ReleaseReceiptCollectionError("output parent is not a no-follow directory") from error
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent_descriptor)
            created = True
        except OSError as error:
            raise ReleaseReceiptCollectionError("output already exists or is unsafe") from error
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise ReleaseReceiptCollectionError("output write made no progress")
                offset += written
            os.fsync(descriptor)
        except Exception:
            try:
                os.unlink(absolute.name, dir_fd=parent_descriptor)
                created = False
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    if not created:
        raise ReleaseReceiptCollectionError("output could not be durably created")


def _assert_output_absent(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReleaseReceiptCollectionError("output path cannot be inspected") from error
    raise ReleaseReceiptCollectionError("output already exists; collection was not started")


def collect_release_receipt(
    *,
    repository: str,
    kind: str,
    tag: str,
    commit: str,
    tree: str,
    deadline: str,
    signature_type: str,
    key_fingerprint: str,
    public_key_path: Path,
    repository_root: Path,
    release_id: int,
    asset_root: Path,
    asset_bindings: Sequence[str],
    token: str | None = None,
    git_runner: GitRunner | None = None,
    transport: GitHubTransport | None = None,
    release_attestation_verifier: ReleaseAttestationVerifier | None = None,
    github_cli_path: Path | None = None,
    cryptographic_attestation_verifier: Any | None = None,
    cosign_path: Path | None = None,
    now: Callable[[], str] = _utc_now,
    late_closeout_observation: bool = False,
) -> bytes:
    """Collect canonical bytes and verify them offline before returning.

    ``late_closeout_observation`` is a narrow evidence-only path.  It requires
    the server publication timestamp to be at or after the registered evidence
    deadline and produces basis bytes for ``LATE_PUBLICATION_INVALID``.  It
    cannot make those bytes pass the ordinary on-time release verifier.
    """

    if type(late_closeout_observation) is not bool:
        raise ReleaseReceiptCollectionError(
            "late closeout observation selector must be boolean"
        )
    if late_closeout_observation and kind != "evidence":
        raise ReleaseReceiptCollectionError(
            "late closeout observation is permitted only for evidence"
        )

    _validate_common_inputs(
        repository=repository,
        kind=kind,
        tag=tag,
        commit=commit,
        tree=tree,
        deadline=deadline,
        signature_type=signature_type,
        key_fingerprint=key_fingerprint,
        release_id=release_id,
    )
    names_by_role = _parse_asset_bindings(kind, asset_bindings)
    public_key = _safe_read_file(
        public_key_path,
        maximum_bytes=MAXIMUM_PUBLIC_KEY_BYTES,
        label="signing public key",
    )
    public_key_sha256 = hashlib.sha256(public_key).hexdigest()
    runner = git_runner or SubprocessGitRunner(repository_root)
    tag_oid, commit_payload, tag_payload = _git_identity(
        runner,
        tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    signature = _verify_tag_signature(
        runner,
        tag_oid=tag_oid,
        commit=commit,
        signature_type=signature_type,
        key_fingerprint=key_fingerprint,
        public_key=public_key,
        public_key_sha256=public_key_sha256,
        now=now,
    )
    owner, name = _validate_repository(repository)
    html_base = f"https://github.com/{owner}/{name}"
    api_base = f"https://api.github.com/repos/{owner}/{name}"
    endpoints = {
        "commit": f"{api_base}/git/commits/{commit}",
        "release": f"{api_base}/releases/{release_id}",
        "tag-object": f"{api_base}/git/tags/{tag_oid}",
        "tag-ref": f"{api_base}/git/ref/tags/{quote(tag, safe='')}",
    }
    client = transport or DirectGitHubTransport(now=now)
    responses: list[dict[str, Any]] = []
    response_bodies: dict[str, Mapping[str, Any]] = {}
    for role in API_ROLES:
        url = endpoints[role]
        capture = client.request(url, token=token)
        if token is not None:
            secret = token.encode("ascii", "strict")
            if secret in capture.response_headers or secret in capture.response_body:
                raise ReleaseReceiptCollectionError(
                    "GitHub echoed the authorization secret; capture was discarded"
                )
        record = _response_record(role, url, capture)
        responses.append(record)
        response_bodies[role] = _strict_json(
            capture.response_body, label=f"GitHub {role} response"
        )
    release_body = response_bodies["release"]
    published_at = release_body.get("published_at")
    if not isinstance(published_at, str):
        raise ReleaseReceiptCollectionError("GitHub release publication time is absent")
    assets = _hash_asset_directory(
        asset_root,
        names_by_role=names_by_role,
        release_body=release_body,
        repository=repository,
        tag=tag,
        kind=kind,
    )
    if release_attestation_verifier is not None and github_cli_path is not None:
        raise ReleaseReceiptCollectionError(
            "release attestation verifier and GitHub CLI path are mutually exclusive"
        )
    if release_attestation_verifier is None:
        if github_cli_path is None:
            raise ReleaseReceiptCollectionError(
                "pinned GitHub CLI is required for release attestation"
            )
        release_attestation_verifier = PinnedGitHubCLIAttestationVerifier(
            github_cli_path
        )
    attestation_output = release_attestation_verifier.verify(
        repository=repository,
        tag=tag,
        token=token,
    )
    if cryptographic_attestation_verifier is not None and cosign_path is not None:
        raise ReleaseReceiptCollectionError(
            "cryptographic attestation verifier and Cosign path are mutually exclusive"
        )
    if cryptographic_attestation_verifier is None:
        if cosign_path is None:
            raise ReleaseReceiptCollectionError(
                "pinned Cosign is required for offline release-attestation verification"
            )
        cryptographic_attestation_verifier = (
            PinnedCosignReleaseAttestationVerifier(cosign_path)
        )
    provisional_attestation = build_attestation_record(attestation_output, {})
    try:
        cryptographic = cryptographic_attestation_verifier.verify(
            attestation_record=provisional_attestation,
            asset_root=asset_root,
            expected_assets=tuple(
                (asset["name"], asset["sha256"]) for asset in assets
            ),
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ReleaseReceiptCollectionError(
            "independent release-attestation cryptographic verification failed"
        ) from error
    attestation = build_attestation_record(
        attestation_output, cryptographic.record
    )
    receipt_created = now()
    receipt: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "githubAPIVersion": GITHUB_API_VERSION,
        "repository": {
            "slug": repository,
            "htmlURL": html_base,
            "apiURL": api_base,
        },
        "kind": kind,
        "tag": tag,
        "release": {
            "id": release_id,
            "apiURL": endpoints["release"],
            "htmlURL": f"{html_base}/releases/tag/{quote(tag, safe='')}",
            "publishedAt": published_at,
            "deadline": deadline,
        },
        "source": {
            "commit": commit,
            "tree": tree,
            "commitObject": {
                "oid": commit,
                "rawPayload": _archived_bytes(commit_payload),
            },
        },
        "annotatedTag": {
            "objectOID": tag_oid,
            "targetType": "commit",
            "targetCommit": commit,
            "rawPayload": _archived_bytes(tag_payload),
        },
        "signatureVerification": signature,
        "githubReleaseAttestation": attestation,
        "requiredAssets": assets,
        "githubAPIResponses": responses,
        "receiptCreatedAt": receipt_created,
    }
    receipt["contentSHA256"] = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    raw_receipt = canonical_json_bytes(receipt) + b"\n"
    if token is not None and token.encode("ascii", "strict") in raw_receipt:
        raise ReleaseReceiptCollectionError("authorization secret entered receipt bytes")
    try:
        verifier = (
            verify_late_release_receipt_for_closeout
            if late_closeout_observation
            else verify_release_receipt
        )
        verifier_arguments: dict[str, Any] = {
            "expected_repository": repository,
            "expected_tag": tag,
            "expected_commit": commit,
            "expected_tree": tree,
            "expected_deadline": deadline,
            "expected_signature_type": signature_type,
            "expected_key_fingerprint": key_fingerprint,
            "expected_public_key_sha256": public_key_sha256,
        }
        if not late_closeout_observation:
            verifier_arguments["expected_kind"] = kind
        verifier_arguments["cryptographic_attestation_verifier"] = (
            cryptographic_attestation_verifier
        )
        verifier(raw_receipt, asset_root, **verifier_arguments)
    except ReleaseReceiptError as error:
        raise ReleaseReceiptCollectionError(
            "collected bytes failed immediate offline verification"
        ) from error
    return raw_receipt


def collect_release_receipt_to_path(
    *,
    output: Path,
    signature_failure_output: Path | None = None,
    **arguments: Any,
) -> str:
    """Preflight no-overwrite, collect, verify, and durably create output."""

    _assert_output_absent(output)
    if signature_failure_output is not None:
        _assert_output_absent(signature_failure_output)
    try:
        raw = collect_release_receipt(**arguments)
    except SignatureVerificationError as error:
        if signature_failure_output is not None:
            diagnostic = {
                "schemaVersion": "corelm-git-signature-failure-v1",
                **error.record,
            }
            diagnostic["contentSHA256"] = hashlib.sha256(
                canonical_json_bytes(diagnostic)
            ).hexdigest()
            _exclusive_write(
                signature_failure_output,
                canonical_json_bytes(diagnostic) + b"\n",
            )
        raise
    _exclusive_write(output, raw)
    return hashlib.sha256(raw).hexdigest()


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="exact OWNER/REPO")
    parser.add_argument("--kind", choices=sorted(KINDS), required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--deadline", required=True)
    parser.add_argument("--signature-type", choices=("SSH",), required=True)
    parser.add_argument("--key-fingerprint", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--repo-path", type=Path, default=Path.cwd())
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument(
        "--github-cli",
        type=Path,
        required=True,
        help="exact pinned gh 2.97.0 macOS-arm64 executable",
    )
    parser.add_argument(
        "--cosign",
        type=Path,
        required=True,
        help="exact pinned Cosign 3.0.6 executable for offline bundle verification",
    )
    parser.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="ROLE=NAME",
        help="repeat once for every canonical required asset role",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--signature-failure-output",
        type=Path,
        help="exclusive diagnostic output used only when git verify-tag fails",
    )
    parser.add_argument(
        "--token-env",
        help="optional environment-variable name holding a token (value is never printed/stored)",
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument(
        "--late-closeout-observation",
        action="store_true",
        help=(
            "evidence only: archive and verify a release first published at or "
            "after its deadline as closeout basis, never as valid evidence"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        token = load_token_from_environment(args.token_env)
        digest = collect_release_receipt_to_path(
            output=args.output,
            signature_failure_output=args.signature_failure_output,
            repository=args.repository,
            kind=args.kind,
            tag=args.tag,
            commit=args.commit,
            tree=args.tree,
            deadline=args.deadline,
            signature_type=args.signature_type,
            key_fingerprint=args.key_fingerprint,
            public_key_path=args.public_key,
            repository_root=args.repo_path,
            release_id=args.release_id,
            asset_root=args.assets_dir,
            asset_bindings=args.asset,
            github_cli_path=args.github_cli,
            cosign_path=args.cosign,
            token=token,
            transport=DirectGitHubTransport(timeout_seconds=args.timeout_seconds),
            late_closeout_observation=args.late_closeout_observation,
        )
    except SignatureVerificationError as error:
        # Do not emit the transcript by default: it is available to callers as
        # error.record, while the CLI emits only a fixed, secret-independent line.
        print("release receipt collection failed (signature verification)", file=sys.stderr)
        return 2
    except (ReleaseReceiptCollectionError, OSError, ValueError):
        print("release receipt collection failed (fail-closed)", file=sys.stderr)
        return 2
    label = (
        "late evidence observation verified and created"
        if args.late_closeout_observation
        else "release receipt verified and created"
    )
    print(f"{label}: sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CommandResult",
    "DirectGitHubTransport",
    "GitHubTransport",
    "GitRunner",
    "HTTPSCapture",
    "PinnedGitHubCLIAttestationVerifier",
    "ReleaseAttestationVerifier",
    "ReleaseReceiptCollectionError",
    "SignatureVerificationError",
    "collect_release_receipt",
    "collect_release_receipt_to_path",
    "load_token_from_environment",
]
