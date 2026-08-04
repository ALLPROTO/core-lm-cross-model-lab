#!/usr/bin/env python3
"""Offline cryptographic verification for GitHub immutable-release bundles.

The GitHub CLI collection result is useful evidence only if the archived
Sigstore bundle is independently verified.  This module runs one exact pinned
Cosign binary against one release asset and the complete DSSE bundle, using a
tracked snapshot of GitHub's Sigstore certificate and RFC3161 timestamp roots.
Cosign verifies the DSSE signature, certificate chain, exact SAN, timestamp
signature/chain, and the selected asset digest.  The dependency-free semantic
replay in :mod:`v2.github_release_attestation` then checks every signed subject.

GitHub release attestations contain an RFC3161 timestamp but no Rekor entry or
certificate SCT.  Accordingly the command uses Cosign's private-infrastructure
mode and disables the unavailable SCT check while explicitly requiring signed
timestamps.  This is not a bypass of the DSSE, X.509, or RFC3161 checks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


V2_ROOT = Path(__file__).resolve().parent
TRACKED_GITHUB_TRUSTED_ROOT = V2_ROOT / "trust" / "github" / "trusted_root.json"
TRUSTED_ROOT_BYTES = 28_886
TRUSTED_ROOT_SHA256 = (
    "26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485"
)
COSIGN_VERSION = "v3.0.6"
COSIGN_GIT_COMMIT = "f1ad3ee952313be5d74a49d67ba0aa8d0d5e351f"
COSIGN_BUILD_DATE = "2026-04-06T21:39:58Z"
COSIGN_GO_VERSION = "go1.25.7"
COSIGN_BINARY_VARIANTS = {
    ("Darwin", "arm64"): {
        "platform": "darwin/arm64",
        "bytes": 134_320_242,
        "sha256": (
            "5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084"
        ),
        "url": (
            "https://github.com/sigstore/cosign/releases/download/v3.0.6/"
            "cosign-darwin-arm64"
        ),
    },
    ("Linux", "x86_64"): {
        "platform": "linux/amd64",
        "bytes": 135_178_161,
        "sha256": (
            "c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"
        ),
        "url": (
            "https://github.com/sigstore/cosign/releases/download/v3.0.6/"
            "cosign-linux-amd64"
        ),
    },
}
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"
GITHUB_RELEASE_SAN = "https://dotcom.releases.github.com"
METHOD = "cosign verify-blob-attestation"
TRUST_POLICY = (
    "PINNED_COSIGN_AND_GITHUB_TRUSTED_ROOT;"
    "DSSE_X509_RFC3161_AND_ASSET_DIGEST_VERIFIED;"
    "PRIVATE_INFRASTRUCTURE_WITHOUT_TLOG_OR_SCT"
)
KNOWN_ANSWER_RESULT_SCHEMA = (
    "corelm-release-attestation-crypto-known-answer-result-v1"
)
KNOWN_ANSWER_REPOSITORY = "cli/cli"
KNOWN_ANSWER_TAG = "v2.97.0"
KNOWN_ANSWER_COMMIT = "55dbb4dc6b7edb10b48e3d7fc5bccd32318d1b55"
KNOWN_ANSWER_RELEASE_ID = 362_812_465
KNOWN_ANSWER_ATTESTED_AT = "2026-07-31T02:04:01Z"
KNOWN_ANSWER_BUNDLE_SHA256 = (
    "f4fdea17886e101c41e02213446e1374f83b07d476097b26c45b5021bf5f5477"
)
KNOWN_ANSWER_RAW_OUTPUT_SHA256 = (
    "dd934980d284943275aa2d9c574fdbcc5e3713e38a616ce49ca0ac682040f07c"
)
KNOWN_ANSWER_ASSET_NAME = "gh_2.97.0_checksums.txt"
KNOWN_ANSWER_ASSET_SHA256 = (
    "61905c69ec8660f310814ec98395cdd0c2d07aabf024c597ec45813984a02334"
)
MAXIMUM_ATTESTATION_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_TRANSCRIPT_BYTES = 4096
READ_CHUNK_BYTES = 1024 * 1024
SAFE_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ReleaseAttestationCryptoError(ValueError):
    """The archived release bundle failed independent cryptographic checks."""


@dataclass(frozen=True)
class VerifiedCryptographicAttestation:
    bundle_sha256: str
    raw_output_sha256: str
    attested_at: str
    verified_asset_name: str
    verified_asset_sha256: str
    record: Mapping[str, Any]


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise ReleaseAttestationCryptoError(
            "cryptographic input is not canonical JSON data"
        ) from error


def _mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseAttestationCryptoError(f"{label} fields differ")
    return value


def _decode_base64(value: Any, *, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ReleaseAttestationCryptoError(f"{label} is not base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ReleaseAttestationCryptoError(f"{label} is not canonical base64") from error
    if not 0 < len(raw) <= maximum_bytes:
        raise ReleaseAttestationCryptoError(f"{label} size is invalid")
    if base64.b64encode(raw).decode("ascii") != value:
        raise ReleaseAttestationCryptoError(f"{label} base64 is non-canonical")
    return raw


def _raw_output(record: Any) -> bytes:
    attestation = _mapping(
        record,
        {
            "status",
            "method",
            "trustPolicy",
            "tool",
            "offlineCryptographicVerification",
            "rawVerificationOutput",
        },
        label="GitHub release attestation",
    )
    archived = _mapping(
        attestation["rawVerificationOutput"],
        {"encoding", "bytes", "sha256", "dataBase64"},
        label="attestation output archive",
    )
    if archived["encoding"] != "base64":
        raise ReleaseAttestationCryptoError("attestation output encoding differs")
    raw = _decode_base64(
        archived["dataBase64"],
        label="attestation output",
        maximum_bytes=MAXIMUM_ATTESTATION_OUTPUT_BYTES,
    )
    if (
        type(archived["bytes"]) is not int
        or archived["bytes"] != len(raw)
        or not isinstance(archived["sha256"], str)
        or SHA256.fullmatch(archived["sha256"]) is None
        or hashlib.sha256(raw).hexdigest() != archived["sha256"]
    ):
        raise ReleaseAttestationCryptoError(
            "attestation output byte commitment differs"
        )
    return raw


def _strict_json(raw: bytes, *, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseAttestationCryptoError(
                    f"duplicate key in {label}: {key}"
                )
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseAttestationCryptoError(f"{label} is not strict JSON") from error


def _read_exact_file(
    path: Path, *, expected_bytes: int, expected_sha256: str, label: str
) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ReleaseAttestationCryptoError(f"{label} cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_bytes:
            raise ReleaseAttestationCryptoError(f"{label} metadata differs")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            chunks.append(chunk)
            observed += len(chunk)
            if observed > expected_bytes:
                raise ReleaseAttestationCryptoError(f"{label} grew while reading")
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
        if (
            identity_before != identity_after
            or observed != expected_bytes
            or digest.hexdigest() != expected_sha256
        ):
            raise ReleaseAttestationCryptoError(f"{label} bytes or identity differ")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new(path: Path, raw: bytes, *, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReleaseAttestationCryptoError("private verifier write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_exact_file(
    source: Path,
    destination: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
    label: str,
    mode: int,
) -> None:
    """Hash and copy one pinned executable without retaining it in memory."""

    absolute = Path(os.path.abspath(os.fspath(source)))
    read_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(absolute, read_flags)
    except OSError as error:
        raise ReleaseAttestationCryptoError(f"{label} cannot be opened safely") from error
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_bytes:
            raise ReleaseAttestationCryptoError(f"{label} metadata differs")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        os.fchmod(destination_descriptor, mode)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(source_descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
            if observed > expected_bytes:
                raise ReleaseAttestationCryptoError(f"{label} grew while reading")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise ReleaseAttestationCryptoError(
                        "private verifier copy stalled"
                    )
                view = view[written:]
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
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
        if (
            identity_before != identity_after
            or observed != expected_bytes
            or digest.hexdigest() != expected_sha256
        ):
            raise ReleaseAttestationCryptoError(f"{label} bytes or identity differ")
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def _archived_bytes(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAXIMUM_TRANSCRIPT_BYTES:
        raise ReleaseAttestationCryptoError("Cosign transcript size is invalid")
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _der_value(raw: bytes, offset: int, *, label: str) -> tuple[int, bytes, int]:
    if offset < 0 or offset + 2 > len(raw):
        raise ReleaseAttestationCryptoError(f"{label} DER is truncated")
    tag = raw[offset]
    first_length = raw[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        width = first_length & 0x7F
        if width == 0 or width > 4 or cursor + width > len(raw):
            raise ReleaseAttestationCryptoError(f"{label} DER length is invalid")
        length_bytes = raw[cursor : cursor + width]
        if length_bytes[0] == 0:
            raise ReleaseAttestationCryptoError(
                f"{label} DER length is non-canonical"
            )
        length = int.from_bytes(length_bytes, "big")
        if length < 128:
            raise ReleaseAttestationCryptoError(
                f"{label} DER long length is non-canonical"
            )
        cursor += width
    else:
        length = first_length
    end = cursor + length
    if end > len(raw):
        raise ReleaseAttestationCryptoError(f"{label} DER value is truncated")
    return tag, raw[cursor:end], end


def _der_children(raw: bytes, *, label: str) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(raw):
        tag, value, cursor = _der_value(raw, cursor, label=label)
        result.append((tag, value))
    if cursor != len(raw):
        raise ReleaseAttestationCryptoError(f"{label} DER children differ")
    return result


def rfc3161_timestamp_utc(raw: bytes) -> str:
    """Extract whole-second UTC genTime from one strict RFC3161 response."""

    tag, response, end = _der_value(raw, 0, label="RFC3161 response")
    if tag != 0x30 or end != len(raw):
        raise ReleaseAttestationCryptoError("RFC3161 response envelope differs")
    response_fields = _der_children(response, label="RFC3161 response")
    if len(response_fields) != 2 or response_fields[0][0] != 0x30:
        raise ReleaseAttestationCryptoError("RFC3161 response fields differ")
    status = _der_children(response_fields[0][1], label="RFC3161 status")
    if not status or status[0] != (0x02, b"\x00"):
        raise ReleaseAttestationCryptoError("RFC3161 status is not granted")
    if response_fields[1][0] != 0x30:
        raise ReleaseAttestationCryptoError("RFC3161 token is absent")
    content_info = _der_children(
        response_fields[1][1], label="RFC3161 content info"
    )
    if (
        len(content_info) != 2
        or content_info[0] != (0x06, bytes.fromhex("2a864886f70d010702"))
        or content_info[1][0] != 0xA0
    ):
        raise ReleaseAttestationCryptoError("RFC3161 signed-data identity differs")
    signed_wrapper = _der_children(
        content_info[1][1], label="RFC3161 signed-data wrapper"
    )
    if len(signed_wrapper) != 1 or signed_wrapper[0][0] != 0x30:
        raise ReleaseAttestationCryptoError("RFC3161 signed-data wrapper differs")
    signed_data = _der_children(
        signed_wrapper[0][1], label="RFC3161 signed data"
    )
    if len(signed_data) < 3 or signed_data[2][0] != 0x30:
        raise ReleaseAttestationCryptoError("RFC3161 encapsulated content is absent")
    encapsulated = _der_children(
        signed_data[2][1], label="RFC3161 encapsulated content"
    )
    if (
        len(encapsulated) != 2
        or encapsulated[0]
        != (0x06, bytes.fromhex("2a864886f70d0109100104"))
        or encapsulated[1][0] != 0xA0
    ):
        raise ReleaseAttestationCryptoError("RFC3161 TSTInfo identity differs")
    content_wrapper = _der_children(
        encapsulated[1][1], label="RFC3161 TSTInfo wrapper"
    )
    if len(content_wrapper) != 1 or content_wrapper[0][0] != 0x04:
        raise ReleaseAttestationCryptoError("RFC3161 TSTInfo wrapper differs")
    tst_tag, tst_info, tst_end = _der_value(
        content_wrapper[0][1], 0, label="RFC3161 TSTInfo"
    )
    if tst_tag != 0x30 or tst_end != len(content_wrapper[0][1]):
        raise ReleaseAttestationCryptoError("RFC3161 TSTInfo envelope differs")
    tst_fields = _der_children(tst_info, label="RFC3161 TSTInfo")
    if len(tst_fields) < 5 or tst_fields[4][0] != 0x18:
        raise ReleaseAttestationCryptoError("RFC3161 genTime is absent")
    try:
        generalized_time = tst_fields[4][1].decode("ascii", "strict")
        parsed = datetime.strptime(generalized_time, "%Y%m%d%H%M%SZ").replace(
            tzinfo=timezone.utc
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ReleaseAttestationCryptoError(
            "RFC3161 genTime is not whole-second UTC"
        ) from error
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_cryptographic_verification_record(
    value: Any,
    *,
    expected_bundle_sha256: str,
    expected_attested_at: str,
    expected_assets: Sequence[tuple[str, str]],
) -> Mapping[str, Any]:
    """Validate an archived Cosign record independently of host platform."""

    record = _mapping(
        value,
        {
            "status",
            "method",
            "trustPolicy",
            "tool",
            "trustedRoot",
            "verifiedAsset",
            "bundleSHA256",
            "attestedAt",
            "transcript",
        },
        label="offline cryptographic verification",
    )
    if (
        record["status"] != "VERIFIED"
        or record["method"] != METHOD
        or record["trustPolicy"] != TRUST_POLICY
        or record["bundleSHA256"] != expected_bundle_sha256
        or record["attestedAt"] != expected_attested_at
    ):
        raise ReleaseAttestationCryptoError(
            "offline cryptographic verification policy or bundle differs"
        )
    tool = _mapping(
        record["tool"],
        {
            "name",
            "version",
            "platform",
            "binaryBytes",
            "binarySHA256",
            "distributionURL",
        },
        label="offline cryptographic verifier tool",
    )
    variants_by_platform = {
        str(variant["platform"]): variant
        for variant in COSIGN_BINARY_VARIANTS.values()
    }
    variant = variants_by_platform.get(tool["platform"])
    if variant is None or tool != {
        "name": "cosign",
        "version": COSIGN_VERSION,
        "platform": variant["platform"],
        "binaryBytes": variant["bytes"],
        "binarySHA256": variant["sha256"],
        "distributionURL": variant["url"],
    }:
        raise ReleaseAttestationCryptoError(
            "offline cryptographic verifier identity differs"
        )
    if record["trustedRoot"] != {
        "bytes": TRUSTED_ROOT_BYTES,
        "sha256": TRUSTED_ROOT_SHA256,
    }:
        raise ReleaseAttestationCryptoError("GitHub trusted-root binding differs")
    if not expected_assets:
        raise ReleaseAttestationCryptoError("release asset inventory is empty")
    expected_asset = min(expected_assets, key=lambda item: item[0].encode("ascii"))
    if record["verifiedAsset"] != {
        "name": expected_asset[0],
        "sha256": expected_asset[1],
    }:
        raise ReleaseAttestationCryptoError(
            "offline cryptographic verified-asset binding differs"
        )
    transcript = _mapping(
        record["transcript"],
        {"encoding", "bytes", "sha256", "dataBase64"},
        label="offline cryptographic verifier transcript",
    )
    if transcript["encoding"] != "base64":
        raise ReleaseAttestationCryptoError(
            "offline cryptographic transcript encoding differs"
        )
    raw_transcript = _decode_base64(
        transcript["dataBase64"],
        label="offline cryptographic transcript",
        maximum_bytes=MAXIMUM_TRANSCRIPT_BYTES,
    )
    if (
        raw_transcript != b"Verified OK\n"
        or transcript["bytes"] != len(raw_transcript)
        or transcript["sha256"] != hashlib.sha256(raw_transcript).hexdigest()
    ):
        raise ReleaseAttestationCryptoError(
            "offline cryptographic verifier transcript differs"
        )
    return record


def expected_known_answer_result(*, expected_platform: str) -> dict[str, Any]:
    """Return the exact genuine release-attestation KAT result for one host."""

    variants = {
        str(variant["platform"]): variant
        for variant in COSIGN_BINARY_VARIANTS.values()
    }
    variant = variants.get(expected_platform)
    if variant is None:
        raise ReleaseAttestationCryptoError(
            "known-answer verifier platform is unsupported"
        )
    return {
        "schemaVersion": KNOWN_ANSWER_RESULT_SCHEMA,
        "status": "KNOWN_ANSWER_PASS",
        "synthetic": False,
        "networkUsed": False,
        "networkIsolation": {
            "linux/amd64": "LINUX_UNSHARE_NETWORK_NAMESPACE",
            "darwin/arm64": "MACOS_SANDBOX_DENY_NETWORK",
        }[expected_platform],
        "repository": KNOWN_ANSWER_REPOSITORY,
        "tag": KNOWN_ANSWER_TAG,
        "commit": KNOWN_ANSWER_COMMIT,
        "releaseId": KNOWN_ANSWER_RELEASE_ID,
        "attestedAt": KNOWN_ANSWER_ATTESTED_AT,
        "bundleSHA256": KNOWN_ANSWER_BUNDLE_SHA256,
        "rawOutputSHA256": KNOWN_ANSWER_RAW_OUTPUT_SHA256,
        "verifiedAsset": {
            "name": KNOWN_ANSWER_ASSET_NAME,
            "sha256": KNOWN_ANSWER_ASSET_SHA256,
        },
        "cosign": {
            "name": "cosign",
            "version": COSIGN_VERSION,
            "platform": variant["platform"],
            "binaryBytes": variant["bytes"],
            "binarySHA256": variant["sha256"],
            "distributionURL": variant["url"],
        },
        "trustedRoot": {
            "bytes": TRUSTED_ROOT_BYTES,
            "sha256": TRUSTED_ROOT_SHA256,
        },
    }


def validate_known_answer_result(
    value: Any, *, expected_platform: str
) -> Mapping[str, Any]:
    """Require the exact genuine offline release-attestation KAT result."""

    expected = expected_known_answer_result(
        expected_platform=expected_platform
    )
    if value != expected:
        raise ReleaseAttestationCryptoError(
            "release-attestation known-answer result differs"
        )
    return value


class PinnedCosignReleaseAttestationVerifier:
    """Verify one archived GitHub release bundle with a private Cosign copy."""

    def __init__(
        self,
        executable: Path,
        *,
        trusted_root: Path = TRACKED_GITHUB_TRUSTED_ROOT,
        timeout_seconds: float = 120.0,
    ) -> None:
        variant = COSIGN_BINARY_VARIANTS.get((platform.system(), platform.machine()))
        if variant is None:
            raise ReleaseAttestationCryptoError(
                "Cosign release verifier platform is unsupported"
            )
        if not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 300:
            raise ReleaseAttestationCryptoError("Cosign timeout is invalid")
        self._executable = Path(os.path.abspath(os.fspath(executable)))
        self._trusted_root = Path(os.path.abspath(os.fspath(trusted_root)))
        self._timeout_seconds = float(timeout_seconds)
        self._variant = variant

    def _version(self, executable: Path, environment: Mapping[str, str]) -> None:
        try:
            completed = subprocess.run(
                [os.fspath(executable), "version", "--json"],
                cwd=environment["HOME"],
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                close_fds=True,
                start_new_session=True,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseAttestationCryptoError("pinned Cosign version failed") from error
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            raise ReleaseAttestationCryptoError("pinned Cosign version differs")
        version = _strict_json(completed.stdout, label="Cosign version output")
        if version != {
            "gitVersion": COSIGN_VERSION,
            "gitCommit": COSIGN_GIT_COMMIT,
            "gitTreeState": "clean",
            "buildDate": COSIGN_BUILD_DATE,
            "goVersion": COSIGN_GO_VERSION,
            "compiler": "gc",
            "platform": self._variant["platform"],
        }:
            raise ReleaseAttestationCryptoError("pinned Cosign version identity differs")

    def verify(
        self,
        *,
        attestation_record: Any,
        asset_root: Path,
        expected_assets: Sequence[tuple[str, str]],
    ) -> VerifiedCryptographicAttestation:
        if not expected_assets:
            raise ReleaseAttestationCryptoError("release asset inventory is empty")
        expected_map = dict(expected_assets)
        if len(expected_map) != len(expected_assets):
            raise ReleaseAttestationCryptoError("release asset names are duplicated")
        for name, digest in expected_assets:
            if (
                not isinstance(name, str)
                or SAFE_ASSET_NAME.fullmatch(name) is None
                or not isinstance(digest, str)
                or SHA256.fullmatch(digest) is None
            ):
                raise ReleaseAttestationCryptoError("release asset binding is invalid")
        verified_name, verified_digest = sorted(
            expected_assets, key=lambda item: item[0].encode("ascii")
        )[0]
        absolute_root = Path(os.path.abspath(os.fspath(asset_root)))
        try:
            root_metadata = os.stat(absolute_root, follow_symlinks=False)
        except OSError as error:
            raise ReleaseAttestationCryptoError("release asset root is unavailable") from error
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ReleaseAttestationCryptoError("release asset root is not a directory")
        verified_path = absolute_root / verified_name
        try:
            before_asset = os.stat(verified_path, follow_symlinks=False)
        except OSError as error:
            raise ReleaseAttestationCryptoError("verified release asset is unavailable") from error
        if not stat.S_ISREG(before_asset.st_mode) or before_asset.st_nlink != 1:
            raise ReleaseAttestationCryptoError("verified release asset type differs")

        raw_output = _raw_output(attestation_record)
        output = _strict_json(raw_output, label="GitHub CLI attestation output")
        outer = _mapping(
            output,
            {"attestation", "verificationResult"},
            label="GitHub CLI attestation output",
        )
        attestation = _mapping(
            outer["attestation"],
            {"bundle", "bundle_url", "initiator"},
            label="GitHub CLI attestation",
        )
        bundle_raw = _canonical_json_bytes(attestation["bundle"]) + b"\n"
        bundle_sha256 = hashlib.sha256(
            _canonical_json_bytes(attestation["bundle"])
        ).hexdigest()
        bundle = _mapping(
            attestation["bundle"],
            {"mediaType", "dsseEnvelope", "verificationMaterial"},
            label="Sigstore bundle",
        )
        verification_material = _mapping(
            bundle["verificationMaterial"],
            {"certificate", "timestampVerificationData"},
            label="Sigstore verification material",
        )
        timestamp_data = _mapping(
            verification_material["timestampVerificationData"],
            {"rfc3161Timestamps"},
            label="Sigstore timestamp verification data",
        )
        timestamps = timestamp_data["rfc3161Timestamps"]
        if not isinstance(timestamps, list) or len(timestamps) != 1:
            raise ReleaseAttestationCryptoError(
                "Sigstore RFC3161 timestamp inventory differs"
            )
        timestamp = _mapping(
            timestamps[0], {"signedTimestamp"}, label="Sigstore RFC3161 timestamp"
        )
        signed_timestamp = _decode_base64(
            timestamp["signedTimestamp"],
            label="Sigstore RFC3161 timestamp",
            maximum_bytes=1024 * 1024,
        )
        attested_at = rfc3161_timestamp_utc(signed_timestamp)
        trusted_root = _read_exact_file(
            self._trusted_root,
            expected_bytes=TRUSTED_ROOT_BYTES,
            expected_sha256=TRUSTED_ROOT_SHA256,
            label="tracked GitHub trusted root",
        )
        _strict_json(trusted_root, label="tracked GitHub trusted root")
        with tempfile.TemporaryDirectory(prefix="corelm-cosign-release-") as value:
            temporary = Path(value)
            os.chmod(temporary, 0o700)
            private_cosign = temporary / "cosign"
            bundle_path = temporary / "release-bundle.json"
            root_path = temporary / "github-trusted-root.json"
            private_asset = temporary / verified_name
            _copy_exact_file(
                self._executable,
                private_cosign,
                expected_bytes=int(self._variant["bytes"]),
                expected_sha256=str(self._variant["sha256"]),
                label="pinned Cosign binary",
                mode=0o700,
            )
            _copy_exact_file(
                verified_path,
                private_asset,
                expected_bytes=before_asset.st_size,
                expected_sha256=verified_digest,
                label="verified release asset",
                mode=0o600,
            )
            _write_new(bundle_path, bundle_raw, mode=0o600)
            _write_new(root_path, trusted_root, mode=0o600)
            environment = {
                "HOME": os.fspath(temporary),
                "XDG_CACHE_HOME": os.fspath(temporary / "cache"),
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "NO_COLOR": "1",
            }
            self._version(private_cosign, environment)
            command = [
                os.fspath(private_cosign),
                "verify-blob-attestation",
                "--bundle",
                os.fspath(bundle_path),
                "--trusted-root",
                os.fspath(root_path),
                "--certificate-identity",
                GITHUB_RELEASE_SAN,
                "--certificate-oidc-issuer-regexp",
                ".*",
                "--type",
                RELEASE_PREDICATE_TYPE,
                "--use-signed-timestamps",
                "--private-infrastructure",
                "--insecure-ignore-sct",
                os.fspath(private_asset),
            ]
            try:
                completed = subprocess.run(
                    command,
                    cwd=temporary,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    close_fds=True,
                    start_new_session=True,
                    timeout=self._timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ReleaseAttestationCryptoError(
                    "pinned Cosign verification did not complete"
                ) from error
        if (
            completed.returncode != 0
            or completed.stdout
            or completed.stderr != b"Verified OK\n"
        ):
            raise ReleaseAttestationCryptoError(
                "archived GitHub release bundle failed pinned Cosign verification"
            )
        try:
            after_asset = os.stat(verified_path, follow_symlinks=False)
        except OSError as error:
            raise ReleaseAttestationCryptoError(
                "verified release asset disappeared"
            ) from error
        before_identity = (
            before_asset.st_dev,
            before_asset.st_ino,
            before_asset.st_size,
            before_asset.st_mtime_ns,
        )
        after_identity = (
            after_asset.st_dev,
            after_asset.st_ino,
            after_asset.st_size,
            after_asset.st_mtime_ns,
        )
        if before_identity != after_identity or not stat.S_ISREG(after_asset.st_mode):
            raise ReleaseAttestationCryptoError(
                "verified release asset changed during cryptographic verification"
            )
        record = {
            "status": "VERIFIED",
            "method": METHOD,
            "trustPolicy": TRUST_POLICY,
            "tool": {
                "name": "cosign",
                "version": COSIGN_VERSION,
                "platform": self._variant["platform"],
                "binaryBytes": self._variant["bytes"],
                "binarySHA256": self._variant["sha256"],
                "distributionURL": self._variant["url"],
            },
            "trustedRoot": {
                "bytes": TRUSTED_ROOT_BYTES,
                "sha256": TRUSTED_ROOT_SHA256,
            },
            "verifiedAsset": {
                "name": verified_name,
                "sha256": verified_digest,
            },
            "bundleSHA256": bundle_sha256,
            "attestedAt": attested_at,
            "transcript": _archived_bytes(completed.stderr),
        }
        return VerifiedCryptographicAttestation(
            bundle_sha256=bundle_sha256,
            raw_output_sha256=hashlib.sha256(raw_output).hexdigest(),
            attested_at=attested_at,
            verified_asset_name=verified_name,
            verified_asset_sha256=verified_digest,
            record=record,
        )


__all__ = [
    "COSIGN_BINARY_VARIANTS",
    "COSIGN_VERSION",
    "KNOWN_ANSWER_RESULT_SCHEMA",
    "PinnedCosignReleaseAttestationVerifier",
    "ReleaseAttestationCryptoError",
    "TRACKED_GITHUB_TRUSTED_ROOT",
    "TRUSTED_ROOT_BYTES",
    "TRUSTED_ROOT_SHA256",
    "VerifiedCryptographicAttestation",
    "expected_known_answer_result",
    "rfc3161_timestamp_utc",
    "validate_cryptographic_verification_record",
    "validate_known_answer_result",
]
