#!/usr/bin/env python3
"""Offline real-vector integration test for release-attestation cryptography.

This is intentionally not part of zero-skip unit discovery: it requires an
explicit, platform-matched 130+ MB production Cosign binary.  The vector,
chosen release asset, GitHub trusted root, and all expected outcomes are local
tracked bytes.  The verification step performs no acquisition or network I/O.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


V3_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.github_release_attestation import build_attestation_record  # noqa: E402
from v3.release_attestation_crypto import (  # noqa: E402
    METHOD,
    TRUST_POLICY,
    PinnedCosignReleaseAttestationVerifier,
    ReleaseAttestationCryptoError,
    validate_cryptographic_verification_record,
    validate_known_answer_result,
)
from v3.reproducibility import canonical_json_bytes  # noqa: E402


VECTOR_ROOT = V3_ROOT / "test-vectors" / "github-release-attestation-v1"
METADATA_BYTES = 2_899
METADATA_SHA256 = (
    "08fd587c853d0186d7b3ec457b001d014acd060e036e7b66fc433be248c96ad5"
)
RAW_OUTPUT_BYTES = 10_131
RAW_OUTPUT_SHA256 = (
    "dd934980d284943275aa2d9c574fdbcc5e3713e38a616ce49ca0ac682040f07c"
)
ASSET_BYTES = 1_950
ASSET_SHA256 = (
    "61905c69ec8660f310814ec98395cdd0c2d07aabf024c597ec45813984a02334"
)
LICENSE_BYTES = 1_068
LICENSE_SHA256 = (
    "6da4adc42392c8485e40b4251c7e332fc3352df1947c9ffade71dd60b14a7a4f"
)
BUNDLE_SHA256 = (
    "f4fdea17886e101c41e02213446e1374f83b07d476097b26c45b5021bf5f5477"
)
STATEMENT_BYTES = 3_199
STATEMENT_SHA256 = (
    "4446a53335a468ff96db59ce120eab9e1e3e8347d105a5cd56a1d41321820594"
)
CERTIFICATE_SHA256 = (
    "a69a47367524e2ad7b911dc194178e76501b8dd5420fe8332c740157805d332a"
)
TIMESTAMP_BYTES = 723
TIMESTAMP_SHA256 = (
    "ba09509dd6651c83ac9d7a0be9f51cddac0415303bd4fae6e5f58925ac87cbda"
)
ATTESTED_AT = "2026-07-31T02:04:01Z"
REPOSITORY = "cli/cli"
TAG = "v2.97.0"
RELEASE_ID = "362812465"
COMMIT = "55dbb4dc6b7edb10b48e3d7fc5bccd32318d1b55"
ASSET_NAME = "gh_2.97.0_checksums.txt"


class KnownAnswerError(ValueError):
    """The tracked real-world vector or expected result differs."""


def _read_exact(path: Path, *, size: int, digest: str, label: str) -> bytes:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise KnownAnswerError(f"{label} cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != size
        ):
            raise KnownAnswerError(f"{label} metadata differs")
        raw = bytearray()
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            raw.extend(chunk)
            hasher.update(chunk)
            if len(raw) > size:
                raise KnownAnswerError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(raw) != size
            or hasher.hexdigest() != digest
        ):
            raise KnownAnswerError(f"{label} bytes or identity differ")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _decode(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise KnownAnswerError(f"{label} is not base64 text")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise KnownAnswerError(f"{label} is not canonical base64") from error
    if not raw or base64.b64encode(raw).decode("ascii") != value:
        raise KnownAnswerError(f"{label} is not canonical base64")
    return raw


def _strict_json(raw: bytes, *, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise KnownAnswerError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise KnownAnswerError(f"{label} is not strict JSON") from error


def _load_vector() -> tuple[bytes, tuple[tuple[str, str], ...]]:
    metadata_raw = _read_exact(
        VECTOR_ROOT / "metadata.json",
        size=METADATA_BYTES,
        digest=METADATA_SHA256,
        label="known-answer metadata",
    )
    metadata = _strict_json(metadata_raw, label="known-answer metadata")
    if canonical_json_bytes(metadata) + b"\n" != metadata_raw:
        raise KnownAnswerError("known-answer metadata is not canonical JSON plus LF")
    if (
        metadata.get("schemaVersion")
        != "corelm-real-github-release-attestation-known-answer-v1"
        or metadata.get("status") != "REAL_PUBLIC_IMMUTABLE_RELEASE_ATTESTATION"
        or metadata.get("synthetic") is not False
        or metadata.get("expectedVerification")
        != {
            "method": METHOD,
            "networkUsed": False,
            "status": "KNOWN_ANSWER_PASS",
            "synthetic": False,
            "trustPolicy": TRUST_POLICY,
        }
    ):
        raise KnownAnswerError("known-answer metadata identity differs")

    raw_output = _read_exact(
        VECTOR_ROOT / "gh-release-verify-v2.97.0.json",
        size=RAW_OUTPUT_BYTES,
        digest=RAW_OUTPUT_SHA256,
        label="real GitHub attestation output",
    )
    _read_exact(
        VECTOR_ROOT / ASSET_NAME,
        size=ASSET_BYTES,
        digest=ASSET_SHA256,
        label="real GitHub release asset",
    )
    license_raw = _read_exact(
        VECTOR_ROOT / "UPSTREAM-LICENSE",
        size=LICENSE_BYTES,
        digest=LICENSE_SHA256,
        label="upstream license evidence",
    )
    if not license_raw.startswith(
        b"MIT License\n\nCopyright (c) 2019 GitHub Inc.\n"
    ):
        raise KnownAnswerError("upstream MIT license identity differs")

    output = _strict_json(raw_output, label="real GitHub attestation output")
    if not isinstance(output, dict) or set(output) != {
        "attestation",
        "verificationResult",
    }:
        raise KnownAnswerError("real GitHub attestation output fields differ")
    attestation = output["attestation"]
    if not isinstance(attestation, dict) or set(attestation) != {
        "bundle",
        "bundle_url",
        "initiator",
    }:
        raise KnownAnswerError("real GitHub attestation fields differ")
    bundle = attestation["bundle"]
    if hashlib.sha256(canonical_json_bytes(bundle)).hexdigest() != BUNDLE_SHA256:
        raise KnownAnswerError("known-answer bundle digest differs")
    envelope = bundle["dsseEnvelope"]
    statement_raw = _decode(envelope["payload"], label="signed release statement")
    if (
        len(statement_raw) != STATEMENT_BYTES
        or hashlib.sha256(statement_raw).hexdigest() != STATEMENT_SHA256
    ):
        raise KnownAnswerError("signed release statement bytes differ")
    statement = _strict_json(statement_raw, label="signed release statement")
    predicate = statement.get("predicate")
    subjects = statement.get("subject")
    if (
        statement.get("predicateType")
        != "https://in-toto.io/attestation/release/v0.2"
        or not isinstance(predicate, dict)
        or predicate.get("databaseId") != RELEASE_ID
        or predicate.get("repository") != REPOSITORY
        or predicate.get("tag") != TAG
        or not isinstance(subjects, list)
        or len(subjects) != 23
        or subjects[0]
        != {
            "uri": f"pkg:github/{REPOSITORY}@{TAG}",
            "digest": {"sha1": COMMIT},
        }
    ):
        raise KnownAnswerError("signed release identity differs")
    assets: list[tuple[str, str]] = []
    for subject in subjects[1:]:
        if (
            not isinstance(subject, dict)
            or set(subject) != {"name", "digest"}
            or not isinstance(subject["digest"], dict)
            or set(subject["digest"]) != {"sha256"}
        ):
            raise KnownAnswerError("signed asset subject differs")
        assets.append((subject["name"], subject["digest"]["sha256"]))
    if min(assets, key=lambda item: item[0].encode("ascii")) != (
        ASSET_NAME,
        ASSET_SHA256,
    ):
        raise KnownAnswerError("chosen real asset is not the canonical first subject")

    certificate = _decode(
        bundle["verificationMaterial"]["certificate"]["rawBytes"],
        label="release certificate",
    )
    if hashlib.sha256(certificate).hexdigest() != CERTIFICATE_SHA256:
        raise KnownAnswerError("release certificate bytes differ")
    timestamp = _decode(
        bundle["verificationMaterial"]["timestampVerificationData"][
            "rfc3161Timestamps"
        ][0]["signedTimestamp"],
        label="RFC3161 timestamp",
    )
    if (
        len(timestamp) != TIMESTAMP_BYTES
        or hashlib.sha256(timestamp).hexdigest() != TIMESTAMP_SHA256
    ):
        raise KnownAnswerError("RFC3161 timestamp bytes differ")
    verified_timestamps = output["verificationResult"]["verifiedTimestamps"]
    if (
        not isinstance(verified_timestamps, list)
        or len(verified_timestamps) != 1
        or verified_timestamps[0].get("timestamp") != ATTESTED_AT
    ):
        raise KnownAnswerError("GitHub verification timestamp differs")
    return raw_output, tuple(assets)


def run(*, cosign: Path, network_isolation: str) -> dict[str, Any]:
    raw_output, assets = _load_vector()
    attestation_record = build_attestation_record(raw_output, {})
    verified = PinnedCosignReleaseAttestationVerifier(cosign).verify(
        attestation_record=attestation_record,
        asset_root=VECTOR_ROOT.resolve(strict=True),
        expected_assets=assets,
    )
    validate_cryptographic_verification_record(
        verified.record,
        expected_bundle_sha256=BUNDLE_SHA256,
        expected_attested_at=ATTESTED_AT,
        expected_assets=assets,
    )
    if (
        verified.bundle_sha256 != BUNDLE_SHA256
        or verified.raw_output_sha256 != RAW_OUTPUT_SHA256
        or verified.attested_at != ATTESTED_AT
        or verified.verified_asset_name != ASSET_NAME
        or verified.verified_asset_sha256 != ASSET_SHA256
    ):
        raise KnownAnswerError("production Cosign known-answer result differs")
    selected_raw = (VECTOR_ROOT / ASSET_NAME).read_bytes()
    negative_raw = selected_raw + b"\x00"
    negative_sha256 = hashlib.sha256(negative_raw).hexdigest()
    if any(digest == negative_sha256 for _name, digest in assets):
        raise KnownAnswerError("negative digest unexpectedly exists in signed subjects")
    with tempfile.TemporaryDirectory(prefix="corelm-cosign-negative-") as value:
        negative_root = Path(value)
        (negative_root / ASSET_NAME).write_bytes(negative_raw)
        try:
            PinnedCosignReleaseAttestationVerifier(cosign).verify(
                attestation_record=attestation_record,
                asset_root=negative_root,
                expected_assets=((ASSET_NAME, negative_sha256),),
            )
        except ReleaseAttestationCryptoError:
            pass
        else:
            raise KnownAnswerError(
                "Cosign accepted a digest absent from the signed subjects"
            )
    result = {
        "schemaVersion": "corelm-release-attestation-crypto-known-answer-result-v1",
        "status": "KNOWN_ANSWER_PASS",
        "synthetic": False,
        "networkUsed": False,
        "networkIsolation": network_isolation,
        "repository": REPOSITORY,
        "tag": TAG,
        "commit": COMMIT,
        "releaseId": int(RELEASE_ID),
        "attestedAt": verified.attested_at,
        "bundleSHA256": verified.bundle_sha256,
        "rawOutputSHA256": verified.raw_output_sha256,
        "verifiedAsset": {
            "name": verified.verified_asset_name,
            "sha256": verified.verified_asset_sha256,
        },
        "cosign": dict(verified.record["tool"]),
        "trustedRoot": dict(verified.record["trustedRoot"]),
    }
    validate_known_answer_result(
        result,
        expected_platform=str(verified.record["tool"]["platform"]),
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cosign",
        type=Path,
        required=True,
        help="exact production Cosign v3.0.6 executable; no default is allowed",
    )
    parser.add_argument(
        "--network-isolation",
        required=True,
        choices=(
            "LINUX_UNSHARE_NETWORK_NAMESPACE",
            "MACOS_SANDBOX_DENY_NETWORK",
        ),
        help="OS-level network isolation applied by the verified caller",
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            run(
                cosign=arguments.cosign,
                network_isolation=arguments.network_isolation,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
