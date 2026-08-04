from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from v2.github_release_attestation import build_attestation_record
from v2.release_attestation_crypto import (
    COSIGN_BINARY_VARIANTS,
    METHOD as COSIGN_METHOD,
    TRUSTED_ROOT_BYTES,
    TRUSTED_ROOT_SHA256,
    TRUST_POLICY as COSIGN_TRUST_POLICY,
    VerifiedCryptographicAttestation,
)

from v2.release_receipt import (
    API_ROLES,
    GITHUB_API_VERSION,
    REQUIRED_ASSET_ROLES,
    REQUIRED_ROLE_FILENAMES,
    ReleaseReceiptError,
    SCHEMA_VERSION,
    SSH_KEYGEN_PATH,
    SUITE_ID,
    TRACKED_SSH_ALLOWED_SIGNERS_PATH,
    TRACKED_SSH_PUBLIC_KEY_PATH,
    canonical_json_bytes,
    _parse_allowed_signers,
    _parse_ed25519_public_key,
    _parse_signed_tag,
    verify_release_receipt,
)


REPOSITORY = "ALLPROTO/core-lm-benchmark"
HTML_BASE = f"https://github.com/{REPOSITORY}"
API_BASE = f"https://api.github.com/repos/{REPOSITORY}"
TAG = "blind-v2-test-release"
TREE = "2" * 40
DEADLINE = "2026-08-03T13:00:00Z"
PUBLISHED = "2026-08-03T11:00:00Z"
SERVER_DATE = "2026-08-03T12:00:00Z"
CAPTURED_AT = "2026-08-03T12:01:00Z"
RECEIPT_CREATED = "2026-08-03T12:10:00Z"
RELEASE_ID = 987654321
_TEST_KEY_DIRECTORY: tempfile.TemporaryDirectory[str] | None = None
_TEST_PRIVATE_KEY: Path | None = None
_TEST_PUBLIC_KEY: Path | None = None
_TEST_ALLOWED_SIGNERS: Path | None = None
_TEST_KEY_FINGERPRINT: str | None = None
_TEST_PUBLIC_KEY_SHA256: str | None = None


def _tool_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(home),
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def _run_ssh_keygen(arguments: list[str], *, cwd: Path) -> None:
    try:
        completed = subprocess.run(
            [os.fspath(SSH_KEYGEN_PATH), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=_tool_environment(cwd),
            check=False,
            close_fds=True,
            start_new_session=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssertionError("ssh-keygen test fixture could not execute") from error
    if completed.returncode != 0:
        output = completed.stdout.decode("utf-8", "replace")[:4096]
        raise AssertionError(f"ssh-keygen test fixture failed: {output}")


def _generate_test_key(
    directory: Path,
    name: str,
) -> tuple[Path, Path, Path, str, str]:
    private_key = directory / name
    _run_ssh_keygen(
        [
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "corelm-release-receipt-unit-test",
            "-f",
            os.fspath(private_key),
        ],
        cwd=directory,
    )
    public_key = Path(os.fspath(private_key) + ".pub")
    public_raw = public_key.read_bytes()
    public_key_line, fingerprint = _parse_ed25519_public_key(public_raw)
    allowed_signers = directory / f"{name}.allowed_signers"
    allowed_signers.write_bytes(
        b"corelm-release-receipt-unit-test " + public_key_line + b"\n"
    )
    return (
        private_key,
        public_key,
        allowed_signers,
        fingerprint,
        hashlib.sha256(public_raw).hexdigest(),
    )


def _sign_payload(private_key: Path, payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="release-receipt-sign-") as temporary_value:
        temporary = Path(temporary_value)
        payload_path = temporary / "tag-payload"
        payload_path.write_bytes(payload)
        _run_ssh_keygen(
            [
                "-Y",
                "sign",
                "-f",
                os.fspath(private_key),
                "-n",
                "git",
                os.fspath(payload_path),
            ],
            cwd=temporary,
        )
        signature_path = Path(os.fspath(payload_path) + ".sig")
        return signature_path.read_bytes()


def _fixture_signing_identity() -> tuple[Path, Path, Path, str, str]:
    if (
        _TEST_PRIVATE_KEY is None
        or _TEST_PUBLIC_KEY is None
        or _TEST_ALLOWED_SIGNERS is None
        or _TEST_KEY_FINGERPRINT is None
        or _TEST_PUBLIC_KEY_SHA256 is None
    ):
        raise AssertionError("ephemeral SSH signing identity is not initialized")
    return (
        _TEST_PRIVATE_KEY,
        _TEST_PUBLIC_KEY,
        _TEST_ALLOWED_SIGNERS,
        _TEST_KEY_FINGERPRINT,
        _TEST_PUBLIC_KEY_SHA256,
    )


def _git_oid(kind: str, payload: bytes) -> str:
    framed = kind.encode() + b" " + str(len(payload)).encode() + b"\0" + payload
    try:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover
        return hashlib.sha1(framed).hexdigest()


def _archived(raw: bytes) -> dict[str, object]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _headers(request_id: str) -> bytes:
    return (
        "HTTP/2 200\r\n"
        "date: Mon, 03 Aug 2026 12:00:00 GMT\r\n"
        "content-type: application/json; charset=utf-8\r\n"
        f"x-github-api-version-selected: {GITHUB_API_VERSION}\r\n"
        f"x-github-request-id: {request_id}\r\n"
        "\r\n"
    ).encode("ascii")


def _api_record(role: str, request_url: str, body: dict[str, Any]) -> dict[str, Any]:
    raw_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    return {
        "role": role,
        "requestURL": request_url,
        "statusCode": 200,
        "serverDate": SERVER_DATE,
        "capturedAt": CAPTURED_AT,
        "responseHeaders": _archived(_headers(f"UNIT-TEST-{role}")),
        "responseBody": _archived(raw_body),
    }


def _rehash(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("contentSHA256", None)
    receipt["contentSHA256"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return canonical_json_bytes(receipt) + b"\n"


def _replace_api_body(
    receipt: dict[str, Any],
    role: str,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    record = next(item for item in receipt["githubAPIResponses"] if item["role"] == role)
    raw = base64.b64decode(record["responseBody"]["dataBase64"])
    body = json.loads(raw)
    mutation(body)
    record["responseBody"] = _archived(
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    )


def _release_attestation_output(
    *,
    repository: str,
    tag: str,
    commit: str,
    release_id: int,
    assets: list[dict[str, Any]],
    attested_at: str,
) -> bytes:
    owner, _name = repository.split("/", 1)
    del owner
    purl = f"pkg:github/{repository}@{tag}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"uri": purl, "digest": {"sha1": commit}},
            *[
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in assets
            ],
        ],
        "predicateType": "https://in-toto.io/attestation/release/v0.2",
        "predicate": {
            "databaseId": str(release_id),
            "ownerId": "12345",
            "packageId": "67890",
            "purl": purl,
            "repository": repository,
            "repositoryId": "67890",
            "tag": tag,
        },
    }
    payload = json.dumps(statement, separators=(",", ":")).encode("utf-8")
    result = {
        "attestation": {
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": base64.b64encode(b"unit-signature").decode("ascii")}],
                },
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(b"unit-certificate").decode("ascii")
                    },
                    "timestampVerificationData": {
                        "rfc3161Timestamps": [
                            {
                                "signedTimestamp": base64.b64encode(
                                    b"unit-rfc3161-timestamp"
                                ).decode("ascii")
                            }
                        ]
                    },
                },
            },
            "bundle_url": "",
            "initiator": "",
        },
        "verificationResult": {
            "mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
            "signature": {
                "certificate": {
                    "certificateIssuer": "CN=Fulcio Intermediate l1,O=GitHub\\, Inc.",
                    "subjectAlternativeName": "https://dotcom.releases.github.com",
                }
            },
            "statement": statement,
            "verifiedIdentity": {
                "subjectAlternativeName": {
                    "subjectAlternativeName": "",
                    "regexp": "^https://dotcom\\.releases\\.github\\.com$",
                },
                "issuer": {"issuer": "", "regexp": ".*"},
            },
            "verifiedTimestamps": [
                {
                    "type": "TimestampAuthority",
                    "uri": "timestamp.githubapp.com",
                    "timestamp": attested_at,
                }
            ],
        },
    }
    return json.dumps(result, separators=(",", ":")).encode("utf-8") + b"\n"


def _replace_attestation_output(
    receipt: dict[str, Any], mutation: Callable[[dict[str, Any]], None]
) -> None:
    record = receipt["githubReleaseAttestation"]["rawVerificationOutput"]
    value = json.loads(base64.b64decode(record["dataBase64"]))
    mutation(value)
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
    receipt["githubReleaseAttestation"] = build_attestation_record(
        raw, _fixture_crypto_record(raw, receipt["requiredAssets"])
    )


def _fixture_crypto_record(
    raw_output: bytes, assets: list[dict[str, Any]]
) -> dict[str, Any]:
    output = json.loads(raw_output)
    bundle = output["attestation"]["bundle"]
    attested_at = output["verificationResult"]["verifiedTimestamps"][0][
        "timestamp"
    ]
    bundle_sha256 = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
    variant = COSIGN_BINARY_VARIANTS[(platform.system(), platform.machine())]
    verified = min(assets, key=lambda item: item["name"].encode("ascii"))
    return {
        "status": "VERIFIED",
        "method": COSIGN_METHOD,
        "trustPolicy": COSIGN_TRUST_POLICY,
        "tool": {
            "name": "cosign",
            "version": "v3.0.6",
            "platform": variant["platform"],
            "binaryBytes": variant["bytes"],
            "binarySHA256": variant["sha256"],
            "distributionURL": variant["url"],
        },
        "trustedRoot": {
            "bytes": TRUSTED_ROOT_BYTES,
            "sha256": TRUSTED_ROOT_SHA256,
        },
        "verifiedAsset": {
            "name": verified["name"],
            "sha256": verified["sha256"],
        },
        "bundleSHA256": bundle_sha256,
        "attestedAt": attested_at,
        "transcript": _archived(b"Verified OK\n"),
    }


class _FixtureCryptographicVerifier:
    """Explicit unit-only seam; production never defaults to this verifier."""

    def verify(
        self,
        *,
        attestation_record: dict[str, Any],
        asset_root: Path,
        expected_assets: tuple[tuple[str, str], ...],
    ) -> VerifiedCryptographicAttestation:
        del asset_root
        archived = attestation_record["rawVerificationOutput"]
        raw = base64.b64decode(archived["dataBase64"])
        assets = [
            {"name": name, "sha256": digest}
            for name, digest in expected_assets
        ]
        record = _fixture_crypto_record(raw, assets)
        verified = record["verifiedAsset"]
        return VerifiedCryptographicAttestation(
            bundle_sha256=record["bundleSHA256"],
            raw_output_sha256=hashlib.sha256(raw).hexdigest(),
            attested_at=record["attestedAt"],
            verified_asset_name=verified["name"],
            verified_asset_sha256=verified["sha256"],
            record=record,
        )


FIXTURE_CRYPTOGRAPHIC_VERIFIER = _FixtureCryptographicVerifier()


def _build_fixture(
    root: Path,
    kind: str = "design",
    signing_identity: tuple[Path, Path, Path, str, str] | None = None,
) -> tuple[dict[str, Any], bytes]:
    private_key, _public_key, _allowed_signers, fingerprint, public_key_sha256 = (
        _fixture_signing_identity()
        if signing_identity is None
        else signing_identity
    )
    commit_payload = (
        f"tree {TREE}\n"
        "author Unit Test <unit@example.invalid> 1785751200 +0000\n"
        "committer Unit Test <unit@example.invalid> 1785751200 +0000\n"
        "\npublication fixture\n"
    ).encode("ascii")
    commit = _git_oid("commit", commit_payload)
    signed_payload = (
        f"object {commit}\n"
        "type commit\n"
        f"tag {TAG}\n"
        "tagger Unit Test <unit@example.invalid> 1785751200 +0000\n"
        "\npublication fixture\n"
    ).encode("ascii")
    signature = _sign_payload(private_key, signed_payload)
    tag_payload = signed_payload + signature
    tag_oid = _git_oid("tag", tag_payload)

    assets: list[dict[str, Any]] = []
    api_assets: list[dict[str, Any]] = []
    for index, role in enumerate(REQUIRED_ASSET_ROLES[kind]):
        name = REQUIRED_ROLE_FILENAMES.get(
            role, role.replace("-", "_") + ".bin"
        )
        payload = f"exact {kind} {role} asset\n".encode()
        (root / name).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        asset_id = 10000 + index
        api_url = f"{API_BASE}/releases/assets/{asset_id}"
        download_url = f"{HTML_BASE}/releases/download/{TAG}/{name}"
        assets.append(
            {
                "role": role,
                "assetId": asset_id,
                "name": name,
                "apiURL": api_url,
                "downloadURL": download_url,
                "bytes": len(payload),
                "sha256": digest,
            }
        )
        api_assets.append(
            {
                "id": asset_id,
                "name": name,
                "url": api_url,
                "browser_download_url": download_url,
                "state": "uploaded",
                "size": len(payload),
                "digest": f"sha256:{digest}",
                "created_at": "2026-08-03T10:00:00Z",
                "updated_at": "2026-08-03T10:30:00Z",
            }
        )

    release_body = {
        "id": RELEASE_ID,
        "url": f"{API_BASE}/releases/{RELEASE_ID}",
        "html_url": f"{HTML_BASE}/releases/tag/{TAG}",
        "tag_name": TAG,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "published_at": PUBLISHED,
        "assets": api_assets,
    }
    ref_body = {
        "ref": f"refs/tags/{TAG}",
        "object": {
            "type": "tag",
            "sha": tag_oid,
            "url": f"{API_BASE}/git/tags/{tag_oid}",
        },
    }
    tag_body = {
        "sha": tag_oid,
        "tag": TAG,
        "url": f"{API_BASE}/git/tags/{tag_oid}",
        "object": {
            "type": "commit",
            "sha": commit,
            "url": f"{API_BASE}/git/commits/{commit}",
        },
        "verification": {
            "verified": True,
            "reason": "valid",
            "signature": signature.decode("ascii"),
            "payload": signed_payload.decode("ascii"),
            "verified_at": "2026-08-03T11:50:00Z",
        },
    }
    commit_body = {
        "sha": commit,
        "url": f"{API_BASE}/git/commits/{commit}",
        "tree": {
            "sha": TREE,
            "url": f"{API_BASE}/git/trees/{TREE}",
        },
    }
    responses = [
        _api_record("commit", f"{API_BASE}/git/commits/{commit}", commit_body),
        _api_record("release", f"{API_BASE}/releases/{RELEASE_ID}", release_body),
        _api_record("tag-object", f"{API_BASE}/git/tags/{tag_oid}", tag_body),
        _api_record("tag-ref", f"{API_BASE}/git/ref/tags/{TAG}", ref_body),
    ]
    self_check_roles = tuple(item["role"] for item in responses)
    if self_check_roles != API_ROLES:
        raise AssertionError("test API response order drifted")

    receipt: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "githubAPIVersion": GITHUB_API_VERSION,
        "repository": {
            "slug": REPOSITORY,
            "htmlURL": HTML_BASE,
            "apiURL": API_BASE,
        },
        "kind": kind,
        "tag": TAG,
        "release": {
            "id": RELEASE_ID,
            "apiURL": f"{API_BASE}/releases/{RELEASE_ID}",
            "htmlURL": f"{HTML_BASE}/releases/tag/{TAG}",
            "publishedAt": PUBLISHED,
            "deadline": DEADLINE,
        },
        "source": {
            "commit": commit,
            "tree": TREE,
            "commitObject": {
                "oid": commit,
                "rawPayload": _archived(commit_payload),
            },
        },
        "annotatedTag": {
            "objectOID": tag_oid,
            "targetType": "commit",
            "targetCommit": commit,
            "rawPayload": _archived(tag_payload),
        },
        "signatureVerification": {
            "status": "VERIFIED",
            "signatureType": "SSH",
            "method": "git verify-tag",
            "toolVersion": "git version unit-test",
            "exitCode": 0,
            "trustPolicy": "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH",
            "keyFingerprint": fingerprint,
            "publicKeySHA256": public_key_sha256,
            "tagObjectOID": tag_oid,
            "targetCommit": commit,
            "verifiedAt": "2026-08-03T11:55:00Z",
            "transcript": _archived(b"unit fixture: good signature from frozen fingerprint\n"),
        },
        "githubReleaseAttestation": None,
        "requiredAssets": assets,
        "githubAPIResponses": responses,
        "receiptCreatedAt": RECEIPT_CREATED,
    }
    attestation_output = _release_attestation_output(
        repository=REPOSITORY,
        tag=TAG,
        commit=commit,
        release_id=RELEASE_ID,
        assets=assets,
        attested_at=PUBLISHED,
    )
    receipt["githubReleaseAttestation"] = build_attestation_record(
        attestation_output, _fixture_crypto_record(attestation_output, assets)
    )
    return receipt, _rehash(receipt)


def _expected(receipt: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    result = {
        "expected_repository": REPOSITORY,
        "expected_kind": receipt["kind"],
        "expected_tag": TAG,
        "expected_commit": receipt["source"]["commit"],
        "expected_tree": TREE,
        "expected_deadline": DEADLINE,
        "expected_signature_type": receipt["signatureVerification"]["signatureType"],
        "expected_key_fingerprint": receipt["signatureVerification"]["keyFingerprint"],
        "expected_public_key_sha256": receipt["signatureVerification"][
            "publicKeySHA256"
        ],
        "trusted_ssh_public_key_path": _fixture_signing_identity()[1],
        "trusted_ssh_allowed_signers_path": _fixture_signing_identity()[2],
        "cryptographic_attestation_verifier": (
            FIXTURE_CRYPTOGRAPHIC_VERIFIER
        ),
    }
    result.update(overrides)
    return result


class ReleaseReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        global _TEST_KEY_DIRECTORY
        global _TEST_KEY_FINGERPRINT
        global _TEST_PRIVATE_KEY
        global _TEST_PUBLIC_KEY
        global _TEST_ALLOWED_SIGNERS
        global _TEST_PUBLIC_KEY_SHA256

        _TEST_KEY_DIRECTORY = tempfile.TemporaryDirectory(
            prefix="release-receipt-key-"
        )
        key_root = Path(_TEST_KEY_DIRECTORY.name)
        (
            _TEST_PRIVATE_KEY,
            _TEST_PUBLIC_KEY,
            _TEST_ALLOWED_SIGNERS,
            _TEST_KEY_FINGERPRINT,
            _TEST_PUBLIC_KEY_SHA256,
        ) = _generate_test_key(key_root, "signing-key")

    @classmethod
    def tearDownClass(cls) -> None:
        global _TEST_KEY_DIRECTORY
        global _TEST_KEY_FINGERPRINT
        global _TEST_PRIVATE_KEY
        global _TEST_PUBLIC_KEY
        global _TEST_ALLOWED_SIGNERS
        global _TEST_PUBLIC_KEY_SHA256

        if _TEST_KEY_DIRECTORY is not None:
            _TEST_KEY_DIRECTORY.cleanup()
        _TEST_KEY_DIRECTORY = None
        _TEST_PRIVATE_KEY = None
        _TEST_PUBLIC_KEY = None
        _TEST_ALLOWED_SIGNERS = None
        _TEST_KEY_FINGERPRINT = None
        _TEST_PUBLIC_KEY_SHA256 = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_trust_files_bind_the_preregistered_signing_key(self) -> None:
        public_raw = TRACKED_SSH_PUBLIC_KEY_PATH.read_bytes()
        public_key_line, fingerprint = _parse_ed25519_public_key(public_raw)
        self.assertEqual(
            fingerprint,
            "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        )
        self.assertEqual(
            hashlib.sha256(public_raw).hexdigest(),
            "7e0fab5da5fd49258faebf8b2f581b517159c0290aaff2fb1f79c77c9febba3c",
        )
        principal = _parse_allowed_signers(
            TRACKED_SSH_ALLOWED_SIGNERS_PATH.read_bytes(),
            expected_public_key_line=public_key_line,
        )
        self.assertEqual(principal, "ivantyschenko777@gmail.com")

    def test_trusted_public_key_requires_exactly_one_terminal_lf(self) -> None:
        public_raw = TRACKED_SSH_PUBLIC_KEY_PATH.read_bytes()
        self.assertEqual(public_raw.count(b"\n"), 1)
        with self.assertRaisesRegex(ReleaseReceiptError, "non-canonical"):
            _parse_ed25519_public_key(public_raw + b"ignored-second-line\n")

    def test_all_five_canonical_release_kinds_verify_offline(self) -> None:
        for kind in (
            "development-control",
            "design",
            "snapshot",
            "evidence",
            "closeout",
        ):
            with self.subTest(kind=kind):
                asset_root = self.root / kind
                asset_root.mkdir()
                receipt, raw = _build_fixture(asset_root, kind)
                result = verify_release_receipt(
                    raw,
                    asset_root,
                    **_expected(receipt),
                )
                self.assertEqual(result.kind, kind)
                self.assertEqual(result.signature_type, "SSH")
                self.assertEqual(result.commit, receipt["source"]["commit"])
                self.assertEqual(len(result.asset_sha256), len(REQUIRED_ASSET_ROLES[kind]))
                self.assertEqual(result.receipt_sha256, hashlib.sha256(raw).hexdigest())

    def test_evidence_release_is_marker_only_failure_compatible(self) -> None:
        receipt, raw = _build_fixture(self.root, "evidence")
        roles = tuple(asset["role"] for asset in receipt["requiredAssets"])
        self.assertEqual(
            roles,
            (
                "evidence-package",
                "evidence-release-manifest",
                "evidence-package-verifier-report",
                "sha256-manifest",
            ),
        )
        self.assertNotIn("terminal-outcome", roles)
        self.assertNotIn("attempt-marker", roles)
        result = verify_release_receipt(raw, self.root, **_expected(receipt))
        self.assertEqual(result.kind, "evidence")

    def test_signature_status_and_fingerprint_are_external_fail_closed_inputs(self) -> None:
        receipt, _raw = _build_fixture(self.root)
        receipt["signatureVerification"]["status"] = "UNVERIFIED"
        with self.assertRaisesRegex(ReleaseReceiptError, "unsigned or unverified"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

        # A fresh root keeps the first fixture's exact inventory while exercising
        # the independently preregistered fingerprint argument.
        receipt, raw = _build_fixture(self.root)
        with self.assertRaisesRegex(ReleaseReceiptError, "unsigned or unverified"):
            verify_release_receipt(
                raw,
                self.root,
                **_expected(
                    receipt,
                    expected_key_fingerprint="SHA256:" + "B" * 43,
                ),
            )
        with self.assertRaisesRegex(ReleaseReceiptError, "unsigned or unverified"):
            verify_release_receipt(
                raw,
                self.root,
                **_expected(receipt, expected_public_key_sha256="8" * 64),
            )

    def test_only_ssh_is_supported_and_signature_blocks_are_type_bound(self) -> None:
        receipt, _raw = _build_fixture(self.root)
        raw_tag = base64.b64decode(receipt["annotatedTag"]["rawPayload"]["dataBase64"])
        with self.assertRaisesRegex(ReleaseReceiptError, "unsupported"):
            _parse_signed_tag(
                raw_tag,
                expected_tag=TAG,
                signature_type="RSA",
            )

        unsigned = raw_tag.split(b"-----BEGIN SSH SIGNATURE-----", 1)[0]
        with self.assertRaisesRegex(ReleaseReceiptError, "unsigned"):
            _parse_signed_tag(unsigned, expected_tag=TAG, signature_type="SSH")

    def test_forged_valid_ssh_signature_cannot_be_blessed_by_receipt_claims(self) -> None:
        receipt, _raw = _build_fixture(self.root)
        raw_tag = base64.b64decode(
            receipt["annotatedTag"]["rawPayload"]["dataBase64"]
        )
        _target, signed_payload, original_signature = _parse_signed_tag(
            raw_tag,
            expected_tag=TAG,
            signature_type="SSH",
        )
        with tempfile.TemporaryDirectory(
            prefix="release-receipt-attacker-key-"
        ) as attacker_value:
            attacker_root = Path(attacker_value)
            (
                attacker_private,
                _public,
                _allowed_signers,
                _fingerprint,
                _sha256,
            ) = _generate_test_key(attacker_root, "attacker-key")
            forged_signature = _sign_payload(attacker_private, signed_payload)
        self.assertNotEqual(forged_signature, original_signature)

        forged_tag = signed_payload + forged_signature
        forged_tag_oid = _git_oid("tag", forged_tag)
        receipt["annotatedTag"]["objectOID"] = forged_tag_oid
        receipt["annotatedTag"]["rawPayload"] = _archived(forged_tag)
        receipt["signatureVerification"]["tagObjectOID"] = forged_tag_oid

        tag_object = next(
            item
            for item in receipt["githubAPIResponses"]
            if item["role"] == "tag-object"
        )
        tag_object["requestURL"] = f"{API_BASE}/git/tags/{forged_tag_oid}"

        def update_ref(body: dict[str, Any]) -> None:
            body["object"]["sha"] = forged_tag_oid
            body["object"]["url"] = f"{API_BASE}/git/tags/{forged_tag_oid}"

        def update_tag(body: dict[str, Any]) -> None:
            body["sha"] = forged_tag_oid
            body["url"] = f"{API_BASE}/git/tags/{forged_tag_oid}"
            body["verification"]["signature"] = forged_signature.decode("ascii")
            body["verification"]["payload"] = signed_payload.decode("ascii")

        _replace_api_body(receipt, "tag-ref", update_ref)
        _replace_api_body(receipt, "tag-object", update_tag)

        with self.assertRaisesRegex(
            ReleaseReceiptError,
            "cryptographic verification failed",
        ):
            verify_release_receipt(
                _rehash(receipt),
                self.root,
                **_expected(receipt),
            )

    def test_verifier_tool_and_allowed_signers_are_fail_closed(self) -> None:
        receipt, raw = _build_fixture(self.root)
        with mock.patch(
            "v2.release_receipt.SSH_KEYGEN_PATH",
            self.root / "missing-ssh-keygen",
        ):
            with self.assertRaisesRegex(ReleaseReceiptError, "unavailable"):
                verify_release_receipt(raw, self.root, **_expected(receipt))

        with tempfile.TemporaryDirectory(
            prefix="release-receipt-other-allowed-signers-"
        ) as other_value:
            other_root = Path(other_value)
            (
                _private,
                _public,
                other_allowed_signers,
                _fingerprint,
                _sha256,
            ) = _generate_test_key(other_root, "other-key")
            with self.assertRaisesRegex(ReleaseReceiptError, "does not bind"):
                verify_release_receipt(
                    raw,
                    self.root,
                    **_expected(
                        receipt,
                        trusted_ssh_allowed_signers_path=other_allowed_signers,
                    ),
                )

    def test_github_unverified_or_lightweight_tag_is_rejected(self) -> None:
        receipt, _raw = _build_fixture(self.root)

        def unverify(body: dict[str, Any]) -> None:
            body["verification"]["verified"] = False
            body["verification"]["reason"] = "unsigned"

        _replace_api_body(receipt, "tag-object", unverify)
        with self.assertRaisesRegex(ReleaseReceiptError, "not valid"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

        receipt, _raw = _build_fixture(self.root)

        def lightweight(body: dict[str, Any]) -> None:
            body["object"]["type"] = "commit"

        _replace_api_body(receipt, "tag-ref", lightweight)
        with self.assertRaisesRegex(ReleaseReceiptError, "lightweight"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_tag_and_commit_raw_objects_bind_exact_commit_tree(self) -> None:
        receipt, raw = _build_fixture(self.root)
        with self.assertRaisesRegex(ReleaseReceiptError, "source commit/tree"):
            verify_release_receipt(
                raw,
                self.root,
                **_expected(receipt, expected_tree="3" * 40),
            )
        receipt["annotatedTag"]["rawPayload"]["dataBase64"] = base64.b64encode(
            b"tampered tag"
        ).decode()
        with self.assertRaisesRegex(ReleaseReceiptError, "archived bytes"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_release_must_be_server_immutable_and_before_external_deadline(self) -> None:
        receipt, _raw = _build_fixture(self.root)

        def mutable(body: dict[str, Any]) -> None:
            body["immutable"] = False

        _replace_api_body(receipt, "release", mutable)
        with self.assertRaisesRegex(ReleaseReceiptError, "identity/state"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

        receipt, _raw = _build_fixture(self.root)
        receipt["release"]["publishedAt"] = DEADLINE
        with self.assertRaisesRegex(ReleaseReceiptError, "identity/state/timestamp"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_archived_api_headers_body_and_server_date_are_bound(self) -> None:
        receipt, _raw = _build_fixture(self.root)
        response = receipt["githubAPIResponses"][0]
        response["serverDate"] = "2026-08-03T12:00:01Z"
        with self.assertRaisesRegex(ReleaseReceiptError, "Date header"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

        receipt, _raw = _build_fixture(self.root)
        response = receipt["githubAPIResponses"][0]
        response["responseBody"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReleaseReceiptError, "archived bytes"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

        receipt, _raw = _build_fixture(self.root)
        response = receipt["githubAPIResponses"][-1]
        response["serverDate"] = "2026-08-03T12:06:00Z"
        response["capturedAt"] = "2026-08-03T12:07:00Z"
        response["responseHeaders"] = _archived(
            _headers("UNIT-TEST-SPAN").replace(b"12:00:00", b"12:06:00")
        )
        with self.assertRaisesRegex(ReleaseReceiptError, "span exceeds"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_required_asset_digest_and_exact_local_inventory_are_verified(self) -> None:
        receipt, raw = _build_fixture(self.root)
        first = receipt["requiredAssets"][0]
        (self.root / first["name"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(ReleaseReceiptError, "size/type|SHA-256"):
            verify_release_receipt(raw, self.root, **_expected(receipt))

        for path in self.root.iterdir():
            path.unlink()
        receipt, raw = _build_fixture(self.root)
        (self.root / "extra.bin").write_bytes(b"extra")
        with self.assertRaisesRegex(ReleaseReceiptError, "inventory differs"):
            verify_release_receipt(raw, self.root, **_expected(receipt))

        (self.root / "extra.bin").unlink()
        first = receipt["requiredAssets"][0]
        (self.root / first["name"]).unlink()
        os.symlink("missing-target", self.root / first["name"])
        with self.assertRaisesRegex(ReleaseReceiptError, "no-follow"):
            verify_release_receipt(raw, self.root, **_expected(receipt))

    def test_design_ci_artifact_release_filenames_are_canonical(self) -> None:
        receipt, _raw = _build_fixture(self.root)
        linux = next(
            item
            for item in receipt["requiredAssets"]
            if item["role"] == "linux-ci-artifact"
        )
        linux["name"] = "renamed-linux.zip"
        with self.assertRaisesRegex(ReleaseReceiptError, "filename differs"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_release_api_asset_digest_must_match_receipt_and_local_bytes(self) -> None:
        receipt, _raw = _build_fixture(self.root)

        def corrupt_digest(body: dict[str, Any]) -> None:
            body["assets"][0]["digest"] = "sha256:" + "0" * 64

        _replace_api_body(receipt, "release", corrupt_digest)
        with self.assertRaisesRegex(ReleaseReceiptError, "asset bytes/digest"):
            verify_release_receipt(_rehash(receipt), self.root, **_expected(receipt))

    def test_release_attestation_closes_self_consistent_asset_forgery(self) -> None:
        receipt, _raw = _build_fixture(self.root, kind="development-control")
        asset = receipt["requiredAssets"][0]
        forged = b"self-consistent forged report bytes\n"
        (self.root / asset["name"]).write_bytes(forged)
        asset["bytes"] = len(forged)
        asset["sha256"] = hashlib.sha256(forged).hexdigest()

        def forge_archived_release(body: dict[str, Any]) -> None:
            item = next(value for value in body["assets"] if value["name"] == asset["name"])
            item["size"] = len(forged)
            item["digest"] = f"sha256:{asset['sha256']}"

        _replace_api_body(receipt, "release", forge_archived_release)
        with self.assertRaisesRegex(ReleaseReceiptError, "attestation"):
            verify_release_receipt(
                _rehash(receipt), self.root, **_expected(receipt)
            )

    def test_release_attestation_timestamp_is_normative_and_fail_closed(self) -> None:
        receipt, _raw = _build_fixture(self.root)

        def move_verified_timestamp(value: dict[str, Any]) -> None:
            value["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = DEADLINE

        _replace_attestation_output(receipt, move_verified_timestamp)
        with self.assertRaisesRegex(ReleaseReceiptError, "attestation"):
            verify_release_receipt(
                _rehash(receipt), self.root, **_expected(receipt)
            )

    def test_content_digest_canonical_json_and_duplicate_keys_are_required(self) -> None:
        receipt, raw = _build_fixture(self.root)
        mutated = bytearray(raw)
        mutated[-3] = ord("0") if mutated[-3] != ord("0") else ord("1")
        with self.assertRaises(ReleaseReceiptError):
            verify_release_receipt(bytes(mutated), self.root, **_expected(receipt))
        pretty = json.dumps(receipt, indent=2).encode() + b"\n"
        with self.assertRaisesRegex(ReleaseReceiptError, "not canonical"):
            verify_release_receipt(pretty, self.root, **_expected(receipt))
        with self.assertRaisesRegex(ReleaseReceiptError, "duplicate"):
            verify_release_receipt(
                b'{"x":1,"x":2}\n', self.root, **_expected(receipt)
            )

    def test_schema_is_tracked_strict_and_matches_runtime_constants(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "release-receipt.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schemaVersion"]["const"], SCHEMA_VERSION)
        self.assertEqual(schema["properties"]["suiteId"]["const"], SUITE_ID)
        self.assertEqual(
            schema["properties"]["githubAPIVersion"]["const"], GITHUB_API_VERSION
        )
        self.assertEqual(
            tuple(
                schema["$defs"][item["$ref"].rsplit("/", 1)[1]]["allOf"][1][
                    "properties"
                ]["role"]["const"]
                for item in schema["properties"]["githubAPIResponses"]["prefixItems"]
            ),
            API_ROLES,
        )
        for conditional in schema["allOf"]:
            kind = conditional["if"]["properties"]["kind"]["const"]
            prefix = conditional["then"]["properties"]["requiredAssets"][
                "prefixItems"
            ]
            roles = tuple(
                schema["$defs"][item["$ref"].rsplit("/", 1)[1]]["allOf"][1][
                    "properties"
                ]["role"]["const"]
                for item in prefix
            )
            self.assertEqual(roles, REQUIRED_ASSET_ROLES[kind])
            if kind == "design":
                for item in prefix:
                    definition = schema["$defs"][item["$ref"].rsplit("/", 1)[1]]
                    properties = definition["allOf"][1]["properties"]
                    role = properties["role"]["const"]
                    if role in REQUIRED_ROLE_FILENAMES:
                        self.assertEqual(
                            properties["name"]["const"],
                            REQUIRED_ROLE_FILENAMES[role],
                        )


if __name__ == "__main__":
    unittest.main()
