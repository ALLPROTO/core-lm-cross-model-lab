from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Mapping, Sequence
from unittest import mock

import v3.tests.test_release_receipt as release_fixture
from v3.collect_release_receipt import (
    CommandResult,
    DirectGitHubTransport,
    HTTPSCapture,
    ReleaseReceiptCollectionError,
    SignatureVerificationError,
    collect_release_receipt_to_path,
    load_token_from_environment,
)
from v3.release_receipt import (
    GITHUB_API_VERSION,
    REQUIRED_ASSET_ROLES,
    REQUIRED_ROLE_FILENAMES,
    ReleaseReceiptError,
    verify_late_release_receipt_for_closeout,
    verify_release_receipt,
)


REPOSITORY = "ALLPROTO/core-lm-benchmark"
API_BASE = f"https://api.github.com/repos/{REPOSITORY}"
HTML_BASE = f"https://github.com/{REPOSITORY}"
TAG = "blind-v3-test-release"
TREE = "2" * 40
DEADLINE = "2026-08-03T13:00:00Z"
PUBLISHED = "2026-08-03T11:00:00Z"
SERVER_DATE = "2026-08-03T12:00:00Z"
CAPTURED = "2026-08-03T12:01:00Z"
NOW = "2026-08-03T12:10:00Z"
RELEASE_ID = 987654321
TOKEN = "unit-test-placeholder-token"


def _git_oid(kind: str, payload: bytes) -> str:
    framed = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
    try:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover
        return hashlib.sha1(framed).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _headers(request_id: str, status: int = 200) -> bytes:
    reason = "OK" if status == 200 else "Found"
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Date: Mon, 03 Aug 2026 12:00:00 GMT\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"X-GitHub-Api-Version-Selected: {GITHUB_API_VERSION}\r\n"
        f"X-GitHub-Request-Id: {request_id}\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
    ).encode("ascii")


class FakeGit:
    def __init__(
        self,
        *,
        tag_oid: str,
        commit: str,
        tree: str,
        commit_payload: bytes,
        tag_payload: bytes,
        fingerprint: str,
        verify_exit: int = 0,
    ) -> None:
        self.tag_oid = tag_oid
        self.commit = commit
        self.tree = tree
        self.commit_payload = commit_payload
        self.tag_payload = tag_payload
        self.fingerprint = fingerprint
        self.verify_exit = verify_exit
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str] | None, bool]] = []
        self.allowed_signers_bytes: bytes | None = None

    def run(
        self,
        arguments: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        merge_stderr: bool = False,
    ) -> CommandResult:
        args = tuple(arguments)
        self.calls.append((args, environment, merge_stderr))
        if args == ("rev-parse", "--verify", f"refs/tags/{TAG}^{{tag}}"):
            return CommandResult(0, (self.tag_oid + "\n").encode("ascii"))
        if args == ("rev-parse", "--verify", f"{self.commit}^{{tree}}"):
            return CommandResult(0, (self.tree + "\n").encode("ascii"))
        if args == ("cat-file", "commit", self.commit):
            return CommandResult(0, self.commit_payload)
        if args == ("cat-file", "tag", self.tag_oid):
            return CommandResult(0, self.tag_payload)
        if args == ("--version",):
            return CommandResult(0, b"git version 2.50.1\n")
        if "verify-tag" in args:
            allowed_option = next(
                item
                for item in args
                if item.startswith("gpg.ssh.allowedSignersFile=")
            )
            self.allowed_signers_bytes = Path(
                allowed_option.split("=", 1)[1]
            ).read_bytes()
            transcript = (
                f"Good \"git\" signature for release-signer with ED25519 key "
                f"{self.fingerprint}\n"
            ).encode("ascii")
            if self.verify_exit:
                transcript = b"Could not verify signature\n"
            return CommandResult(self.verify_exit, transcript)
        raise AssertionError(f"unexpected Git call: {args!r}")


class FakeTransport:
    def __init__(self, bodies: Mapping[str, Mapping[str, object]], *, status: int = 200) -> None:
        self.bodies = bodies
        self.status = status
        self.calls: list[tuple[str, str | None]] = []

    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture:
        self.calls.append((url, token))
        if self.status != 200:
            return HTTPSCapture(
                self.status,
                _headers("UNIT-REDIRECT", self.status),
                b"{}",
                CAPTURED,
            )
        role = next(
            role
            for role, expected_url in self.bodies["_urls"].items()  # type: ignore[index,union-attr]
            if expected_url == url
        )
        raw_body = _json_bytes(self.bodies[role])
        raw_headers = _headers(f"UNIT-{role}").replace(b"Content-Length: 2", f"Content-Length: {len(raw_body)}".encode())
        return HTTPSCapture(200, raw_headers, raw_body, CAPTURED)


class FakeReleaseAttestationVerifier:
    def __init__(self, fixture: "CollectorFixture") -> None:
        self.fixture = fixture
        self.calls: list[tuple[str, str, str | None]] = []

    def verify(self, *, repository: str, tag: str, token: str | None) -> bytes:
        self.calls.append((repository, tag, token))
        release = self.fixture.bodies["release"]
        api_assets = release["assets"]  # type: ignore[index]
        assets = [
            {
                "name": item["name"],
                "sha256": item["digest"].removeprefix("sha256:"),
            }
            for item in api_assets  # type: ignore[union-attr]
        ]
        return release_fixture._release_attestation_output(
            repository=repository,
            tag=tag,
            commit=self.fixture.commit,
            release_id=RELEASE_ID,
            assets=assets,
            attested_at=release["published_at"],  # type: ignore[index]
        )


class CollectorFixture:
    def __init__(self, root: Path) -> None:
        self.asset_root = root / "assets"
        self.asset_root.mkdir()
        (
            self.private_key,
            self.public_key,
            self.allowed_signers,
            self.fingerprint,
            self.public_key_sha256,
        ) = release_fixture._generate_test_key(root, "signer")
        self.commit_payload = (
            f"tree {TREE}\n"
            "author Unit Test <unit@example.invalid> 1785751200 +0000\n"
            "committer Unit Test <unit@example.invalid> 1785751200 +0000\n"
            "\npublication fixture\n"
        ).encode("ascii")
        self.commit = _git_oid("commit", self.commit_payload)
        self.signed_payload = (
            f"object {self.commit}\n"
            "type commit\n"
            f"tag {TAG}\n"
            "tagger Unit Test <unit@example.invalid> 1785751200 +0000\n"
            "\npublication fixture\n"
        ).encode("ascii")
        self.signature = release_fixture._sign_payload(
            self.private_key,
            self.signed_payload,
        )
        self.tag_payload = self.signed_payload + self.signature
        self.tag_oid = _git_oid("tag", self.tag_payload)
        self.bindings: list[str] = []
        api_assets: list[dict[str, object]] = []
        for index, role in enumerate(REQUIRED_ASSET_ROLES["design"]):
            name = REQUIRED_ROLE_FILENAMES.get(
                role, role.replace("-", "_") + ".bin"
            )
            payload = f"exact design {role}\n".encode("ascii")
            (self.asset_root / name).write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            asset_id = 1000 + index
            self.bindings.append(f"{role}={name}")
            api_assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "url": f"{API_BASE}/releases/assets/{asset_id}",
                    "browser_download_url": f"{HTML_BASE}/releases/download/{TAG}/{name}",
                    "state": "uploaded",
                    "size": len(payload),
                    "digest": f"sha256:{digest}",
                    "created_at": "2026-08-03T10:00:00Z",
                    "updated_at": "2026-08-03T10:30:00Z",
                }
            )
        urls = {
            "commit": f"{API_BASE}/git/commits/{self.commit}",
            "release": f"{API_BASE}/releases/{RELEASE_ID}",
            "tag-object": f"{API_BASE}/git/tags/{self.tag_oid}",
            "tag-ref": f"{API_BASE}/git/ref/tags/{TAG}",
        }
        self.bodies: dict[str, Mapping[str, object]] = {
            "_urls": urls,
            "commit": {
                "sha": self.commit,
                "url": urls["commit"],
                "tree": {"sha": TREE, "url": f"{API_BASE}/git/trees/{TREE}"},
            },
            "release": {
                "id": RELEASE_ID,
                "url": urls["release"],
                "html_url": f"{HTML_BASE}/releases/tag/{TAG}",
                "tag_name": TAG,
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "published_at": PUBLISHED,
                "assets": api_assets,
            },
            "tag-object": {
                "sha": self.tag_oid,
                "tag": TAG,
                "url": urls["tag-object"],
                "object": {
                    "type": "commit",
                    "sha": self.commit,
                    "url": urls["commit"],
                },
                "verification": {
                    "verified": True,
                    "reason": "valid",
                    "signature": self.signature.decode("ascii"),
                    "payload": self.signed_payload.decode("ascii"),
                    "verified_at": "2026-08-03T11:50:00Z",
                },
            },
            "tag-ref": {
                "ref": f"refs/tags/{TAG}",
                "object": {
                    "type": "tag",
                    "sha": self.tag_oid,
                    "url": urls["tag-object"],
                },
            },
        }
        self.attestation_verifier = FakeReleaseAttestationVerifier(self)

    def git(self, verify_exit: int = 0) -> FakeGit:
        return FakeGit(
            tag_oid=self.tag_oid,
            commit=self.commit,
            tree=TREE,
            commit_payload=self.commit_payload,
            tag_payload=self.tag_payload,
            fingerprint=self.fingerprint,
            verify_exit=verify_exit,
        )

    def use_kind(self, kind: str, *, published_at: str) -> None:
        for path in self.asset_root.iterdir():
            path.unlink()
        self.bindings = []
        api_assets: list[dict[str, object]] = []
        for index, role in enumerate(REQUIRED_ASSET_ROLES[kind]):
            name = REQUIRED_ROLE_FILENAMES.get(
                role, role.replace("-", "_") + ".bin"
            )
            payload = f"exact {kind} {role}\n".encode("ascii")
            (self.asset_root / name).write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            asset_id = 2000 + index
            self.bindings.append(f"{role}={name}")
            api_assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "url": f"{API_BASE}/releases/assets/{asset_id}",
                    "browser_download_url": f"{HTML_BASE}/releases/download/{TAG}/{name}",
                    "state": "uploaded",
                    "size": len(payload),
                    "digest": f"sha256:{digest}",
                    "created_at": "2026-08-03T10:00:00Z",
                    "updated_at": "2026-08-03T10:30:00Z",
                }
            )
        release = dict(self.bodies["release"])
        release["published_at"] = published_at
        release["assets"] = api_assets
        self.bodies["release"] = release

    def arguments(self) -> dict[str, object]:
        return {
            "repository": REPOSITORY,
            "kind": "design",
            "tag": TAG,
            "commit": self.commit,
            "tree": TREE,
            "deadline": DEADLINE,
            "signature_type": "SSH",
            "key_fingerprint": self.fingerprint,
            "public_key_path": self.public_key,
            "repository_root": self.public_key.parent,
            "release_id": RELEASE_ID,
            "asset_root": self.asset_root,
            "asset_bindings": self.bindings,
            "release_attestation_verifier": self.attestation_verifier,
            "cryptographic_attestation_verifier": (
                release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER
            ),
            "now": lambda: NOW,
        }


class ReleaseReceiptCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = CollectorFixture(self.root)
        self.trust_patch = mock.patch.multiple(
            "v3.release_receipt",
            TRACKED_SSH_PUBLIC_KEY_PATH=self.fixture.public_key,
            TRACKED_SSH_ALLOWED_SIGNERS_PATH=self.fixture.allowed_signers,
        )
        self.trust_patch.start()

    def tearDown(self) -> None:
        self.trust_patch.stop()
        self.temporary.cleanup()

    def test_collects_four_exact_endpoints_self_verifies_and_never_archives_secret(self) -> None:
        git = self.fixture.git()
        transport = FakeTransport(self.fixture.bodies)
        output = self.root / "receipt.json"
        with mock.patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "http://proxy.example.invalid:9999",
                "HTTP_PROXY": "http://proxy.example.invalid:9999",
                "NO_PROXY": "",
                "UNIT_GITHUB_TOKEN": TOKEN,
            },
            clear=False,
        ):
            token = load_token_from_environment("UNIT_GITHUB_TOKEN")
            digest = collect_release_receipt_to_path(
                output=output,
                token=token,
                git_runner=git,
                transport=transport,
                **self.fixture.arguments(),
            )
        raw = output.read_bytes()
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.assertNotIn(TOKEN.encode("ascii"), raw)
        self.assertEqual(len(transport.calls), 4)
        self.assertEqual(
            [url for url, _token in transport.calls],
            list(self.fixture.bodies["_urls"].values()),
        )
        self.assertTrue(all(token == TOKEN for _url, token in transport.calls))
        self.assertEqual(
            self.fixture.attestation_verifier.calls,
            [(REPOSITORY, TAG, TOKEN)],
        )
        for _args, environment, _merge in git.calls:
            if environment is not None:
                self.assertNotIn("HTTP_PROXY", environment)
                self.assertNotIn("HTTPS_PROXY", environment)
                self.assertNotIn("UNIT_GITHUB_TOKEN", environment)
                self.assertNotIn(TOKEN, environment.values())
        public_key_line, _fingerprint = release_fixture._parse_ed25519_public_key(
            self.fixture.public_key.read_bytes()
        )
        self.assertEqual(
            git.allowed_signers_bytes,
            b"release-signer " + public_key_line + b"\n",
        )
        verified = verify_release_receipt(
            raw,
            self.fixture.asset_root,
            expected_repository=REPOSITORY,
            expected_kind="design",
            expected_tag=TAG,
            expected_commit=self.fixture.commit,
            expected_tree=TREE,
            expected_deadline=DEADLINE,
            expected_signature_type="SSH",
            expected_key_fingerprint=self.fixture.fingerprint,
            expected_public_key_sha256=self.fixture.public_key_sha256,
            trusted_ssh_public_key_path=self.fixture.public_key,
            trusted_ssh_allowed_signers_path=self.fixture.allowed_signers,
            cryptographic_attestation_verifier=(
                release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER
            ),
        )
        self.assertEqual(verified.release_id, RELEASE_ID)

    def test_existing_output_is_not_overwritten_and_collection_does_not_start(self) -> None:
        output = self.root / "receipt.json"
        output.write_bytes(b"keep me\n")
        git = self.fixture.git()
        transport = FakeTransport(self.fixture.bodies)
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "already exists"):
            collect_release_receipt_to_path(
                output=output,
                git_runner=git,
                transport=transport,
                **self.fixture.arguments(),
            )
        self.assertEqual(output.read_bytes(), b"keep me\n")
        self.assertEqual(git.calls, [])
        self.assertEqual(transport.calls, [])

    def test_non_ssh_signature_type_is_rejected_before_git_or_network(self) -> None:
        arguments = self.fixture.arguments()
        arguments["signature_type"] = "RSA"
        git = self.fixture.git()
        transport = FakeTransport(self.fixture.bodies)
        output = self.root / "receipt.json"
        with self.assertRaisesRegex(
            ReleaseReceiptCollectionError, "signature type must be SSH"
        ):
            collect_release_receipt_to_path(
                output=output,
                git_runner=git,
                transport=transport,
                **arguments,
            )
        self.assertEqual(git.calls, [])
        self.assertEqual(transport.calls, [])
        self.assertFalse(output.exists())

    def test_missing_system_ssh_keygen_fails_before_network_or_output(self) -> None:
        git = self.fixture.git()
        transport = FakeTransport(self.fixture.bodies)
        output = self.root / "receipt.json"
        with mock.patch(
            "v3.collect_release_receipt.SSH_KEYGEN_PATH",
            self.root / "missing-ssh-keygen",
        ), self.assertRaisesRegex(
            ReleaseReceiptCollectionError, "ssh-keygen is unavailable"
        ):
            collect_release_receipt_to_path(
                output=output,
                git_runner=git,
                transport=transport,
                **self.fixture.arguments(),
            )
        self.assertEqual(transport.calls, [])
        self.assertFalse(output.exists())

    def test_late_evidence_can_be_archived_only_as_closeout_observation(self) -> None:
        late_deadline = "2026-08-03T12:00:00Z"
        self.fixture.use_kind("evidence", published_at=late_deadline)
        arguments = self.fixture.arguments()
        arguments["kind"] = "evidence"
        arguments["deadline"] = late_deadline
        output = self.root / "late-observation.json"
        collect_release_receipt_to_path(
            output=output,
            git_runner=self.fixture.git(),
            transport=FakeTransport(self.fixture.bodies),
            late_closeout_observation=True,
            **arguments,
        )
        raw = output.read_bytes()
        verified = verify_late_release_receipt_for_closeout(
            raw,
            self.fixture.asset_root,
            expected_repository=REPOSITORY,
            expected_tag=TAG,
            expected_commit=self.fixture.commit,
            expected_tree=TREE,
            expected_deadline=late_deadline,
            expected_signature_type="SSH",
            expected_key_fingerprint=self.fixture.fingerprint,
            expected_public_key_sha256=self.fixture.public_key_sha256,
            trusted_ssh_public_key_path=self.fixture.public_key,
            trusted_ssh_allowed_signers_path=self.fixture.allowed_signers,
            cryptographic_attestation_verifier=(
                release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER
            ),
        )
        self.assertEqual(verified.kind, "evidence")
        with self.assertRaisesRegex(ReleaseReceiptError, "binding replay"):
            verify_release_receipt(
                raw,
                self.fixture.asset_root,
                expected_repository=REPOSITORY,
                expected_kind="evidence",
                expected_tag=TAG,
                expected_commit=self.fixture.commit,
                expected_tree=TREE,
                expected_deadline=late_deadline,
                expected_signature_type="SSH",
                expected_key_fingerprint=self.fixture.fingerprint,
                expected_public_key_sha256=self.fixture.public_key_sha256,
                trusted_ssh_public_key_path=self.fixture.public_key,
                trusted_ssh_allowed_signers_path=self.fixture.allowed_signers,
                cryptographic_attestation_verifier=(
                    release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER
                ),
            )

    def test_late_closeout_mode_rejects_on_time_and_non_evidence_releases(self) -> None:
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "only for evidence"):
            collect_release_receipt_to_path(
                output=self.root / "wrong-kind.json",
                git_runner=self.fixture.git(),
                transport=FakeTransport(self.fixture.bodies),
                late_closeout_observation=True,
                **self.fixture.arguments(),
            )
        self.fixture.use_kind("evidence", published_at=PUBLISHED)
        arguments = self.fixture.arguments()
        arguments["kind"] = "evidence"
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "offline verification"):
            collect_release_receipt_to_path(
                output=self.root / "on-time.json",
                git_runner=self.fixture.git(),
                transport=FakeTransport(self.fixture.bodies),
                late_closeout_observation=True,
                **arguments,
            )

    def test_nonzero_verify_tag_is_archived_as_failure_but_never_claimed_or_published(self) -> None:
        output = self.root / "receipt.json"
        failure_output = self.root / "signature-failure.json"
        git = self.fixture.git(verify_exit=7)
        transport = FakeTransport(self.fixture.bodies)
        with self.assertRaises(SignatureVerificationError) as caught:
            collect_release_receipt_to_path(
                output=output,
                signature_failure_output=failure_output,
                git_runner=git,
                transport=transport,
                **self.fixture.arguments(),
            )
        self.assertFalse(output.exists())
        self.assertEqual(transport.calls, [])
        self.assertEqual(caught.exception.record["status"], "FAILED")
        self.assertEqual(caught.exception.record["exitCode"], 7)
        transcript = base64.b64decode(
            caught.exception.record["transcript"]["dataBase64"]
        )
        self.assertIn(b"Could not verify", transcript)
        archived = json.loads(failure_output.read_bytes())
        self.assertEqual(archived["schemaVersion"], "corelm-git-signature-failure-v1")
        self.assertEqual(archived["status"], "FAILED")
        unsigned = dict(archived)
        observed_digest = unsigned.pop("contentSHA256")
        canonical = json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(observed_digest, hashlib.sha256(canonical).hexdigest())

    def test_redirect_fails_after_one_request_without_retry_or_output(self) -> None:
        output = self.root / "receipt.json"
        transport = FakeTransport(self.fixture.bodies, status=302)
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "redirects"):
            collect_release_receipt_to_path(
                output=output,
                git_runner=self.fixture.git(),
                transport=transport,
                **self.fixture.arguments(),
            )
        self.assertEqual(len(transport.calls), 1)
        self.assertFalse(output.exists())

    def test_asset_inventory_and_no_follow_policy_are_fail_closed(self) -> None:
        first_name = self.fixture.bindings[0].split("=", 1)[1]
        (self.fixture.asset_root / first_name).unlink()
        os.symlink(self.fixture.public_key, self.fixture.asset_root / first_name)
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "no-follow"):
            collect_release_receipt_to_path(
                output=self.root / "receipt.json",
                git_runner=self.fixture.git(),
                transport=FakeTransport(self.fixture.bodies),
                **self.fixture.arguments(),
            )

    def test_allowlist_and_token_name_are_strict(self) -> None:
        transport = DirectGitHubTransport()
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "allowlist"):
            transport.request("https://github.com/ALLPROTO/core-lm-benchmark")
        attempted: list[tuple[str, int]] = []

        def refuse_connection(address: tuple[str, int], timeout: float) -> None:
            del timeout
            attempted.append(address)
            raise OSError("offline unit fixture")

        with mock.patch.dict(
            os.environ,
            {"HTTPS_PROXY": "https://proxy.example.invalid:4443", "NO_PROXY": ""},
            clear=False,
        ), mock.patch(
            "v3.collect_release_receipt.socket.create_connection",
            side_effect=refuse_connection,
        ):
            with self.assertRaisesRegex(ReleaseReceiptCollectionError, "direct GitHub"):
                transport.request(f"{API_BASE}/releases/{RELEASE_ID}")
        self.assertEqual(attempted, [("api.github.com", 443)])
        with self.assertRaisesRegex(ReleaseReceiptCollectionError, "name"):
            load_token_from_environment("BAD-NAME")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseReceiptCollectionError, "absent"):
                load_token_from_environment("MISSING_TOKEN")


if __name__ == "__main__":
    unittest.main()
