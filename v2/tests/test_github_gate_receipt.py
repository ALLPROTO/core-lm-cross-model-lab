from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

import jsonschema

from v2.collect_github_gate_receipt import (
    DirectGitHubGateTransport,
    GitHubGateCollectionError,
    HTTPSCapture,
    collect_github_gate_receipt_to_path,
    load_token_from_environment,
)
from v2.github_gate_receipt import (
    EVIDENCE_BOUNDARY,
    API_ROLES,
    GITHUB_API_VERSION,
    GitHubGateReceiptError,
    REQUIRED_LINUX_JOB_NAME,
    REQUIRED_MACOS_JOB_NAME,
    REQUIRED_REVIEW_DECLARATION,
    REQUIRED_WORKFLOW_NAME,
    REQUIRED_WORKFLOW_PATH,
    verify_github_gate_receipt,
)
from v2.release_receipt import canonical_json_bytes


REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
HTML_BASE = f"https://github.com/{REPOSITORY}"
API_BASE = f"https://api.github.com/repos/{REPOSITORY}"
PR = 19
RUN_ID = 30123456789
WORKFLOW_ID = 777001
COMMIT = "a" * 40
REVIEWER = "independent-reviewer"
WORKFLOW_NAME = REQUIRED_WORKFLOW_NAME
WORKFLOW_PATH = REQUIRED_WORKFLOW_PATH
TOKEN = "gate-unit-placeholder-token"
NOW = "2026-08-03T12:10:00Z"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _archived(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _headers(
    second: int,
    role: str,
    *,
    link: str | None = None,
    status: int = 200,
    base: datetime | None = None,
) -> bytes:
    reason = "OK" if status == 200 else "Found"
    observed = (base or datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)) + timedelta(
        seconds=second
    )
    lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Date: {observed.strftime('%a, %d %b %Y %H:%M:%S GMT')}",
        "Content-Type: application/json; charset=utf-8",
        f"X-GitHub-Api-Version-Selected: {GITHUB_API_VERSION}",
        f"X-GitHub-Request-Id: GATE-{role}-{second}",
    ]
    if link is not None:
        lines.append(f"Link: {link}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _endpoints() -> dict[str, str]:
    return {
        "pull-request": f"{API_BASE}/pulls/{PR}",
        "workflow-run": f"{API_BASE}/actions/runs/{RUN_ID}",
        "workflow-jobs": (
            f"{API_BASE}/actions/runs/{RUN_ID}/jobs?filter=all&per_page=100&page=1"
        ),
        "workflow-artifacts": (
            f"{API_BASE}/actions/runs/{RUN_ID}/artifacts?per_page=100&page=1"
        ),
        "reviews": f"{API_BASE}/pulls/{PR}/reviews?per_page=100&page=1",
    }


def _base_bodies(
    *,
    linux_artifact_sha256: str = "b" * 64,
    macos_artifact_sha256: str = "c" * 64,
) -> dict[str, Any]:
    endpoints = _endpoints()
    return {
        "pull-request": {
            "number": PR,
            "url": endpoints["pull-request"],
            "html_url": f"{HTML_BASE}/pull/{PR}",
            "state": "open",
            "head": {"sha": COMMIT, "repo": {"full_name": REPOSITORY}},
        },
        "workflow-run": {
            "id": RUN_ID,
            "workflow_id": WORKFLOW_ID,
            "url": endpoints["workflow-run"],
            "html_url": f"{HTML_BASE}/actions/runs/{RUN_ID}",
            "head_sha": COMMIT,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": REPOSITORY},
        },
        "workflow-jobs": {
            "total_count": 2,
            "jobs": [
                {
                    "id": 81001,
                    "run_id": RUN_ID,
                    "run_url": endpoints["workflow-run"],
                    "head_sha": COMMIT,
                    "name": REQUIRED_LINUX_JOB_NAME,
                    "status": "completed",
                    "conclusion": "success",
                    "labels": ["ubuntu-24.04"],
                },
                {
                    "id": 81002,
                    "run_id": RUN_ID,
                    "run_url": endpoints["workflow-run"],
                    "head_sha": COMMIT,
                    "name": REQUIRED_MACOS_JOB_NAME,
                    "status": "completed",
                    "conclusion": "success",
                    "labels": ["macos-15"],
                },
            ],
        },
        "workflow-artifacts": {
            "total_count": 2,
            "artifacts": [
                {
                    "id": 91001,
                    "name": f"blind-v2-linux-development-{RUN_ID}-1",
                    "expired": False,
                    "archive_download_url": f"{API_BASE}/actions/artifacts/91001/zip",
                    "workflow_run": {"id": RUN_ID},
                    "digest": "sha256:" + linux_artifact_sha256,
                    "size_in_bytes": 4096,
                },
                {
                    "id": 91002,
                    "name": f"blind-v2-macos-development-{RUN_ID}-1",
                    "expired": False,
                    "archive_download_url": f"{API_BASE}/actions/artifacts/91002/zip",
                    "workflow_run": {"id": RUN_ID},
                    "digest": "sha256:" + macos_artifact_sha256,
                    "size_in_bytes": 4096,
                }
            ],
        },
        "reviews": [
            {
                "id": 71000,
                "user": {"login": "ALLPROTO", "type": "User"},
                "state": "COMMENTED",
                "commit_id": COMMIT,
                "submitted_at": "2026-08-03T11:57:00Z",
                "pull_request_url": endpoints["pull-request"],
            },
            {
                "id": 71001,
                "user": {"login": REVIEWER, "type": "User"},
                "state": "APPROVED",
                "commit_id": COMMIT,
                "body": REQUIRED_REVIEW_DECLARATION,
                "submitted_at": "2026-08-03T11:59:00Z",
                "pull_request_url": endpoints["pull-request"],
            },
        ],
    }


class FakeTransport:
    def __init__(
        self,
        bodies: Mapping[str, Any],
        *,
        status: int = 200,
        links: Mapping[str, str] | None = None,
        date_step: int = 1,
        base: datetime | None = None,
    ) -> None:
        self.bodies = bodies
        self.status = status
        self.links = dict(links or {})
        self.date_step = date_step
        self.base = base or datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)
        self.calls: list[tuple[str, str | None]] = []

    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture:
        self.calls.append((url, token))
        role = API_ROLES[len(self.calls) - 1]
        if url != _endpoints()[role]:
            raise AssertionError(f"unexpected endpoint for {role}: {url}")
        second = (len(self.calls) - 1) * self.date_step
        captured = self.base + timedelta(
            seconds=second + 1
        )
        status = self.status if len(self.calls) == 1 else 200
        return HTTPSCapture(
            status,
            _headers(
                second,
                role,
                link=self.links.get(role),
                status=status,
                base=self.base,
            ),
            _json_bytes(self.bodies[role]),
            captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


def _expected() -> dict[str, Any]:
    return {
        "expected_repository": REPOSITORY,
        "expected_pull_request_number": PR,
        "expected_implementation_commit": COMMIT,
        "expected_reviewer_login": REVIEWER,
        "expected_workflow_run_id": RUN_ID,
        "expected_workflow_name": WORKFLOW_NAME,
        "expected_workflow_path": WORKFLOW_PATH,
    }


def _collect(root: Path, bodies: Mapping[str, Any], **transport_args: Any) -> bytes:
    output = root / "github-gate-receipt.json"
    transport = FakeTransport(bodies, **transport_args)
    collect_github_gate_receipt_to_path(
        output=output,
        repository=REPOSITORY,
        pull_request_number=PR,
        implementation_commit=COMMIT,
        reviewer_login=REVIEWER,
        workflow_run_id=RUN_ID,
        workflow_name=WORKFLOW_NAME,
        workflow_path=WORKFLOW_PATH,
        transport=transport,
        now=lambda: NOW,
    )
    return output.read_bytes()


def _rehash(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("contentSHA256", None)
    receipt["contentSHA256"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return canonical_json_bytes(receipt) + b"\n"


def _mutate_body(
    receipt: dict[str, Any], role: str, mutation: Any
) -> None:
    record = next(item for item in receipt["githubAPIResponses"] if item["role"] == role)
    body = json.loads(base64.b64decode(record["responseBody"]["dataBase64"]))
    mutation(body)
    record["responseBody"] = _archived(_json_bytes(body))


class GitHubGateReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_success_is_canonical_schema_valid_and_offline_verifiable(self) -> None:
        raw = _collect(self.root, _base_bodies())
        receipt = json.loads(raw)
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/github-gate-receipt.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema).validate(receipt)
        artifact_schema = schema["properties"]["ciGate"]["properties"][
            "artifactSHA256"
        ]
        self.assertEqual(len(artifact_schema["prefixItems"]), 2)
        self.assertIs(artifact_schema["items"], False)
        verified = verify_github_gate_receipt(raw, **_expected())
        self.assertEqual(receipt["evidenceBoundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(verified.evidence_boundary, EVIDENCE_BOUNDARY)
        self.assertEqual(verified.reviewer_login, REVIEWER)
        self.assertEqual(verified.job_ids, (81001, 81002))
        self.assertEqual(verified.linux_job_ids, (81001,))
        self.assertEqual(verified.macos_arm64_job_ids, (81002,))
        self.assertEqual(
            verified.artifact_sha256,
            (
                (f"blind-v2-linux-development-{RUN_ID}-1", "b" * 64),
                (f"blind-v2-macos-development-{RUN_ID}-1", "c" * 64),
            ),
        )
        self.assertEqual(verified.receipt_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["capturePolicy"]["artifactBytesArchived"], False)

    def test_evidence_boundary_is_required_and_cannot_claim_origin_attestation(self) -> None:
        raw = _collect(self.root, _base_bodies())
        receipt = json.loads(raw)
        del receipt["evidenceBoundary"]
        with self.assertRaisesRegex(GitHubGateReceiptError, "fields differ"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

        receipt = json.loads(raw)
        receipt["evidenceBoundary"] = "GITHUB_SIGNED_ORIGIN_ATTESTATION"
        with self.assertRaisesRegex(GitHubGateReceiptError, "evidence boundary differs"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

    def test_token_proxy_environment_and_exact_five_requests_leave_no_secret(self) -> None:
        output = self.root / "receipt.json"
        transport = FakeTransport(_base_bodies())
        with mock.patch.dict(
            os.environ,
            {
                "UNIT_GATE_TOKEN": TOKEN,
                "HTTPS_PROXY": "https://proxy.example.invalid:443",
                "NO_PROXY": "",
            },
            clear=False,
        ):
            token = load_token_from_environment("UNIT_GATE_TOKEN")
            collect_github_gate_receipt_to_path(
                output=output,
                repository=REPOSITORY,
                pull_request_number=PR,
                implementation_commit=COMMIT,
                reviewer_login=REVIEWER,
                workflow_run_id=RUN_ID,
                workflow_name=WORKFLOW_NAME,
                workflow_path=WORKFLOW_PATH,
                token=token,
                transport=transport,
                now=lambda: NOW,
            )
        self.assertEqual([url for url, _ in transport.calls], list(_endpoints().values()))
        self.assertTrue(all(token == TOKEN for _, token in transport.calls))
        self.assertNotIn(TOKEN.encode(), output.read_bytes())

        attempted: list[tuple[str, int]] = []

        def refuse(address: tuple[str, int], timeout: float) -> None:
            del timeout
            attempted.append(address)
            raise OSError("offline fixture")

        direct = DirectGitHubGateTransport()
        with mock.patch(
            "v2.collect_github_gate_receipt.socket.create_connection", side_effect=refuse
        ):
            with self.assertRaisesRegex(GitHubGateCollectionError, "direct GitHub"):
                direct.request(_endpoints()["workflow-jobs"])
        self.assertEqual(attempted, [("api.github.com", 443)])

    def test_output_is_never_overwritten_and_redirect_is_not_retried(self) -> None:
        output = self.root / "receipt.json"
        output.write_bytes(b"keep\n")
        transport = FakeTransport(_base_bodies())
        with self.assertRaisesRegex(GitHubGateCollectionError, "already exists"):
            collect_github_gate_receipt_to_path(
                output=output,
                repository=REPOSITORY,
                pull_request_number=PR,
                implementation_commit=COMMIT,
                reviewer_login=REVIEWER,
                workflow_run_id=RUN_ID,
                workflow_name=WORKFLOW_NAME,
                workflow_path=WORKFLOW_PATH,
                transport=transport,
                now=lambda: NOW,
            )
        self.assertEqual(output.read_bytes(), b"keep\n")
        self.assertEqual(transport.calls, [])

        transport = FakeTransport(_base_bodies(), status=302)
        with self.assertRaisesRegex(GitHubGateCollectionError, "redirects"):
            collect_github_gate_receipt_to_path(
                output=self.root / "new.json",
                repository=REPOSITORY,
                pull_request_number=PR,
                implementation_commit=COMMIT,
                reviewer_login=REVIEWER,
                workflow_run_id=RUN_ID,
                workflow_name=WORKFLOW_NAME,
                workflow_path=WORKFLOW_PATH,
                transport=transport,
                now=lambda: NOW,
            )
        self.assertEqual(len(transport.calls), 1)
        self.assertFalse((self.root / "new.json").exists())

    def test_owner_bot_wrong_commit_and_later_invalidation_are_rejected(self) -> None:
        bodies = _base_bodies()
        with self.assertRaisesRegex(GitHubGateCollectionError, "did not pass"):
            collect_github_gate_receipt_to_path(
                output=self.root / "owner.json",
                repository=REPOSITORY,
                pull_request_number=PR,
                implementation_commit=COMMIT,
                reviewer_login="ALLPROTO",
                workflow_run_id=RUN_ID,
                workflow_name=WORKFLOW_NAME,
                workflow_path=WORKFLOW_PATH,
                transport=FakeTransport(bodies),
                now=lambda: NOW,
            )

        bodies = _base_bodies()
        bodies["reviews"][1]["user"]["type"] = "Bot"
        with self.assertRaises(GitHubGateCollectionError):
            _collect(self.root, bodies)

        bodies = _base_bodies()
        bodies["reviews"][1]["body"] = "Looks good to me."
        with self.assertRaisesRegex(GitHubGateCollectionError, "did not pass"):
            _collect(self.root, bodies)

        bodies = _base_bodies()
        bodies["reviews"][1]["commit_id"] = "c" * 40
        with self.assertRaises(GitHubGateCollectionError):
            _collect(self.root, bodies)

        bodies = _base_bodies()
        bodies["reviews"].append(
            {
                "id": 71002,
                "user": {"login": REVIEWER, "type": "User"},
                "state": "CHANGES_REQUESTED",
                "commit_id": COMMIT,
                "submitted_at": "2026-08-03T12:00:00Z",
                "pull_request_url": _endpoints()["pull-request"],
            }
        )
        with self.assertRaises(GitHubGateCollectionError):
            _collect(self.root, bodies)

    def test_workflow_and_every_job_are_bound_to_exact_head_path_and_success(self) -> None:
        mutations = [
            lambda body: body.update({"head_sha": "d" * 40}),
            lambda body: body.update({"path": ".github/workflows/other.yml"}),
            lambda body: body.update({"conclusion": "failure"}),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(run_mutation=index):
                bodies = _base_bodies()
                mutation(bodies["workflow-run"])
                with self.assertRaises(GitHubGateCollectionError):
                    _collect(self.root, bodies)

        for conclusion in ("skipped", "cancelled", "failure", None):
            with self.subTest(job_conclusion=conclusion):
                bodies = _base_bodies()
                bodies["workflow-jobs"]["jobs"][0]["conclusion"] = conclusion
                with self.assertRaises(GitHubGateCollectionError):
                    _collect(self.root, bodies)

        bodies = _base_bodies()
        bodies["workflow-jobs"]["jobs"][1]["labels"] = ["macos-14"]
        with self.assertRaisesRegex(GitHubGateCollectionError, "did not pass"):
            _collect(self.root, bodies)

        bodies = _base_bodies()
        bodies["workflow-jobs"]["jobs"][0]["name"] = "looks-valid-but-is-not-registered"
        with self.assertRaisesRegex(GitHubGateCollectionError, "did not pass"):
            _collect(self.root, bodies)

    def test_caller_cannot_substitute_a_trivial_workflow(self) -> None:
        raw = _collect(self.root, _base_bodies())
        substituted = dict(_expected())
        substituted["expected_workflow_name"] = "Trivial green workflow"
        substituted["expected_workflow_path"] = ".github/workflows/trivial.yml"
        with self.assertRaisesRegex(GitHubGateReceiptError, "registered CI gate"):
            verify_github_gate_receipt(raw, **substituted)

    def test_pagination_and_capture_window_fail_closed(self) -> None:
        link = (
            f'<{_endpoints()["reviews"][:-1]}2>; rel="next", '
            f'<{_endpoints()["reviews"][:-1]}2>; rel="last"'
        )
        with self.assertRaisesRegex(GitHubGateCollectionError, "offline verification"):
            _collect(self.root, _base_bodies(), links={"reviews": link})
        with self.assertRaisesRegex(GitHubGateCollectionError, "offline verification"):
            _collect(self.root, _base_bodies(), date_step=31)

    def test_offline_tampering_summary_and_raw_bodies_are_rejected(self) -> None:
        raw = _collect(self.root, _base_bodies())
        receipt = json.loads(raw)
        receipt["ciGate"]["linuxJobIds"] = [81002]
        with self.assertRaisesRegex(GitHubGateReceiptError, "derived CI"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

        receipt = json.loads(raw)
        _mutate_body(
            receipt,
            "workflow-jobs",
            lambda body: body["jobs"][0].update({"conclusion": "skipped"}),
        )
        with self.assertRaisesRegex(GitHubGateReceiptError, "skipped"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

        receipt = json.loads(raw)
        receipt["contentSHA256"] = "0" * 64
        with self.assertRaisesRegex(GitHubGateReceiptError, "contentSHA256"):
            verify_github_gate_receipt(canonical_json_bytes(receipt) + b"\n", **_expected())

        receipt = json.loads(raw)
        record = receipt["githubAPIResponses"][0]
        record["responseBody"] = _archived(b'{"number":NaN}')
        with self.assertRaisesRegex(GitHubGateReceiptError, "non-finite"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

    def test_artifact_metadata_digest_is_bound_but_bytes_are_not_claimed(self) -> None:
        raw = _collect(self.root, _base_bodies())
        receipt = json.loads(raw)
        _mutate_body(
            receipt,
            "workflow-artifacts",
            lambda body: body["artifacts"][0].update({"digest": "sha512:" + "a" * 128}),
        )
        with self.assertRaisesRegex(GitHubGateReceiptError, "algorithm"):
            verify_github_gate_receipt(_rehash(receipt), **_expected())

        missing = _base_bodies()
        missing["workflow-artifacts"]["artifacts"].pop()
        missing["workflow-artifacts"]["total_count"] = 1
        missing_root = self.root / "missing-platform-artifact"
        missing_root.mkdir()
        with self.assertRaises(GitHubGateCollectionError) as missing_error:
            _collect(missing_root, missing)
        self.assertIsInstance(missing_error.exception.__cause__, GitHubGateReceiptError)
        self.assertRegex(
            str(missing_error.exception.__cause__), "exactly Linux and macOS"
        )

        wrong_name = _base_bodies()
        wrong_name["workflow-artifacts"]["artifacts"][0]["name"] = (
            "blind-v2-linux-development-999-1"
        )
        wrong_name_root = self.root / "wrong-platform-artifact-name"
        wrong_name_root.mkdir()
        with self.assertRaises(GitHubGateCollectionError) as wrong_name_error:
            _collect(wrong_name_root, wrong_name)
        self.assertIsInstance(
            wrong_name_error.exception.__cause__, GitHubGateReceiptError
        )
        self.assertRegex(
            str(wrong_name_error.exception.__cause__), "platform/run prefix"
        )

        mixed_attempt = _base_bodies()
        mixed_attempt["workflow-artifacts"]["artifacts"][1]["name"] = (
            f"blind-v2-macos-development-{RUN_ID}-2"
        )
        mixed_attempt_root = self.root / "mixed-artifact-attempt"
        mixed_attempt_root.mkdir()
        with self.assertRaises(GitHubGateCollectionError) as mixed_attempt_error:
            _collect(mixed_attempt_root, mixed_attempt)
        self.assertRegex(
            str(mixed_attempt_error.exception.__cause__), "same run attempt"
        )

    def test_api_allowlist_and_query_contract_are_exact(self) -> None:
        direct = DirectGitHubGateTransport()
        for url in (
            "https://github.com/ALLPROTO/core-lm-cross-model-lab/pull/19",
            f"{API_BASE}/pulls/{PR}/reviews?per_page=99&page=1",
            f"{API_BASE}/pulls/{PR}/reviews?per_page=100&page=2",
        ):
            with self.subTest(url=url):
                with self.assertRaises(GitHubGateCollectionError):
                    direct.request(url)
        with self.assertRaises(GitHubGateCollectionError):
            load_token_from_environment("BAD-NAME")


if __name__ == "__main__":
    unittest.main()
