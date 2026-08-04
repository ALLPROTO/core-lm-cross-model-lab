#!/usr/bin/env python3
"""Structural verification of an archived GitHub PR and Actions CI observation.

The collector checks GitHub's TLS certificate and hostname while collecting the
response bytes.  GitHub does not sign those response bytes, and the receipt does
not preserve a TLS transcript that can authenticate their origin offline.
Successful offline verification therefore establishes only canonical structure
and internal consistency, not GitHub-origin attestation, simultaneity, or state
persistence after the last archived ``Date`` value.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Mapping

from v4.release_receipt import canonical_json_bytes


SCHEMA_VERSION = "corelm-github-ci-gate-receipt-v2"
SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v4-author-verified"
GITHUB_API_VERSION = "2026-03-10"
EVIDENCE_BOUNDARY = (
    "DIRECT_TLS_VERIFIED_AT_COLLECTION;"
    "NO_GITHUB_RESPONSE_SIGNATURE;"
    "OFFLINE_STRUCTURAL_CONSISTENCY_ONLY"
)
API_ROLES = (
    "pull-request",
    "workflow-run",
    "workflow-jobs",
    "workflow-artifacts",
)
MAXIMUM_RECEIPT_BYTES = 128 * 1024 * 1024
MAXIMUM_API_BODY_BYTES = 32 * 1024 * 1024
MAXIMUM_HEADER_BYTES = 256 * 1024
MAXIMUM_CAPTURE_SPAN_SECONDS = 120
REQUIRED_WORKFLOW_NAME = "Author-verified v4 development controls"
REQUIRED_WORKFLOW_PATH = ".github/workflows/v4-development-controls.yml"
REQUIRED_LINUX_JOB_NAME = "Linux x86-64 locked runtime"
REQUIRED_LINUX_SCHEDULER_LABEL = "ubuntu-24.04"
REQUIRED_MACOS_JOB_NAME = "macOS arm64 clean clone"
REQUIRED_MACOS_SCHEDULER_LABEL = "macos-15"
REQUIRED_LINUX_ARTIFACT_PREFIX = "author-v4-linux-development-"
REQUIRED_MACOS_ARTIFACT_PREFIX = "author-v4-macos-development-"
AUTHOR_VERIFICATION_MODE = "AUTHOR_SELF_VERIFICATION"
AUTHOR_NAME = "Ivan Tyshchenko"
AUTHOR_ORCID = "https://orcid.org/0009-0000-7935-6090"
AUTHOR_GITHUB_LOGIN = "ALLPROTO"
AUTHOR_VERIFICATION_DECLARATION = (
    "I, Ivan Tyshchenko, repository owner and author, personally verified the "
    "normative protocol, canonical schemas, fail-closed implementation, "
    "zero-skip tests, and evidence plan on this exact commit. This is author "
    "self-verification only; it is not independent human review, peer review, "
    "operator blindness, or independent replication."
)
AUTHOR_VERIFICATION_CLAIM_BOUNDARY = (
    "AUTHOR_SELF_VERIFICATION_ONLY;"
    "NO_INDEPENDENT_HUMAN_REVIEW;"
    "NO_PEER_REVIEW;"
    "NO_OPERATOR_BLINDNESS;"
    "NO_INDEPENDENT_REPLICATION"
)
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
OWNER_OR_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z"
)
WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9._/-]{0,240}\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class GitHubGateReceiptError(ValueError):
    """The archived PR/CI gate is incomplete, stale, or inconsistent."""


@dataclass(frozen=True)
class VerifiedGitHubGateReceipt:
    repository: str
    evidence_boundary: str
    pull_request_number: int
    implementation_commit: str
    author_verification_mode: str
    author_name: str
    author_orcid: str
    author_github_login: str
    independent_human_review_required: bool
    independent_human_review_performed: bool
    author_verification_declaration: str
    author_verification_claim_boundary: str
    workflow_run_id: int
    workflow_id: int
    workflow_name: str
    workflow_path: str
    job_ids: tuple[int, ...]
    linux_job_ids: tuple[int, ...]
    macos_arm64_job_ids: tuple[int, ...]
    artifact_sha256: tuple[tuple[str, str], ...]
    first_server_date: str
    last_server_date: str
    receipt_created_at: str
    receipt_sha256: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def author_verification_summary() -> dict[str, Any]:
    """Return the exact non-independent author-verification disclosure."""

    return {
        "mode": AUTHOR_VERIFICATION_MODE,
        "authorName": AUTHOR_NAME,
        "authorORCID": AUTHOR_ORCID,
        "authorGitHubLogin": AUTHOR_GITHUB_LOGIN,
        "independentHumanReviewRequired": False,
        "independentHumanReviewPerformed": False,
        "declaration": AUTHOR_VERIFICATION_DECLARATION,
        "claimBoundary": AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
    }


def _mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GitHubGateReceiptError(f"{label} fields differ from the canonical contract")
    return value


def _positive_integer(value: Any, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise GitHubGateReceiptError(f"{label} must be a positive integer")
    return value


def _oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA1.fullmatch(value) is None:
        raise GitHubGateReceiptError(f"{label} must be a full lowercase SHA-1 OID")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise GitHubGateReceiptError(f"{label} must be lowercase SHA-256")
    return value


def _utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise GitHubGateReceiptError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise GitHubGateReceiptError(f"{label} is not a real timestamp") from error


def _strict_json(raw: bytes, *, label: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GitHubGateReceiptError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result

    def no_nonfinite(value: str) -> Any:
        raise GitHubGateReceiptError(f"non-finite number in {label}: {value}")

    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_nonfinite,
        )
    except UnicodeDecodeError as error:
        raise GitHubGateReceiptError(f"{label} is not strict UTF-8") from error
    except json.JSONDecodeError as error:
        raise GitHubGateReceiptError(f"{label} is not JSON") from error


def _archived_bytes(value: Any, *, label: str, maximum_bytes: int) -> bytes:
    record = _mapping(
        value,
        {"encoding", "bytes", "sha256", "dataBase64"},
        label=label,
    )
    if record["encoding"] != "base64":
        raise GitHubGateReceiptError(f"{label} encoding must be base64")
    count = record["bytes"]
    if type(count) is not int or not 0 <= count <= maximum_bytes:
        raise GitHubGateReceiptError(f"{label} byte count is invalid")
    digest = _digest(record["sha256"], label=f"{label} SHA-256")
    encoded = record["dataBase64"]
    if not isinstance(encoded, str) or len(encoded) > ((maximum_bytes + 2) // 3) * 4:
        raise GitHubGateReceiptError(f"{label} base64 is invalid")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise GitHubGateReceiptError(f"{label} base64 is invalid") from error
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise GitHubGateReceiptError(f"{label} base64 is not canonical")
    if len(raw) != count or _sha256(raw) != digest:
        raise GitHubGateReceiptError(f"{label} differs from its commitment")
    return raw


def _parse_headers(raw: bytes) -> dict[str, list[str]]:
    if not raw.endswith(b"\r\n\r\n") or b"\0" in raw:
        raise GitHubGateReceiptError("archived GitHub headers are incomplete")
    lines = raw[:-4].split(b"\r\n")
    if (
        not lines
        or re.fullmatch(rb"HTTP/(?:1\.1|2) 200(?: [^\r\n]*)?", lines[0]) is None
    ):
        raise GitHubGateReceiptError("archived GitHub HTTP status is not 200")
    fields: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or HEADER_NAME.fullmatch(name) is None or value[:1] not in {b"", b" "}:
            raise GitHubGateReceiptError("archived GitHub header is malformed")
        key = name.decode("ascii").lower()
        text = value.lstrip(b" ").decode("latin-1")
        if "\r" in text or "\n" in text:
            raise GitHubGateReceiptError("archived GitHub header is folded")
        fields.setdefault(key, []).append(text)
    for required in (
        "date",
        "content-type",
        "x-github-api-version-selected",
        "x-github-request-id",
    ):
        if len(fields.get(required, [])) != 1:
            raise GitHubGateReceiptError(f"GitHub header {required} must occur once")
    if not fields["content-type"][0].lower().startswith("application/json"):
        raise GitHubGateReceiptError("GitHub response is not JSON")
    if fields["x-github-api-version-selected"][0] != GITHUB_API_VERSION:
        raise GitHubGateReceiptError("GitHub API version differs")
    if not fields["x-github-request-id"][0].strip():
        raise GitHubGateReceiptError("GitHub request ID is empty")
    return fields


def _http_date(value: str) -> datetime:
    try:
        result = parsedate_to_datetime(value)
    except (TypeError, ValueError) as error:
        raise GitHubGateReceiptError("GitHub Date header is invalid") from error
    if result.tzinfo is None:
        raise GitHubGateReceiptError("GitHub Date header has no timezone")
    result = result.astimezone(timezone.utc)
    if result.microsecond:
        raise GitHubGateReceiptError("GitHub Date header is not whole-second")
    return result


def _repository(repository: str) -> tuple[str, str, str, str]:
    if not isinstance(repository, str) or repository.count("/") != 1:
        raise GitHubGateReceiptError("expected repository must be OWNER/REPO")
    owner, name = repository.split("/", 1)
    if (
        OWNER_OR_REPOSITORY.fullmatch(owner) is None
        or OWNER_OR_REPOSITORY.fullmatch(name) is None
        or name.endswith(".git")
    ):
        raise GitHubGateReceiptError("expected repository is invalid")
    return (
        owner,
        name,
        f"https://github.com/{owner}/{name}",
        f"https://api.github.com/repos/{owner}/{name}",
    )


def _expected_endpoints(
    *,
    api_base: str,
    pr_number: int,
    run_id: int,
) -> dict[str, str]:
    return {
        "pull-request": f"{api_base}/pulls/{pr_number}",
        "workflow-run": f"{api_base}/actions/runs/{run_id}",
        "workflow-jobs": (
            f"{api_base}/actions/runs/{run_id}/jobs?filter=all&per_page=100&page=1"
        ),
        "workflow-artifacts": (
            f"{api_base}/actions/runs/{run_id}/artifacts?per_page=100&page=1"
        ),
    }


def _validate_responses(
    value: Any,
    *,
    endpoints: Mapping[str, str],
    receipt_created: datetime,
) -> tuple[dict[str, Any], list[datetime]]:
    if not isinstance(value, list) or len(value) != len(API_ROLES):
        raise GitHubGateReceiptError("exactly four GitHub API responses are required")
    bodies: dict[str, Any] = {}
    dates: list[datetime] = []
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
            label=f"GitHub response {index}",
        )
        role = record["role"]
        if role != API_ROLES[index] or record["requestURL"] != endpoints[role]:
            raise GitHubGateReceiptError("GitHub endpoint role/order/URL differs")
        if record["statusCode"] != 200:
            raise GitHubGateReceiptError("GitHub response status is not 200")
        headers = _archived_bytes(
            record["responseHeaders"],
            label=f"GitHub {role} headers",
            maximum_bytes=MAXIMUM_HEADER_BYTES,
        )
        fields = _parse_headers(headers)
        if role in {"workflow-jobs", "workflow-artifacts"} and fields.get("link"):
            raise GitHubGateReceiptError(
                f"GitHub {role} is paginated; one-page gate cannot prove completeness"
            )
        raw_date = _http_date(fields["date"][0])
        server_date = _utc(record["serverDate"], label=f"GitHub {role} serverDate")
        captured = _utc(record["capturedAt"], label=f"GitHub {role} capturedAt")
        if raw_date != server_date or captured < server_date or captured > receipt_created:
            raise GitHubGateReceiptError(f"GitHub {role} capture chronology differs")
        if dates and server_date < dates[-1]:
            raise GitHubGateReceiptError("GitHub server Dates are not monotonic")
        dates.append(server_date)
        raw_body = _archived_bytes(
            record["responseBody"],
            label=f"GitHub {role} body",
            maximum_bytes=MAXIMUM_API_BODY_BYTES,
        )
        bodies[role] = _strict_json(raw_body, label=f"GitHub {role} body")
    if (dates[-1] - dates[0]).total_seconds() > MAXIMUM_CAPTURE_SPAN_SECONDS:
        raise GitHubGateReceiptError("GitHub capture window exceeds 120 seconds")
    return bodies, dates


def _verify_pull_request(
    body: Any,
    *,
    repository: str,
    html_base: str,
    api_base: str,
    pr_number: int,
    commit: str,
) -> None:
    if not isinstance(body, dict):
        raise GitHubGateReceiptError("pull-request response is not an object")
    head = body.get("head")
    head_repo = head.get("repo") if isinstance(head, dict) else None
    if (
        body.get("number") != pr_number
        or body.get("url") != f"{api_base}/pulls/{pr_number}"
        or body.get("html_url") != f"{html_base}/pull/{pr_number}"
        or not isinstance(head, dict)
        or head.get("sha") != commit
        or not isinstance(head_repo, dict)
        or head_repo.get("full_name") != repository
    ):
        raise GitHubGateReceiptError("pull request does not bind the exact repository/commit")


def _verify_workflow_run(
    body: Any,
    *,
    repository: str,
    html_base: str,
    api_base: str,
    run_id: int,
    commit: str,
    workflow_name: str,
    workflow_path: str,
) -> int:
    if not isinstance(body, dict):
        raise GitHubGateReceiptError("workflow-run response is not an object")
    repository_body = body.get("repository")
    workflow_id = _positive_integer(body.get("workflow_id"), label="workflow ID")
    if (
        body.get("id") != run_id
        or body.get("url") != f"{api_base}/actions/runs/{run_id}"
        or body.get("html_url") != f"{html_base}/actions/runs/{run_id}"
        or body.get("head_sha") != commit
        or body.get("name") != workflow_name
        or body.get("path") != workflow_path
        or body.get("status") != "completed"
        or body.get("conclusion") != "success"
        or not isinstance(repository_body, dict)
        or repository_body.get("full_name") != repository
    ):
        raise GitHubGateReceiptError("workflow run identity/path/head/outcome differs")
    return workflow_id


def _labels(job: Mapping[str, Any]) -> set[str]:
    raw = job.get("labels")
    if not isinstance(raw, list) or not raw or any(not isinstance(item, str) for item in raw):
        raise GitHubGateReceiptError("job has no exact scheduler labels")
    return {item.casefold() for item in raw}


def _verify_jobs(
    body: Any,
    *,
    api_base: str,
    run_id: int,
    commit: str,
) -> tuple[list[Mapping[str, Any]], tuple[int, ...], tuple[int, ...]]:
    if not isinstance(body, dict) or set(body) != {"total_count", "jobs"}:
        raise GitHubGateReceiptError("workflow-jobs response fields differ")
    jobs = body["jobs"]
    if not isinstance(jobs, list) or not 2 <= len(jobs) <= 100:
        raise GitHubGateReceiptError("workflow job inventory is empty or oversized")
    if body["total_count"] != len(jobs):
        raise GitHubGateReceiptError("workflow job total_count differs from one-page inventory")
    ids: set[int] = set()
    names: set[str] = set()
    linux: list[int] = []
    macos_arm64: list[int] = []
    for raw in jobs:
        if not isinstance(raw, dict):
            raise GitHubGateReceiptError("workflow job is not an object")
        job_id = _positive_integer(raw.get("id"), label="job ID")
        name = raw.get("name")
        if job_id in ids or not isinstance(name, str) or not name or name in names:
            raise GitHubGateReceiptError("job ID/name is invalid or duplicated")
        ids.add(job_id)
        names.add(name)
        if (
            raw.get("run_id") != run_id
            or raw.get("run_url") != f"{api_base}/actions/runs/{run_id}"
            or raw.get("head_sha") != commit
            or raw.get("status") != "completed"
            or raw.get("conclusion") != "success"
        ):
            raise GitHubGateReceiptError(
                "a workflow job is skipped, cancelled, failed, incomplete, or on another head"
            )
        labels = _labels(raw)
        if name == REQUIRED_LINUX_JOB_NAME:
            if REQUIRED_LINUX_SCHEDULER_LABEL not in labels:
                raise GitHubGateReceiptError(
                    "registered Linux job lacks the ubuntu-24.04 scheduler label"
                )
            linux.append(job_id)
        if name == REQUIRED_MACOS_JOB_NAME:
            if REQUIRED_MACOS_SCHEDULER_LABEL not in labels:
                raise GitHubGateReceiptError(
                    "registered macOS job lacks the macos-15 scheduler label"
                )
            macos_arm64.append(job_id)
    if not linux:
        raise GitHubGateReceiptError("registered Linux verification job is absent")
    if not macos_arm64:
        raise GitHubGateReceiptError(
            "registered macOS arm64 verification job is absent"
        )
    return jobs, tuple(linux), tuple(macos_arm64)


def _verify_artifacts(
    body: Any,
    *,
    api_base: str,
    run_id: int,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(body, dict) or set(body) != {"total_count", "artifacts"}:
        raise GitHubGateReceiptError("workflow-artifacts response fields differ")
    artifacts = body["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > 100:
        raise GitHubGateReceiptError("artifact inventory is invalid or oversized")
    if body["total_count"] != len(artifacts):
        raise GitHubGateReceiptError("artifact total_count differs from one-page inventory")
    ids: set[int] = set()
    names: set[str] = set()
    commitments: list[tuple[str, str]] = []
    for raw in artifacts:
        if not isinstance(raw, dict):
            raise GitHubGateReceiptError("artifact record is not an object")
        artifact_id = _positive_integer(raw.get("id"), label="artifact ID")
        name = raw.get("name")
        if artifact_id in ids or not isinstance(name, str) or not name or name in names:
            raise GitHubGateReceiptError("artifact ID/name is invalid or duplicated")
        ids.add(artifact_id)
        names.add(name)
        workflow_run = raw.get("workflow_run")
        if (
            raw.get("expired") is not False
            or raw.get("archive_download_url")
            != f"{api_base}/actions/artifacts/{artifact_id}/zip"
            or not isinstance(workflow_run, dict)
            or workflow_run.get("id") != run_id
        ):
            raise GitHubGateReceiptError("artifact is expired or belongs to another run")
        digest = raw.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise GitHubGateReceiptError(
                "required CI artifact digest is absent or uses an unsupported algorithm"
            )
        commitments.append((name, _digest(digest[7:], label="artifact SHA-256")))
    return canonical_ci_artifact_commitments(commitments, run_id=run_id)


def canonical_ci_artifact_commitments(
    commitments: Any,
    *,
    run_id: int,
) -> tuple[tuple[str, str], tuple[str, str]]:
    """Validate and order the exact Linux/macOS Actions artifact commitments."""

    run = _positive_integer(run_id, label="workflow run ID")
    if not isinstance(commitments, (list, tuple)) or len(commitments) != 2:
        raise GitHubGateReceiptError(
            "CI artifact inventory must contain exactly Linux and macOS payloads"
        )
    by_platform: dict[str, tuple[str, str, int]] = {}
    patterns = (
        (
            "linux",
            re.compile(
                rf"{re.escape(REQUIRED_LINUX_ARTIFACT_PREFIX)}{run}-([1-9][0-9]*)\Z"
            ),
        ),
        (
            "macos-arm64",
            re.compile(
                rf"{re.escape(REQUIRED_MACOS_ARTIFACT_PREFIX)}{run}-([1-9][0-9]*)\Z"
            ),
        ),
    )
    for item in commitments:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise GitHubGateReceiptError("CI artifact commitment fields differ")
        name, digest = item
        if not isinstance(name, str):
            raise GitHubGateReceiptError("CI artifact name is invalid")
        _digest(digest, label="CI artifact SHA-256")
        matches = [
            (key, match)
            for key, pattern in patterns
            if (match := pattern.fullmatch(name)) is not None
        ]
        if len(matches) != 1:
            raise GitHubGateReceiptError(
                "CI artifact name does not match the exact platform/run prefix"
            )
        platform_key, match = matches[0]
        if platform_key in by_platform:
            raise GitHubGateReceiptError("CI artifact platform is duplicated")
        by_platform[platform_key] = (name, digest, int(match.group(1)))
    if set(by_platform) != {"linux", "macos-arm64"}:
        raise GitHubGateReceiptError("one required platform CI artifact is absent")
    if len({record[2] for record in by_platform.values()}) != 1:
        raise GitHubGateReceiptError(
            "Linux and macOS CI artifacts must come from the same run attempt"
        )
    linux_name, linux_digest, _attempt = by_platform["linux"]
    macos_name, macos_digest, _attempt = by_platform["macos-arm64"]
    return (linux_name, linux_digest), (macos_name, macos_digest)


def verify_github_gate_receipt(
    raw_receipt: bytes,
    *,
    expected_repository: str,
    expected_pull_request_number: int,
    expected_implementation_commit: str,
    expected_workflow_run_id: int,
    expected_workflow_name: str,
    expected_workflow_path: str,
) -> VerifiedGitHubGateReceipt:
    """Structurally verify one canonical archived observation without network access."""

    if (
        not isinstance(raw_receipt, bytes)
        or not 0 < len(raw_receipt) <= MAXIMUM_RECEIPT_BYTES
        or not raw_receipt.endswith(b"\n")
        or raw_receipt.endswith(b"\n\n")
    ):
        raise GitHubGateReceiptError("receipt must be bounded and end in exactly one LF")
    receipt = _strict_json(raw_receipt, label="GitHub gate receipt")
    if not isinstance(receipt, dict) or raw_receipt != canonical_json_bytes(receipt) + b"\n":
        raise GitHubGateReceiptError("receipt bytes are not canonical JSON plus LF")
    root = _mapping(
        receipt,
        {
            "schemaVersion",
            "suiteId",
            "githubAPIVersion",
            "evidenceBoundary",
            "repository",
            "implementationCommit",
            "pullRequestNumber",
            "authorVerification",
            "ciGate",
            "capturePolicy",
            "githubAPIResponses",
            "receiptCreatedAt",
            "contentSHA256",
        },
        label="GitHub gate receipt",
    )
    if (
        root["schemaVersion"] != SCHEMA_VERSION
        or root["suiteId"] != SUITE_ID
        or root["githubAPIVersion"] != GITHUB_API_VERSION
    ):
        raise GitHubGateReceiptError("receipt schema/suite/API version differs")
    if root["evidenceBoundary"] != EVIDENCE_BOUNDARY:
        raise GitHubGateReceiptError("GitHub gate evidence boundary differs")
    content_digest = _digest(root["contentSHA256"], label="receipt contentSHA256")
    unsigned = dict(root)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != content_digest:
        raise GitHubGateReceiptError("receipt contentSHA256 mismatch")
    owner, _name, html_base, api_base = _repository(expected_repository)
    if owner.casefold() != AUTHOR_GITHUB_LOGIN.casefold():
        raise GitHubGateReceiptError(
            "repository owner differs from the declared author GitHub login"
        )
    repository_record = _mapping(
        root["repository"], {"slug", "htmlURL", "apiURL"}, label="repository"
    )
    if repository_record != {
        "slug": expected_repository,
        "htmlURL": html_base,
        "apiURL": api_base,
    }:
        raise GitHubGateReceiptError("repository identity differs")
    pr_number = _positive_integer(
        expected_pull_request_number, label="expected pull request number"
    )
    run_id = _positive_integer(expected_workflow_run_id, label="expected workflow run ID")
    commit = _oid(expected_implementation_commit, label="expected implementation commit")
    if root["implementationCommit"] != commit or root["pullRequestNumber"] != pr_number:
        raise GitHubGateReceiptError("receipt implementation/PR identity differs")
    if (
        expected_workflow_name != REQUIRED_WORKFLOW_NAME
        or expected_workflow_path != REQUIRED_WORKFLOW_PATH
    ):
        raise GitHubGateReceiptError("workflow name/path is not the registered CI gate")
    receipt_created = _utc(root["receiptCreatedAt"], label="receiptCreatedAt")
    capture_policy = _mapping(
        root["capturePolicy"],
        {
            "maxResultsPerListEndpoint",
            "paginationAllowed",
            "redirectsAllowed",
            "retriesAllowed",
            "proxyEnvironmentAllowed",
            "maximumServerDateSpanSeconds",
            "ciSnapshotIsTimeBounded",
            "platformEvidenceBoundary",
            "artifactBytesArchived",
        },
        label="capture policy",
    )
    if capture_policy != {
        "maxResultsPerListEndpoint": 100,
        "paginationAllowed": False,
        "redirectsAllowed": False,
        "retriesAllowed": False,
        "proxyEnvironmentAllowed": False,
        "maximumServerDateSpanSeconds": MAXIMUM_CAPTURE_SPAN_SECONDS,
        "ciSnapshotIsTimeBounded": True,
        "platformEvidenceBoundary": "GITHUB_ACTIONS_SCHEDULER_LABELS_NOT_MEASURED_CPU",
        "artifactBytesArchived": False,
    }:
        raise GitHubGateReceiptError("capture policy weakens or misstates the evidence boundary")
    endpoints = _expected_endpoints(api_base=api_base, pr_number=pr_number, run_id=run_id)
    bodies, dates = _validate_responses(
        root["githubAPIResponses"], endpoints=endpoints, receipt_created=receipt_created
    )
    _verify_pull_request(
        bodies["pull-request"],
        repository=expected_repository,
        html_base=html_base,
        api_base=api_base,
        pr_number=pr_number,
        commit=commit,
    )
    author_verification = _mapping(
        root["authorVerification"],
        {
            "mode",
            "authorName",
            "authorORCID",
            "authorGitHubLogin",
            "independentHumanReviewRequired",
            "independentHumanReviewPerformed",
            "declaration",
            "claimBoundary",
        },
        label="author verification",
    )
    if author_verification != author_verification_summary():
        raise GitHubGateReceiptError("author verification disclosure differs")
    workflow_id = _verify_workflow_run(
        bodies["workflow-run"],
        repository=expected_repository,
        html_base=html_base,
        api_base=api_base,
        run_id=run_id,
        commit=commit,
        workflow_name=expected_workflow_name,
        workflow_path=expected_workflow_path,
    )
    jobs, linux, macos_arm64 = _verify_jobs(
        bodies["workflow-jobs"], api_base=api_base, run_id=run_id, commit=commit
    )
    artifacts = _verify_artifacts(
        bodies["workflow-artifacts"], api_base=api_base, run_id=run_id
    )
    ci_gate = _mapping(
        root["ciGate"],
        {
            "runId",
            "workflowId",
            "workflowName",
            "workflowPath",
            "headSHA",
            "status",
            "conclusion",
            "totalJobs",
            "allJobsCompletedSuccess",
            "zeroSkippedOrCancelledJobs",
            "jobIds",
            "linuxJobIds",
            "macOSArm64JobIds",
            "artifactSHA256",
        },
        label="CI gate",
    )
    expected_ci = {
        "runId": run_id,
        "workflowId": workflow_id,
        "workflowName": expected_workflow_name,
        "workflowPath": expected_workflow_path,
        "headSHA": commit,
        "status": "completed",
        "conclusion": "success",
        "totalJobs": len(jobs),
        "allJobsCompletedSuccess": True,
        "zeroSkippedOrCancelledJobs": True,
        "jobIds": [job["id"] for job in jobs],
        "linuxJobIds": list(linux),
        "macOSArm64JobIds": list(macos_arm64),
        "artifactSHA256": [
            {"name": name, "sha256": digest} for name, digest in artifacts
        ],
    }
    if ci_gate != expected_ci:
        raise GitHubGateReceiptError("derived CI gate differs from archived API bytes")
    return VerifiedGitHubGateReceipt(
        repository=expected_repository,
        evidence_boundary=EVIDENCE_BOUNDARY,
        pull_request_number=pr_number,
        implementation_commit=commit,
        author_verification_mode=AUTHOR_VERIFICATION_MODE,
        author_name=AUTHOR_NAME,
        author_orcid=AUTHOR_ORCID,
        author_github_login=AUTHOR_GITHUB_LOGIN,
        independent_human_review_required=False,
        independent_human_review_performed=False,
        author_verification_declaration=AUTHOR_VERIFICATION_DECLARATION,
        author_verification_claim_boundary=AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
        workflow_run_id=run_id,
        workflow_id=workflow_id,
        workflow_name=expected_workflow_name,
        workflow_path=expected_workflow_path,
        job_ids=tuple(job["id"] for job in jobs),
        linux_job_ids=linux,
        macos_arm64_job_ids=macos_arm64,
        artifact_sha256=artifacts,
        first_server_date=dates[0].strftime("%Y-%m-%dT%H:%M:%SZ"),
        last_server_date=dates[-1].strftime("%Y-%m-%dT%H:%M:%SZ"),
        receipt_created_at=root["receiptCreatedAt"],
        receipt_sha256=_sha256(raw_receipt),
    )


__all__ = [
    "API_ROLES",
    "AUTHOR_GITHUB_LOGIN",
    "AUTHOR_NAME",
    "AUTHOR_ORCID",
    "AUTHOR_VERIFICATION_CLAIM_BOUNDARY",
    "AUTHOR_VERIFICATION_DECLARATION",
    "AUTHOR_VERIFICATION_MODE",
    "EVIDENCE_BOUNDARY",
    "GITHUB_API_VERSION",
    "GitHubGateReceiptError",
    "MAXIMUM_CAPTURE_SPAN_SECONDS",
    "REQUIRED_LINUX_ARTIFACT_PREFIX",
    "REQUIRED_LINUX_JOB_NAME",
    "REQUIRED_LINUX_SCHEDULER_LABEL",
    "REQUIRED_MACOS_JOB_NAME",
    "REQUIRED_MACOS_ARTIFACT_PREFIX",
    "REQUIRED_MACOS_SCHEDULER_LABEL",
    "REQUIRED_WORKFLOW_NAME",
    "REQUIRED_WORKFLOW_PATH",
    "SCHEMA_VERSION",
    "SUITE_ID",
    "VerifiedGitHubGateReceipt",
    "author_verification_summary",
    "canonical_ci_artifact_commitments",
    "verify_github_gate_receipt",
]
