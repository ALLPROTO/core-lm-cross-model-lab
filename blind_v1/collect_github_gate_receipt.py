#!/usr/bin/env python3
"""Collect one direct-TLS GitHub PR + Actions CI structural observation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, urlsplit


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.github_gate_receipt import (
    API_ROLES,
    AUTHOR_GITHUB_LOGIN,
    EVIDENCE_BOUNDARY,
    GITHUB_API_VERSION,
    MAXIMUM_API_BODY_BYTES,
    MAXIMUM_CAPTURE_SPAN_SECONDS,
    MAXIMUM_HEADER_BYTES,
    SCHEMA_VERSION,
    SUITE_ID,
    GitHubGateReceiptError,
    _expected_endpoints,
    _http_date,
    _parse_headers,
    _repository,
    _strict_json,
    _verify_artifacts,
    _verify_jobs,
    _verify_pull_request,
    _verify_workflow_run,
    author_verification_summary,
    verify_github_gate_receipt,
)
from blind_v1.release_receipt import canonical_json_bytes
from blind_v1.protocol import require_scientific_schedule_open


GITHUB_API_HOST = "api.github.com"
GITHUB_API_PORT = 443
USER_AGENT = "core-lm-github-ci-gate-collector/2"
TOKEN_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
READ_CHUNK_BYTES = 1024 * 1024


class GitHubGateCollectionError(RuntimeError):
    """The GitHub PR/CI gate could not be collected and verified."""


@dataclass(frozen=True)
class HTTPSCapture:
    status_code: int
    response_headers: bytes
    response_body: bytes
    captured_at: str


class GitHubGateTransport(Protocol):
    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _archived(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def load_token_from_environment(name: str | None) -> str | None:
    if name is None:
        return None
    if TOKEN_ENVIRONMENT_NAME.fullmatch(name) is None:
        raise GitHubGateCollectionError("token environment-variable name is invalid")
    value = os.environ.get(name)
    if value is None or not value or "\r" in value or "\n" in value:
        raise GitHubGateCollectionError("requested token is absent or invalid")
    try:
        value.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise GitHubGateCollectionError("GitHub token must be ASCII") from error
    return value


def _validate_exact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise GitHubGateCollectionError("GitHub API URL is malformed") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != GITHUB_API_HOST
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/repos/")
    ):
        raise GitHubGateCollectionError("request is outside api.github.com allowlist")
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    allowed_queries = {
        (),
        (("filter", "all"), ("per_page", "100"), ("page", "1")),
        (("per_page", "100"), ("page", "1")),
    }
    if tuple(pairs) not in allowed_queries:
        raise GitHubGateCollectionError("GitHub query differs from the fixed one-page contract")
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


class DirectGitHubGateTransport:
    """Direct TLS, one HTTP/1.1 request, no proxy/redirect/retry path."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        if not 0 < timeout_seconds <= 120:
            raise GitHubGateCollectionError("timeout must be in (0, 120] seconds")
        self.timeout_seconds = timeout_seconds
        self.now = now

    @staticmethod
    def _recv(tls: ssl.SSLSocket, deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GitHubGateCollectionError("GitHub request exceeded total timeout")
        tls.settimeout(remaining)
        try:
            return tls.recv(READ_CHUNK_BYTES)
        except (OSError, TimeoutError) as error:
            raise GitHubGateCollectionError("GitHub TLS read failed") from error

    def request(self, url: str, *, token: str | None = None) -> HTTPSCapture:
        target = _validate_exact_url(url)
        if token is not None:
            try:
                token.encode("ascii", "strict")
            except UnicodeEncodeError as error:
                raise GitHubGateCollectionError("GitHub token is invalid") from error
            if not token or "\r" in token or "\n" in token:
                raise GitHubGateCollectionError("GitHub token is invalid")
        headers = [
            f"GET {target} HTTP/1.1",
            f"Host: {GITHUB_API_HOST}",
            f"User-Agent: {USER_AGENT}",
            "Accept: application/vnd.github+json",
            "Accept-Encoding: identity",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "Connection: close",
        ]
        if token is not None:
            headers.append(f"Authorization: Bearer {token}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        deadline = time.monotonic() + self.timeout_seconds
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["http/1.1"])
        try:
            raw_socket = socket.create_connection(
                (GITHUB_API_HOST, GITHUB_API_PORT), timeout=self.timeout_seconds
            )
            with raw_socket:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GitHubGateCollectionError("GitHub request exceeded total timeout")
                raw_socket.settimeout(remaining)
                with context.wrap_socket(raw_socket, server_hostname=GITHUB_API_HOST) as tls:
                    if tls.selected_alpn_protocol() not in (None, "http/1.1"):
                        raise GitHubGateCollectionError("unexpected TLS application protocol")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GitHubGateCollectionError("GitHub request exceeded total timeout")
                    tls.settimeout(remaining)
                    tls.sendall(request)
                    buffer = bytearray()
                    while b"\r\n\r\n" not in buffer:
                        chunk = self._recv(tls, deadline)
                        if not chunk:
                            raise GitHubGateCollectionError("GitHub headers are truncated")
                        buffer.extend(chunk)
                        if len(buffer) > MAXIMUM_HEADER_BYTES + MAXIMUM_API_BODY_BYTES:
                            raise GitHubGateCollectionError("GitHub response is oversized")
                    raw_headers, initial = bytes(buffer).split(b"\r\n\r\n", 1)
                    raw_headers += b"\r\n\r\n"
                    status_match = re.match(
                        rb"HTTP/1\.1 ([0-9]{3})(?: [^\r\n]*)?\r\n", raw_headers
                    )
                    if status_match is None:
                        raise GitHubGateCollectionError("GitHub status line is invalid")
                    status = int(status_match.group(1))
                    if status != 200:
                        raise GitHubGateCollectionError(
                            "GitHub returned non-200; redirects and retries are forbidden"
                        )
                    fields = self._wire_fields(raw_headers)
                    encodings = fields.get("content-encoding", ["identity"])
                    if len(encodings) != 1 or encodings[0].casefold() not in {"", "identity"}:
                        raise GitHubGateCollectionError("compressed response is forbidden")
                    transfer = fields.get("transfer-encoding", [])
                    lengths = fields.get("content-length", [])
                    if transfer and lengths:
                        raise GitHubGateCollectionError("ambiguous HTTP body framing")
                    if transfer:
                        if len(transfer) != 1 or transfer[0].casefold() != "chunked":
                            raise GitHubGateCollectionError("unsupported transfer encoding")
                        body = self._chunked(tls, bytearray(initial), deadline)
                    elif lengths:
                        if len(lengths) != 1 or not lengths[0].isdigit():
                            raise GitHubGateCollectionError("Content-Length is invalid")
                        expected = int(lengths[0])
                        if expected > MAXIMUM_API_BODY_BYTES:
                            raise GitHubGateCollectionError("GitHub body is oversized")
                        body_buffer = bytearray(initial)
                        while len(body_buffer) < expected:
                            chunk = self._recv(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                        if len(body_buffer) != expected:
                            raise GitHubGateCollectionError("Content-Length framing differs")
                        body = bytes(body_buffer)
                    else:
                        body_buffer = bytearray(initial)
                        while True:
                            chunk = self._recv(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                            if len(body_buffer) > MAXIMUM_API_BODY_BYTES:
                                raise GitHubGateCollectionError("GitHub body is oversized")
                        body = bytes(body_buffer)
        except GitHubGateCollectionError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as error:
            raise GitHubGateCollectionError("direct GitHub TLS request failed") from error
        return HTTPSCapture(status, raw_headers, body, self.now())

    @staticmethod
    def _wire_fields(raw: bytes) -> dict[str, list[str]]:
        fields: dict[str, list[str]] = {}
        lines = raw[:-4].split(b"\r\n")
        if not lines:
            raise GitHubGateCollectionError("GitHub header block is empty")
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or HEADER_NAME.fullmatch(name) is None:
                raise GitHubGateCollectionError("GitHub header is malformed")
            fields.setdefault(name.decode("ascii").casefold(), []).append(
                value.lstrip(b" ").decode("latin-1")
            )
        return fields

    def _chunked(
        self, tls: ssl.SSLSocket, buffer: bytearray, deadline: float
    ) -> bytes:
        body = bytearray()

        def until(marker: bytes) -> None:
            while marker not in buffer:
                chunk = self._recv(tls, deadline)
                if not chunk:
                    raise GitHubGateCollectionError("chunked body is truncated")
                buffer.extend(chunk)
                if len(buffer) + len(body) > MAXIMUM_API_BODY_BYTES + MAXIMUM_HEADER_BYTES:
                    raise GitHubGateCollectionError("chunked body is oversized")

        while True:
            until(b"\r\n")
            raw_size, _, remainder = bytes(buffer).partition(b"\r\n")
            buffer[:] = remainder
            raw_size = raw_size.split(b";", 1)[0]
            if not raw_size or re.fullmatch(rb"[0-9A-Fa-f]+", raw_size) is None:
                raise GitHubGateCollectionError("chunk size is invalid")
            size = int(raw_size, 16)
            if size == 0:
                until(b"\r\n")
                trailer, _, remainder = bytes(buffer).partition(b"\r\n")
                if trailer or remainder:
                    raise GitHubGateCollectionError("chunk trailers/extra bytes are forbidden")
                break
            if len(body) + size > MAXIMUM_API_BODY_BYTES:
                raise GitHubGateCollectionError("chunked body is oversized")
            while len(buffer) < size + 2:
                chunk = self._recv(tls, deadline)
                if not chunk:
                    raise GitHubGateCollectionError("chunk is truncated")
                buffer.extend(chunk)
            if buffer[size : size + 2] != b"\r\n":
                raise GitHubGateCollectionError("chunk terminator differs")
            body.extend(buffer[:size])
            del buffer[: size + 2]
        return bytes(body)


def _response_record(role: str, url: str, capture: HTTPSCapture) -> dict[str, Any]:
    if capture.status_code != 200:
        raise GitHubGateCollectionError(
            "GitHub returned non-200; redirects and retries are forbidden"
        )
    try:
        fields = _parse_headers(capture.response_headers)
        server_date = _http_date(fields["date"][0])
        _strict_json(capture.response_body, label=f"GitHub {role} response")
    except GitHubGateReceiptError as error:
        raise GitHubGateCollectionError("GitHub response contract is invalid") from error
    return {
        "role": role,
        "requestURL": url,
        "statusCode": 200,
        "serverDate": server_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "capturedAt": capture.captured_at,
        "responseHeaders": _archived(capture.response_headers),
        "responseBody": _archived(capture.response_body),
    }


def _exclusive_write(path: Path, raw: bytes) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent = os.open(absolute.parent, parent_flags)
    except OSError as error:
        raise GitHubGateCollectionError("output parent is not a no-follow directory") from error
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent)
        except OSError as error:
            raise GitHubGateCollectionError("output exists or is unsafe") from error
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise GitHubGateCollectionError("output write made no progress")
                offset += written
            os.fsync(descriptor)
        except Exception:
            try:
                os.unlink(absolute.name, dir_fd=parent)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        try:
            os.fsync(parent)
        except OSError as error:
            try:
                os.unlink(absolute.name, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                pass
            raise GitHubGateCollectionError(
                "output directory durability barrier failed"
            ) from error
    finally:
        os.close(parent)


def _assert_absent(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise GitHubGateCollectionError("output cannot be inspected") from error
    raise GitHubGateCollectionError("output already exists; collection was not started")


def collect_github_gate_receipt(
    *,
    repository: str,
    pull_request_number: int,
    implementation_commit: str,
    workflow_run_id: int,
    workflow_name: str,
    workflow_path: str,
    token: str | None = None,
    transport: GitHubGateTransport | None = None,
    now: Callable[[], str] = _utc_now,
) -> bytes:
    """Collect over verified TLS, then structurally verify canonical receipt bytes."""

    require_scientific_schedule_open(operation="collect Blind V1 GitHub CI gate receipt")
    return _historical_collect_github_gate_receipt(
        repository=repository,
        pull_request_number=pull_request_number,
        implementation_commit=implementation_commit,
        workflow_run_id=workflow_run_id,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        token=token,
        transport=transport,
        now=now,
    )


def _historical_collect_github_gate_receipt(
    *,
    repository: str,
    pull_request_number: int,
    implementation_commit: str,
    workflow_run_id: int,
    workflow_name: str,
    workflow_path: str,
    token: str | None = None,
    transport: GitHubGateTransport | None = None,
    now: Callable[[], str] = _utc_now,
) -> bytes:
    """Retain the former receipt shape for offline structural fixtures."""

    try:
        owner, _name, html_base, api_base = _repository(repository)
    except GitHubGateReceiptError as error:
        raise GitHubGateCollectionError("repository input is invalid") from error
    if owner.casefold() != AUTHOR_GITHUB_LOGIN.casefold():
        raise GitHubGateCollectionError(
            "repository owner differs from the declared author GitHub login"
        )
    if type(pull_request_number) is not int or pull_request_number <= 0:
        raise GitHubGateCollectionError("pull request number is invalid")
    if type(workflow_run_id) is not int or workflow_run_id <= 0:
        raise GitHubGateCollectionError("workflow run ID is invalid")
    endpoints = _expected_endpoints(
        api_base=api_base,
        pr_number=pull_request_number,
        run_id=workflow_run_id,
    )
    client = transport or DirectGitHubGateTransport(now=now)
    records: list[dict[str, Any]] = []
    bodies: dict[str, Any] = {}
    for role in API_ROLES:
        capture = client.request(endpoints[role], token=token)
        if token is not None:
            secret = token.encode("ascii", "strict")
            if secret in capture.response_headers or secret in capture.response_body:
                raise GitHubGateCollectionError("GitHub echoed the token; capture discarded")
        records.append(_response_record(role, endpoints[role], capture))
        bodies[role] = _strict_json(
            capture.response_body, label=f"GitHub {role} body"
        )
    try:
        _verify_pull_request(
            bodies["pull-request"],
            repository=repository,
            html_base=html_base,
            api_base=api_base,
            pr_number=pull_request_number,
            commit=implementation_commit,
        )
        workflow_id = _verify_workflow_run(
            bodies["workflow-run"],
            repository=repository,
            html_base=html_base,
            api_base=api_base,
            run_id=workflow_run_id,
            commit=implementation_commit,
            workflow_name=workflow_name,
            workflow_path=workflow_path,
        )
        jobs, linux_jobs, macos_jobs = _verify_jobs(
            bodies["workflow-jobs"],
            api_base=api_base,
            run_id=workflow_run_id,
            commit=implementation_commit,
        )
        artifacts = _verify_artifacts(
            bodies["workflow-artifacts"], api_base=api_base, run_id=workflow_run_id
        )
    except GitHubGateReceiptError as error:
        raise GitHubGateCollectionError("GitHub PR/CI gate did not pass") from error
    receipt: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "suiteId": SUITE_ID,
        "githubAPIVersion": GITHUB_API_VERSION,
        "evidenceBoundary": EVIDENCE_BOUNDARY,
        "repository": {
            "slug": repository,
            "htmlURL": html_base,
            "apiURL": api_base,
        },
        "implementationCommit": implementation_commit,
        "pullRequestNumber": pull_request_number,
        "authorVerification": author_verification_summary(),
        "ciGate": {
            "runId": workflow_run_id,
            "workflowId": workflow_id,
            "workflowName": workflow_name,
            "workflowPath": workflow_path,
            "headSHA": implementation_commit,
            "status": "completed",
            "conclusion": "success",
            "totalJobs": len(jobs),
            "allJobsCompletedSuccess": True,
            "zeroSkippedOrCancelledJobs": True,
            "jobIds": [job["id"] for job in jobs],
            "linuxJobIds": list(linux_jobs),
            "macOSArm64JobIds": list(macos_jobs),
            "artifactSHA256": [
                {"name": name, "sha256": digest} for name, digest in artifacts
            ],
        },
        "capturePolicy": {
            "maxResultsPerListEndpoint": 100,
            "paginationAllowed": False,
            "redirectsAllowed": False,
            "retriesAllowed": False,
            "proxyEnvironmentAllowed": False,
            "maximumServerDateSpanSeconds": MAXIMUM_CAPTURE_SPAN_SECONDS,
            "ciSnapshotIsTimeBounded": True,
            "platformEvidenceBoundary": "GITHUB_ACTIONS_SCHEDULER_LABELS_NOT_MEASURED_CPU",
            "artifactBytesArchived": False,
        },
        "githubAPIResponses": records,
        "receiptCreatedAt": now(),
    }
    receipt["contentSHA256"] = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    raw = canonical_json_bytes(receipt) + b"\n"
    if token is not None and token.encode("ascii") in raw:
        raise GitHubGateCollectionError("authorization secret entered receipt bytes")
    try:
        verify_github_gate_receipt(
            raw,
            expected_repository=repository,
            expected_pull_request_number=pull_request_number,
            expected_implementation_commit=implementation_commit,
            expected_workflow_run_id=workflow_run_id,
            expected_workflow_name=workflow_name,
            expected_workflow_path=workflow_path,
        )
    except GitHubGateReceiptError as error:
        raise GitHubGateCollectionError("collected receipt failed offline verification") from error
    return raw


def collect_github_gate_receipt_to_path(*, output: Path, **arguments: Any) -> str:
    require_scientific_schedule_open(
        operation="publish Blind V1 GitHub CI gate receipt"
    )
    return _historical_collect_github_gate_receipt_to_path(
        output=output, **arguments
    )


def _historical_collect_github_gate_receipt_to_path(
    *, output: Path, **arguments: Any
) -> str:
    """Publish a legacy receipt only for isolated structural fixtures."""

    _assert_absent(output)
    raw = _historical_collect_github_gate_receipt(**arguments)
    _exclusive_write(output, raw)
    return hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--token-env")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        require_scientific_schedule_open(
            operation="run Blind V1 GitHub gate collector"
        )
        token = load_token_from_environment(args.token_env)
        digest = collect_github_gate_receipt_to_path(
            output=args.output,
            repository=args.repository,
            pull_request_number=args.pull_request,
            implementation_commit=args.implementation_commit,
            workflow_run_id=args.workflow_run_id,
            workflow_name=args.workflow_name,
            workflow_path=args.workflow_path,
            token=token,
            transport=DirectGitHubGateTransport(timeout_seconds=args.timeout_seconds),
        )
    except (GitHubGateCollectionError, GitHubGateReceiptError, OSError, ValueError):
        print("GitHub gate collection failed (fail-closed)", file=sys.stderr)
        return 2
    print(f"GitHub gate observation collected and structurally verified: sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DirectGitHubGateTransport",
    "GitHubGateCollectionError",
    "GitHubGateTransport",
    "HTTPSCapture",
    "collect_github_gate_receipt",
    "collect_github_gate_receipt_to_path",
    "load_token_from_environment",
]
