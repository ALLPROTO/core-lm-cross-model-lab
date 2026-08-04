#!/usr/bin/env python3
"""Collect one self-verified, read-only Zenodo production receipt.

Exactly three authenticated GET requests are made.  This program has no code
path for POST, PUT, PATCH, DELETE, file upload, DOI reservation, or publish.
It ignores proxy variables, follows no redirects, performs no retry, archives
the exact request targets and response header/entity-body bytes, and aborts if
the bearer token appears anywhere in the output.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urlsplit

from v4.reproducibility import canonical_json_bytes, write_new_bytes
from v4.release_attestation_crypto import (
    PinnedCosignReleaseAttestationVerifier,
)
from v4.zenodo_archive import (
    API_ROLES,
    MAXIMUM_API_BODY_BYTES,
    MAXIMUM_HEADER_BYTES,
    READ_CHUNK_BYTES,
    ZENODO_API_BASE,
    ZENODO_HOST,
    HTTPSCapture,
    ZenodoArchiveError,
    build_zenodo_receipt,
    verify_zenodo_receipt,
)


ZENODO_PORT = 443
USER_AGENT = "core-lm-zenodo-receipt-collector/1"
TOKEN_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


class ZenodoReceiptCollectionError(RuntimeError):
    """A read-only Zenodo receipt could not be collected safely."""


class ZenodoTransport(Protocol):
    def request(self, url: str, *, token: str) -> HTTPSCapture: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def load_token_from_environment(name: str) -> str:
    if not isinstance(name, str) or TOKEN_ENVIRONMENT_NAME.fullmatch(name) is None:
        raise ZenodoReceiptCollectionError("token environment-variable name is invalid")
    token = os.environ.get(name)
    if token is None or not token or "\r" in token or "\n" in token or len(token) > 4096:
        raise ZenodoReceiptCollectionError("requested Zenodo token is absent or invalid")
    try:
        token.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise ZenodoReceiptCollectionError("Zenodo token must be ASCII") from error
    return token


def _validate_exact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise ZenodoReceiptCollectionError("Zenodo API URL is malformed") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != ZENODO_HOST
        or parsed.port not in (None, ZENODO_PORT)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or re.fullmatch(
            r"/api/(?:deposit/depositions/[1-9][0-9]*(?:/files)?|records/[1-9][0-9]*)",
            parsed.path,
        )
        is None
    ):
        raise ZenodoReceiptCollectionError(
            "request target is outside the fixed Zenodo read allowlist"
        )
    if "/actions/" in parsed.path or parsed.path.endswith("/draft"):
        raise ZenodoReceiptCollectionError("Zenodo state-changing target is forbidden")
    return parsed.path


class DirectZenodoTransport:
    """Direct TLS/HTTP 1.1 GET transport with no proxy, redirect, or retry."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 30.0,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        if not 0 < timeout_seconds <= 120:
            raise ZenodoReceiptCollectionError("timeout must be in (0, 120] seconds")
        self.timeout_seconds = timeout_seconds
        self.now = now

    @staticmethod
    def _recv(tls: ssl.SSLSocket, deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ZenodoReceiptCollectionError("Zenodo request exceeded total timeout")
        tls.settimeout(remaining)
        try:
            return tls.recv(READ_CHUNK_BYTES)
        except (OSError, TimeoutError) as error:
            raise ZenodoReceiptCollectionError("Zenodo TLS read failed") from error

    @staticmethod
    def _wire_fields(raw_headers: bytes) -> dict[str, list[str]]:
        fields: dict[str, list[str]] = {}
        for line in raw_headers[:-4].split(b"\r\n")[1:]:
            if not line or line[:1] in b" \t" or b":" not in line:
                raise ZenodoReceiptCollectionError("Zenodo response header line is invalid")
            name, value = line.split(b":", 1)
            try:
                normalized_name = name.decode("ascii").casefold()
                normalized_value = value.strip(b" \t").decode("latin-1")
            except UnicodeDecodeError as error:
                raise ZenodoReceiptCollectionError("Zenodo response header is invalid") from error
            fields.setdefault(normalized_name, []).append(normalized_value)
        return fields

    def _chunked(
        self, tls: ssl.SSLSocket, buffer: bytearray, deadline: float
    ) -> bytes:
        body = bytearray()

        def line() -> bytes:
            while b"\r\n" not in buffer:
                chunk = self._recv(tls, deadline)
                if not chunk:
                    raise ZenodoReceiptCollectionError("chunked Zenodo response is truncated")
                buffer.extend(chunk)
                if len(buffer) > MAXIMUM_API_BODY_BYTES + MAXIMUM_HEADER_BYTES:
                    raise ZenodoReceiptCollectionError("Zenodo response is oversized")
            raw_line, _separator, remainder = bytes(buffer).partition(b"\r\n")
            buffer.clear()
            buffer.extend(remainder)
            return raw_line

        while True:
            size_line = line()
            size_token = size_line.split(b";", 1)[0]
            if not size_token or re.fullmatch(rb"[0-9A-Fa-f]+", size_token) is None:
                raise ZenodoReceiptCollectionError("Zenodo chunk size is invalid")
            size = int(size_token, 16)
            if size > MAXIMUM_API_BODY_BYTES - len(body):
                raise ZenodoReceiptCollectionError("Zenodo response body is oversized")
            if size == 0:
                while line():
                    pass
                return bytes(body)
            while len(buffer) < size + 2:
                chunk = self._recv(tls, deadline)
                if not chunk:
                    raise ZenodoReceiptCollectionError("Zenodo chunk data is truncated")
                buffer.extend(chunk)
            body.extend(buffer[:size])
            if buffer[size : size + 2] != b"\r\n":
                raise ZenodoReceiptCollectionError("Zenodo chunk delimiter is invalid")
            del buffer[: size + 2]

    def request(self, url: str, *, token: str) -> HTTPSCapture:
        target = _validate_exact_url(url)
        if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
            raise ZenodoReceiptCollectionError("Zenodo bearer token is invalid")
        try:
            token_bytes = token.encode("ascii", "strict")
        except UnicodeEncodeError as error:
            raise ZenodoReceiptCollectionError("Zenodo bearer token must be ASCII") from error
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {ZENODO_HOST}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: application/vnd.zenodo.v1+json\r\n"
            "Accept-Encoding: identity\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        deadline = time.monotonic() + self.timeout_seconds
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(["http/1.1"])
        try:
            raw_socket = socket.create_connection(
                (ZENODO_HOST, ZENODO_PORT), timeout=self.timeout_seconds
            )
            with raw_socket:
                raw_socket.settimeout(max(0.001, deadline - time.monotonic()))
                with context.wrap_socket(raw_socket, server_hostname=ZENODO_HOST) as tls:
                    if tls.selected_alpn_protocol() not in (None, "http/1.1"):
                        raise ZenodoReceiptCollectionError("unexpected Zenodo TLS protocol")
                    tls.settimeout(max(0.001, deadline - time.monotonic()))
                    tls.sendall(request)
                    buffer = bytearray()
                    while b"\r\n\r\n" not in buffer:
                        chunk = self._recv(tls, deadline)
                        if not chunk:
                            raise ZenodoReceiptCollectionError(
                                "Zenodo response headers are truncated"
                            )
                        buffer.extend(chunk)
                        if len(buffer) > MAXIMUM_HEADER_BYTES + MAXIMUM_API_BODY_BYTES:
                            raise ZenodoReceiptCollectionError("Zenodo response is oversized")
                    header_without_separator, initial = bytes(buffer).split(b"\r\n\r\n", 1)
                    raw_headers = header_without_separator + b"\r\n\r\n"
                    if len(raw_headers) > MAXIMUM_HEADER_BYTES:
                        raise ZenodoReceiptCollectionError("Zenodo response headers are oversized")
                    status_match = re.match(
                        rb"HTTP/1\.1 ([0-9]{3})(?: [^\r\n]*)?\r\n", raw_headers
                    )
                    if status_match is None:
                        raise ZenodoReceiptCollectionError("Zenodo HTTP status is invalid")
                    status = int(status_match.group(1))
                    if status != 200:
                        raise ZenodoReceiptCollectionError(
                            "Zenodo returned non-200; redirects and retries are forbidden"
                        )
                    fields = self._wire_fields(raw_headers)
                    encodings = fields.get("content-encoding", ["identity"])
                    if len(encodings) != 1 or encodings[0].casefold() not in {"", "identity"}:
                        raise ZenodoReceiptCollectionError(
                            "compressed Zenodo response is forbidden"
                        )
                    transfers = fields.get("transfer-encoding", [])
                    lengths = fields.get("content-length", [])
                    if transfers and lengths:
                        raise ZenodoReceiptCollectionError("ambiguous Zenodo body framing")
                    if transfers:
                        if len(transfers) != 1 or transfers[0].casefold() != "chunked":
                            raise ZenodoReceiptCollectionError(
                                "unsupported Zenodo transfer encoding"
                            )
                        body = self._chunked(tls, bytearray(initial), deadline)
                    elif lengths:
                        if len(lengths) != 1 or not lengths[0].isdigit():
                            raise ZenodoReceiptCollectionError("Zenodo Content-Length is invalid")
                        expected = int(lengths[0])
                        if expected > MAXIMUM_API_BODY_BYTES:
                            raise ZenodoReceiptCollectionError("Zenodo body is oversized")
                        body_buffer = bytearray(initial)
                        while len(body_buffer) < expected:
                            chunk = self._recv(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                        if len(body_buffer) != expected:
                            raise ZenodoReceiptCollectionError("Zenodo Content-Length differs")
                        body = bytes(body_buffer)
                    else:
                        body_buffer = bytearray(initial)
                        while True:
                            chunk = self._recv(tls, deadline)
                            if not chunk:
                                break
                            body_buffer.extend(chunk)
                            if len(body_buffer) > MAXIMUM_API_BODY_BYTES:
                                raise ZenodoReceiptCollectionError("Zenodo body is oversized")
                        body = bytes(body_buffer)
        except ZenodoReceiptCollectionError:
            raise
        except (OSError, ssl.SSLError, TimeoutError) as error:
            raise ZenodoReceiptCollectionError("direct Zenodo TLS request failed") from error
        if token_bytes in raw_headers or token_bytes in body:
            raise ZenodoReceiptCollectionError("Zenodo echoed bearer token in response")
        return HTTPSCapture(status, raw_headers, body, self.now())


def collect_zenodo_receipt_to_path(
    *,
    manifest_path: Path,
    deposit_root: Path,
    deposition_id: int,
    record_id: int,
    doi: str,
    token: str,
    output_path: Path,
    transport: ZenodoTransport | None = None,
    now: Callable[[], str] = _utc_now,
    cryptographic_attestation_verifier: object | None = None,
    release_receipt_verifier: Callable[..., object] | None = None,
) -> dict[str, object]:
    if type(deposition_id) is not int or deposition_id <= 0:
        raise ZenodoReceiptCollectionError("deposition ID must be positive")
    if type(record_id) is not int or record_id <= 0:
        raise ZenodoReceiptCollectionError("record ID must be positive")
    if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
        raise ZenodoReceiptCollectionError("Zenodo token is invalid")
    if cryptographic_attestation_verifier is None or not hasattr(
        cryptographic_attestation_verifier, "verify"
    ):
        raise ZenodoReceiptCollectionError(
            "pinned cryptographic release-attestation verifier is required"
        )
    if release_receipt_verifier is not None and not callable(
        release_receipt_verifier
    ):
        raise ZenodoReceiptCollectionError(
            "injected complete release-receipt verifier is invalid"
        )
    client = transport or DirectZenodoTransport()
    targets = {
        "deposition": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}",
        "deposition-files": f"{ZENODO_API_BASE}/deposit/depositions/{deposition_id}/files",
        "record": f"{ZENODO_API_BASE}/records/{record_id}",
    }
    captures: dict[str, HTTPSCapture] = {}
    token_bytes = token.encode("ascii", "strict")
    for role in API_ROLES:
        captures[role] = client.request(targets[role], token=token)
        if (
            token_bytes in captures[role].response_headers
            or token_bytes in captures[role].response_body
        ):
            raise ZenodoReceiptCollectionError("Zenodo echoed bearer token in response")
    receipt_created_at = now()
    try:
        verifier_arguments: dict[str, object] = {
            "cryptographic_attestation_verifier": (
                cryptographic_attestation_verifier
            )
        }
        if release_receipt_verifier is not None:
            verifier_arguments["release_receipt_verifier"] = (
                release_receipt_verifier
            )
        receipt = build_zenodo_receipt(
            manifest_path=manifest_path,
            deposit_root=deposit_root,
            deposition_id=deposition_id,
            record_id=record_id,
            doi=doi,
            captures=captures,
            receipt_created_at=receipt_created_at,
            **verifier_arguments,
        )
        raw = canonical_json_bytes(receipt) + b"\n"
        if token_bytes in raw:
            raise ZenodoReceiptCollectionError("authorization secret entered receipt bytes")
        verify_zenodo_receipt(
            raw,
            manifest_path=manifest_path,
            deposit_root=deposit_root,
            expected_deposition_id=deposition_id,
            expected_record_id=record_id,
            expected_doi=doi,
            **verifier_arguments,
        )
    except ZenodoArchiveError as error:
        raise ZenodoReceiptCollectionError(
            "Zenodo receipt failed offline self-verification"
        ) from error
    write_new_bytes(output_path, raw)
    return receipt


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--deposit-root", type=Path, required=True)
    parser.add_argument("--deposition-id", type=int, required=True)
    parser.add_argument("--record-id", type=int, required=True)
    parser.add_argument("--doi", required=True)
    parser.add_argument("--token-env", default="ZENODO_ACCESS_TOKEN")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cosign",
        type=Path,
        required=True,
        help="absolute path to the byte-pinned Cosign 3.0.6 executable",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        token = load_token_from_environment(arguments.token_env)
        receipt = collect_zenodo_receipt_to_path(
            manifest_path=arguments.manifest,
            deposit_root=arguments.deposit_root,
            deposition_id=arguments.deposition_id,
            record_id=arguments.record_id,
            doi=arguments.doi,
            token=token,
            output_path=arguments.output,
            cryptographic_attestation_verifier=(
                PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            ),
        )
    except (OSError, ZenodoReceiptCollectionError, ValueError) as error:
        print(f"ZENODO RECEIPT COLLECTION FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "ZENODO RECEIPT COLLECTION PASS: "
        f"record={receipt['recordId']} doi={receipt['doi']} requests=3 published=false-by-collector"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
