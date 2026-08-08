from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blind_v1.collect_zenodo_receipt import (
    ZenodoReceiptCollectionError,
    _validate_exact_url,
    _historical_collect_zenodo_receipt_to_path as collect_zenodo_receipt_to_path,
    load_token_from_environment,
)
from blind_v1.tests.test_zenodo_archive import CREATED, DEPOSITION_ID, DOI, RECORD_ID, ZenodoFixture
from blind_v1.zenodo_archive import HTTPSCapture


TOKEN = "zenodo-unit-token-never-archive"


class FakeTransport:
    def __init__(self, fixture: ZenodoFixture) -> None:
        self.captures = fixture.captures()
        self.calls: list[tuple[str, str]] = []

    def request(self, url: str, *, token: str) -> HTTPSCapture:
        self.calls.append((url, token))
        if url.endswith(f"/deposit/depositions/{DEPOSITION_ID}"):
            return self.captures["deposition"]
        if url.endswith(f"/deposit/depositions/{DEPOSITION_ID}/files"):
            return self.captures["deposition-files"]
        if url.endswith(f"/records/{RECORD_ID}"):
            return self.captures["record"]
        raise AssertionError(f"unexpected request: {url}")


class ZenodoCollectorTests(unittest.TestCase):
    def test_missing_crypto_verifier_fails_before_any_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            transport = FakeTransport(fixture)
            output = fixture.root / "must-not-exist.json"
            with self.assertRaisesRegex(
                ZenodoReceiptCollectionError,
                "pinned cryptographic release-attestation verifier is required",
            ):
                collect_zenodo_receipt_to_path(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    token=TOKEN,
                    output_path=output,
                    transport=transport,
                    now=lambda: CREATED,
                )
            self.assertEqual(transport.calls, [])
            self.assertFalse(output.exists())

    def test_collector_uses_exactly_three_get_allowlisted_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            transport = FakeTransport(fixture)
            output = fixture.root / "receipt.json"
            receipt = collect_zenodo_receipt_to_path(
                manifest_path=fixture.manifest_path,
                deposit_root=fixture.deposit,
                deposition_id=DEPOSITION_ID,
                record_id=RECORD_ID,
                doi=DOI,
                token=TOKEN,
                output_path=output,
                transport=transport,
                now=lambda: CREATED,
                **fixture.verification_kwargs,
            )
            self.assertEqual(len(transport.calls), 3)
            self.assertTrue(all(token == TOKEN for _url, token in transport.calls))
            self.assertTrue(all("/actions/" not in url for url, _token in transport.calls))
            self.assertNotIn(TOKEN.encode("ascii"), output.read_bytes())
            self.assertEqual(receipt["doi"], DOI)
            with self.assertRaises(FileExistsError):
                collect_zenodo_receipt_to_path(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    token=TOKEN,
                    output_path=output,
                    transport=FakeTransport(fixture),
                    now=lambda: CREATED,
                    **fixture.verification_kwargs,
                )

    def test_collector_rejects_echoed_token_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            transport = FakeTransport(fixture)
            capture = transport.captures["record"]
            transport.captures["record"] = HTTPSCapture(
                capture.status_code,
                capture.response_headers,
                capture.response_body.replace(
                    b'"state":"done"',
                    f'"secret":"{TOKEN}","state":"done"'.encode(),
                ),
                capture.captured_at,
            )
            output = fixture.root / "must-not-exist.json"
            with self.assertRaises(ZenodoReceiptCollectionError):
                collect_zenodo_receipt_to_path(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    token=TOKEN,
                    output_path=output,
                    transport=transport,
                    now=lambda: CREATED,
                    **fixture.verification_kwargs,
                )
            self.assertFalse(output.exists())

    def test_url_allowlist_has_no_publish_or_query_path(self) -> None:
        self.assertEqual(
            _validate_exact_url(f"https://zenodo.org/api/records/{RECORD_ID}"),
            f"/api/records/{RECORD_ID}",
        )
        for forbidden in (
            f"https://zenodo.org/api/deposit/depositions/{DEPOSITION_ID}/actions/publish",
            f"https://zenodo.org/api/records/{RECORD_ID}?access_token=secret",
            f"https://sandbox.zenodo.org/api/records/{RECORD_ID}",
            f"http://zenodo.org/api/records/{RECORD_ID}",
        ):
            with self.assertRaises(ZenodoReceiptCollectionError):
                _validate_exact_url(forbidden)

    def test_token_loader_requires_named_ascii_secret(self) -> None:
        with mock.patch.dict(os.environ, {"ZENODO_TEST_TOKEN": TOKEN}, clear=True):
            self.assertEqual(load_token_from_environment("ZENODO_TEST_TOKEN"), TOKEN)
            with self.assertRaises(ZenodoReceiptCollectionError):
                load_token_from_environment("MISSING")
            with self.assertRaises(ZenodoReceiptCollectionError):
                load_token_from_environment("bad-name")


if __name__ == "__main__":
    unittest.main()
