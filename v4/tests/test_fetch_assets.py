from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from v4 import fetch_assets as subject


REVISION = "1" * 40


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
        before_first_read: Callable[[], None] | None = None,
    ) -> None:
        self.payload = payload
        self.url = url
        self.headers = headers or {}
        self.status = status
        self.before_first_read = before_first_read
        self.offset = 0
        self.read_requests: list[int] = []
        self.closed = False

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *arguments: Any) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True

    def geturl(self) -> str:
        return self.url

    def read(self, size: int) -> bytes:
        self.read_requests.append(size)
        if self.before_first_read is not None:
            callback = self.before_first_read
            self.before_first_read = None
            callback()
        result = self.payload[self.offset : self.offset + size]
        self.offset += len(result)
        return result


class FakeTransport:
    def __init__(
        self,
        payloads: dict[str, bytes],
        *,
        final_url: str | None = None,
        include_length: bool = True,
        before_first_read: Callable[[], None] | None = None,
    ) -> None:
        self.payloads = payloads
        self.final_url = final_url
        self.include_length = include_length
        self.before_first_read = before_first_read
        self.requests: list[urllib.request.Request] = []
        self.responses: list[FakeResponse] = []

    def __call__(self, request: urllib.request.Request) -> FakeResponse:
        self.requests.append(request)
        payload = self.payloads[request.full_url]
        headers = {"Content-Length": str(len(payload))} if self.include_length else {}
        response = FakeResponse(
            payload,
            self.final_url or request.full_url,
            headers=headers,
            before_first_read=self.before_first_read,
        )
        self.responses.append(response)
        return response


class NoCallTransport:
    def __init__(self) -> None:
        self.called = False

    def __call__(self, request: urllib.request.Request) -> Any:
        self.called = True
        raise AssertionError(f"transport must not be called: {request.full_url}")


class FetchAssetsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # macOS exposes /var through a symlink. Resolve the test-only temporary
        # root so the production no-symlink policy remains meaningfully strict.
        self.root = Path(temporary.name).resolve()
        self.manifest = self.root / "manifest.json"
        self.destination = self.root / "assets"

    def write_manifest(self, files: dict[str, bytes]) -> list[subject.AssetSpecification]:
        manifest_files = {
            name: {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "digestSource": "fixture",
            }
            for name, payload in files.items()
        }
        value = {
            "schemaVersion": subject.MANIFEST_SCHEMA,
            "completeRuntimeFileList": True,
            "models": {
                "fixture-model": {
                    "repository": "fixture/model",
                    "revision": REVISION,
                    "files": manifest_files,
                }
            },
        }
        self.manifest.write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )
        return subject.load_manifest(self.manifest)

    def transport_for(self, files: dict[str, bytes], **arguments: Any) -> FakeTransport:
        specifications = subject.load_manifest(self.manifest)
        payloads = {
            specification.url: files[specification.filename]
            for specification in specifications
        }
        return FakeTransport(payloads, **arguments)

    def test_actual_draft_manifest_has_24_assets_and_21_small_assets(self) -> None:
        specifications = subject.load_manifest(subject.DEFAULT_MANIFEST)
        self.assertEqual(len(specifications), 24)
        small = [
            item
            for item in specifications
            if Path(item.filename).name not in subject.SMALL_FILE_EXCLUSIONS
        ]
        self.assertEqual(len(small), 21)
        self.assertEqual(
            {item.model_key for item in specifications},
            {"gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py"},
        )

    def test_development_dataset_specification_is_exact_and_immutable(self) -> None:
        specification = subject.DevelopmentDatasetSpecification()
        self.assertEqual(specification.model_key, "ud-english-pud-r2.18")
        self.assertEqual(
            specification.repository,
            "UniversalDependencies/UD_English-PUD",
        )
        self.assertEqual(
            specification.revision,
            "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
        )
        self.assertEqual(specification.filename, "en_pud-ud-test.conllu")
        self.assertEqual(specification.expected_bytes, 1_386_858)
        self.assertEqual(
            specification.expected_sha256,
            "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa",
        )
        self.assertEqual(
            specification.url,
            "https://raw.githubusercontent.com/UniversalDependencies/"
            "UD_English-PUD/e173a1be1b442faf34e7d5a502189ad5d9d1e197/"
            "en_pud-ud-test.conllu",
        )
        self.assertEqual(
            subject.DEVELOPMENT_DATASET_HOSTS,
            frozenset({"raw.githubusercontent.com"}),
        )

    def test_development_dataset_uses_same_verified_no_overwrite_fetcher(self) -> None:
        payload = b"real pinned CoNLL-U fixture bytes"
        specification = subject.DevelopmentDatasetSpecification(
            expected_bytes=len(payload),
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )
        transport = FakeTransport({specification.url: payload})
        with mock.patch.object(
            subject, "DevelopmentDatasetSpecification", return_value=specification
        ):
            record = subject.fetch_development_dataset(
                self.destination, transport=transport
            )
        destination = (
            self.destination
            / "ud-english-pud-r2.18"
            / "en_pud-ud-test.conllu"
        )
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(record.status, "downloaded-and-verified")
        self.assertEqual(record.sha256, hashlib.sha256(payload).hexdigest())
        self.assertFalse(
            destination.with_name("en_pud-ud-test.conllu.partial").exists()
        )

        with mock.patch.object(
            subject, "DevelopmentDatasetSpecification", return_value=specification
        ):
            repeated = subject.fetch_development_dataset(
                self.destination, transport=NoCallTransport()
            )
        self.assertEqual(repeated.status, "verified-existing")

    def test_development_dataset_rejects_every_other_final_host(self) -> None:
        payload = b"pinned CoNLL-U fixture"
        specification = subject.DevelopmentDatasetSpecification(
            expected_bytes=len(payload),
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )
        transport = FakeTransport(
            {specification.url: payload},
            final_url="https://huggingface.co/redirected-dataset",
        )
        with (
            mock.patch.object(
                subject,
                "DevelopmentDatasetSpecification",
                return_value=specification,
            ),
            self.assertRaisesRegex(subject.AssetFetchError, "not allowlisted"),
        ):
            subject.fetch_development_dataset(
                self.destination,
                transport=transport,
            )

    def test_downloads_exact_bytes_with_mock_transport(self) -> None:
        files = {"config.json": b'{"model_type":"fixture"}\n'}
        self.write_manifest(files)
        transport = self.transport_for(files)
        records = subject.fetch_assets(
            self.manifest, self.destination, transport=transport
        )
        destination = self.destination / "fixture-model" / "config.json"
        self.assertEqual(destination.read_bytes(), files["config.json"])
        self.assertFalse(destination.with_name("config.json.partial").exists())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "downloaded-and-verified")
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(
            transport.requests[0].get_header("Accept-encoding"), "identity"
        )
        self.assertTrue(transport.responses[0].closed)

    def test_small_files_only_skips_weights_but_full_mode_includes_them(self) -> None:
        files = {
            "config.json": b"configuration",
            "model.safetensors": b"fixture-weights",
        }
        specifications = self.write_manifest(files)
        urls = {item.filename: item.url for item in specifications}
        small_transport = FakeTransport(
            {urls["config.json"]: files["config.json"]}
        )
        records = subject.fetch_assets(
            self.manifest,
            self.destination,
            small_files_only=True,
            transport=small_transport,
        )
        self.assertEqual([record.filename for record in records], ["config.json"])
        self.assertFalse(
            (self.destination / "fixture-model" / "model.safetensors").exists()
        )

        full_transport = FakeTransport(
            {urls["model.safetensors"]: files["model.safetensors"]}
        )
        records = subject.fetch_assets(
            self.manifest, self.destination, transport=full_transport
        )
        self.assertEqual(
            [record.status for record in records],
            ["verified-existing", "downloaded-and-verified"],
        )
        self.assertEqual(
            (self.destination / "fixture-model" / "model.safetensors").read_bytes(),
            files["model.safetensors"],
        )

    def test_exact_existing_asset_is_verified_without_transport(self) -> None:
        files = {"config.json": b"committed bytes"}
        self.write_manifest(files)
        destination = self.destination / "fixture-model" / "config.json"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(files["config.json"])
        transport = NoCallTransport()
        records = subject.fetch_assets(
            self.manifest, self.destination, transport=transport
        )
        self.assertFalse(transport.called)
        self.assertEqual(records[0].status, "verified-existing")

    def test_mismatched_existing_asset_is_never_overwritten(self) -> None:
        files = {"config.json": b"committed bytes"}
        self.write_manifest(files)
        destination = self.destination / "fixture-model" / "config.json"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"different")
        transport = NoCallTransport()
        with self.assertRaisesRegex(
            subject.AssetFetchError, "will not be overwritten"
        ):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        self.assertEqual(destination.read_bytes(), b"different")
        self.assertFalse(transport.called)

    def test_concurrent_mismatched_leaf_is_not_overwritten(self) -> None:
        files = {"config.json": b"committed bytes"}
        self.write_manifest(files)
        destination = self.destination / "fixture-model" / "config.json"

        def inject_leaf() -> None:
            destination.write_bytes(b"racing mismatch")

        transport = self.transport_for(files, before_first_read=inject_leaf)
        with self.assertRaisesRegex(
            subject.AssetFetchError, "will not be overwritten"
        ):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        self.assertEqual(destination.read_bytes(), b"racing mismatch")
        self.assertFalse(destination.with_name("config.json.partial").exists())

    def test_exclusive_partial_is_preserved_and_blocks_fetch(self) -> None:
        files = {"config.json": b"committed bytes"}
        self.write_manifest(files)
        partial = self.destination / "fixture-model" / "config.json.partial"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(b"foreign partial")
        transport = NoCallTransport()
        with self.assertRaisesRegex(subject.AssetFetchError, "partial path"):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        self.assertEqual(partial.read_bytes(), b"foreign partial")
        self.assertFalse(transport.called)

    def test_oversized_response_reads_at_most_expected_bytes_plus_one(self) -> None:
        committed = b"12345678"
        files = {"config.json": committed}
        specifications = self.write_manifest(files)
        oversized = committed + b"X"
        transport = FakeTransport(
            {specifications[0].url: oversized}, include_length=False
        )
        with self.assertRaisesRegex(subject.AssetFetchError, "exceeds"):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        self.assertEqual(sum(transport.responses[0].read_requests), len(committed) + 1)
        destination = self.destination / "fixture-model" / "config.json"
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_name("config.json.partial").exists())

    def test_hash_mismatch_removes_own_partial_and_publishes_nothing(self) -> None:
        files = {"config.json": b"committed bytes"}
        specifications = self.write_manifest(files)
        same_length_wrong_hash = b"X" * len(files["config.json"])
        transport = FakeTransport(
            {specifications[0].url: same_length_wrong_hash}
        )
        with self.assertRaisesRegex(subject.AssetFetchError, "SHA-256"):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        destination = self.destination / "fixture-model" / "config.json"
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_name("config.json.partial").exists())

    def test_non_https_or_non_allowlisted_final_url_is_rejected(self) -> None:
        files = {"config.json": b"committed bytes"}
        self.write_manifest(files)
        for final_url in (
            "http://huggingface.co/file",
            "https://attacker.invalid/file",
        ):
            with self.subTest(final_url=final_url):
                destination = self.destination / final_url.split(":", 1)[0]
                transport = self.transport_for(files, final_url=final_url)
                with self.assertRaises(subject.AssetFetchError):
                    subject.fetch_assets(
                        self.manifest, destination, transport=transport
                    )

    def test_redirect_handler_rejects_bad_scheme_and_host(self) -> None:
        handler = subject.AllowlistedHTTPSRedirectHandler()
        request = urllib.request.Request("https://huggingface.co/source")
        for target in (
            "http://huggingface.co/file",
            "https://evil.invalid/file",
            "https://huggingface.co.evil.invalid/file",
        ):
            with self.subTest(target=target):
                with self.assertRaises(subject.AssetFetchError):
                    handler.redirect_request(
                        request, None, 302, "Found", {}, target
                    )

    def test_current_hugging_face_weight_cdn_is_allowlisted_exactly(self) -> None:
        subject._validate_https_url(
            "https://us.aws.cdn.hf.co/model.safetensors",
            subject.DEFAULT_REDIRECT_HOSTS,
        )
        with self.assertRaises(subject.AssetFetchError):
            subject._validate_https_url(
                "https://subdomain.us.aws.cdn.hf.co/model.safetensors",
                subject.DEFAULT_REDIRECT_HOSTS,
            )

    def test_symlink_root_intermediate_and_leaf_are_rejected(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        files = {"nested/config.json": b"committed bytes"}
        self.write_manifest(files)
        transport = self.transport_for(files)

        real_root = self.root / "real-root"
        real_root.mkdir()
        linked_root = self.root / "linked-root"
        linked_root.symlink_to(real_root, target_is_directory=True)
        with self.assertRaisesRegex(subject.AssetFetchError, "symlink"):
            subject.fetch_assets(
                self.manifest, linked_root, transport=transport
            )

        model_root = self.destination / "fixture-model"
        model_root.mkdir(parents=True)
        real_nested = self.root / "real-nested"
        real_nested.mkdir()
        (model_root / "nested").symlink_to(real_nested, target_is_directory=True)
        with self.assertRaisesRegex(subject.AssetFetchError, "symlink"):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )
        (model_root / "nested").unlink()

        nested = model_root / "nested"
        nested.mkdir()
        other = self.root / "other-file"
        other.write_bytes(b"other")
        (nested / "config.json").symlink_to(other)
        with self.assertRaisesRegex(subject.AssetFetchError, "symlink"):
            subject.fetch_assets(
                self.manifest, self.destination, transport=transport
            )

    def test_mutable_revision_and_unsafe_filename_are_rejected(self) -> None:
        base = {
            "schemaVersion": subject.MANIFEST_SCHEMA,
            "completeRuntimeFileList": True,
            "models": {
                "fixture-model": {
                    "repository": "fixture/model",
                    "revision": "main",
                    "files": {
                        "../escape": {
                            "bytes": 1,
                            "sha256": hashlib.sha256(b"x").hexdigest(),
                        }
                    },
                }
            },
        }
        self.manifest.write_text(json.dumps(base), encoding="utf-8")
        with self.assertRaisesRegex(subject.AssetFetchError, "revision"):
            subject.load_manifest(self.manifest)
        base["models"]["fixture-model"]["revision"] = REVISION
        self.manifest.write_text(json.dumps(base), encoding="utf-8")
        with self.assertRaisesRegex(subject.AssetFetchError, "unsafe asset"):
            subject.load_manifest(self.manifest)

    def test_zero_size_and_non_finite_json_number_are_rejected(self) -> None:
        digest = hashlib.sha256(b"x").hexdigest()
        value = {
            "schemaVersion": subject.MANIFEST_SCHEMA,
            "completeRuntimeFileList": True,
            "models": {
                "fixture-model": {
                    "repository": "fixture/model",
                    "revision": REVISION,
                    "files": {"config.json": {"bytes": 0, "sha256": digest}},
                }
            },
        }
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(subject.AssetFetchError, "byte count"):
            subject.load_manifest(self.manifest)

        self.manifest.write_text(
            json.dumps(value).replace('"bytes": 0', '"bytes": 1e999'),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(subject.AssetFetchError, "non-finite"):
            subject.load_manifest(self.manifest)

    def test_oversized_manifest_is_rejected(self) -> None:
        self.manifest.write_bytes(b" " * (subject.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(subject.AssetFetchError, "size limit"):
            subject.load_manifest(self.manifest)

    def test_default_transport_does_not_consult_environment_proxies(self) -> None:
        with mock.patch(
            "urllib.request.getproxies",
            side_effect=AssertionError("environment proxy lookup is forbidden"),
        ) as getproxies:
            transport = subject.default_transport()
        self.assertTrue(callable(transport))
        getproxies.assert_not_called()

    def test_duplicate_manifest_keys_are_rejected(self) -> None:
        self.manifest.write_text(
            '{"schemaVersion":"x","schemaVersion":"y"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(subject.AssetFetchError, "duplicate JSON key"):
            subject.load_manifest(self.manifest)


if __name__ == "__main__":
    unittest.main()
