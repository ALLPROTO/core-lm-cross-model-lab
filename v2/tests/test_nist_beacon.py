from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

from v2 import nist_beacon as subject
from v2.mediawiki_snapshot import ArchivedHTTPResponse, archive_response
from v2.protocol import canonical_json_bytes


VECTOR_PATH = Path(__file__).resolve().parents[1] / "test-vectors" / "nist-chain1-pulse1.json"
CERTIFICATE_PATH = Path(__file__).resolve().parents[1] / "test-vectors" / "nist-chain1-cert.pem"
TRACKED_TRUST_MANIFEST = Path(__file__).resolve().parents[1] / "trust" / "nist" / "manifest.json"
TRACKED_TRUST_MANIFEST_SHA256 = (
    "3c17cb8f6086e201eb4babc692616f621054339dc17376a7acee730e6a8cfc71"
)


def digest_commitment(relative_path: str, value: bytes, *, sha512: bool) -> dict[str, object]:
    result: dict[str, object] = {
        "relativePath": relative_path,
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }
    if sha512:
        result["sha512"] = hashlib.sha512(value).hexdigest()
    return result


class NISTBeaconTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        self.pem = CERTIFICATE_PATH.read_bytes()
        self.der = subject._pem_to_der(self.pem)
        self.milliseconds = self.vector["requestUnixMilliseconds"]
        self.pulse_time = datetime.fromtimestamp(
            self.milliseconds / 1000, tz=timezone.utc
        )
        self.certificate_id = hashlib.sha512(self.der).hexdigest()
        self.assertEqual(
            self.certificate_id,
            self.vector["pulseResponse"]["pulse"]["certificateId"],
        )
        self.assertEqual(
            self.vector["certificateSource"],
            "https://beacon.nist.gov/beacon/2.0/certificate/"
            + self.certificate_id,
        )

    def write_bundle(
        self,
        *,
        fixture_only: bool = True,
        pem: bytes | None = None,
        der: bytes | None = None,
        policy: str | None = None,
        canonical: bool = True,
    ) -> Path:
        pem = self.pem if pem is None else pem
        der = self.der if der is None else der
        pem_path = self.root / "leaf.pem"
        der_path = self.root / "leaf.der"
        pem_path.write_bytes(pem)
        der_path.write_bytes(der)
        manifest = {
            "schemaVersion": subject.TRUST_SCHEMA,
            "status": (
                "KNOWN_ANSWER_FIXTURE_ONLY"
                if fixture_only
                else "FROZEN_OFFLINE_TRUST_BUNDLE"
            ),
            "fixtureOnly": fixture_only,
            "certificates": {
                self.certificate_id: {
                    "chainPolicy": policy or (
                        "fixture-leaf-pin-only"
                        if fixture_only
                        else "offline-x509-rsa-pkcs1"
                    ),
                    "pem": digest_commitment("leaf.pem", pem, sha512=False),
                    "chain": [digest_commitment("leaf.der", der, sha512=True)],
                }
            },
        }
        path = self.root / "trust-bundle.json"
        encoded = (
            canonical_json_bytes(manifest)
            if canonical
            else json.dumps(manifest, indent=2).encode("utf-8")
        )
        path.write_bytes(encoded)
        return path

    def load_fixture_bundle(self) -> subject.OfflineTrustBundle:
        return subject.load_offline_trust_bundle(
            self.write_bundle(), expected_time=self.pulse_time, allow_fixture=True
        )

    def response(
        self,
        pulse_response: dict[str, object] | None = None,
        *,
        request_milliseconds: int | None = None,
        date: datetime | None = None,
        body: bytes | None = None,
    ) -> ArchivedHTTPResponse:
        request_milliseconds = (
            self.milliseconds
            if request_milliseconds is None
            else request_milliseconds
        )
        uri = (
            "https://beacon.nist.gov/beacon/2.0/pulse/time/"
            + str(request_milliseconds)
        )
        if body is None:
            body = canonical_json_bytes(
                self.vector["pulseResponse"]
                if pulse_response is None
                else pulse_response
            )
        date = self.pulse_time + timedelta(seconds=1) if date is None else date
        headers = (
            "HTTP/1.1 200 OK\r\n"
            f"Date: {format_datetime(date, usegmt=True)}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        return ArchivedHTTPResponse(uri, 200, headers, body)

    def verify_fixture(
        self, pulse_response: dict[str, object] | None = None
    ) -> dict[str, object]:
        return subject.verify_nist_pulse_response(
            response=self.response(pulse_response),
            trust_bundle=self.load_fixture_bundle(),
            expected_unix_milliseconds=self.milliseconds,
            allow_fixture=True,
        )

    def test_official_known_answer_signature_output_and_serialization(self) -> None:
        pulse = self.vector["pulseResponse"]["pulse"]
        unsigned = subject.serialize_unsigned_pulse(
            pulse, expected_version=subject.HISTORICAL_FIXTURE_PULSE_VERSION
        )
        self.assertEqual(len(unsigned), self.vector["expectedUnsignedBytes"])
        self.assertEqual(
            hashlib.sha512(unsigned).hexdigest(),
            self.vector["expectedSignedBytesSHA512"],
        )
        signature = bytes.fromhex(pulse["signatureValue"])
        self.assertEqual(
            hashlib.sha512(unsigned + signature).hexdigest().upper(),
            self.vector["expectedOutputValue"],
        )
        result = self.verify_fixture()
        self.assertEqual(result["status"], "VERIFIED_KNOWN_ANSWER_FIXTURE")
        self.assertFalse(result["countsTowardScientificVerdict"])
        self.assertFalse(result["certificateChainVerified"])
        self.assertTrue(result["signatureVerified"])
        self.assertTrue(result["outputConstructionVerified"])
        self.assertTrue(result["exactTimestampVerified"])
        self.assertTrue(result["responseDateNotBeforePulseVerified"])
        self.assertEqual(result["outputValue"], self.vector["expectedOutputValue"])
        self.assertEqual(
            subject.canonical_verification_bytes(result),
            canonical_json_bytes(result),
        )
        malformed = dict(result)
        malformed["unverifiedExtra"] = True
        with self.assertRaisesRegex(subject.BeaconVerificationError, "fields differ"):
            subject.canonical_verification_bytes(malformed)
        malformed = dict(result)
        malformed["signatureVerified"] = False
        with self.assertRaisesRegex(subject.BeaconVerificationError, "truth flags"):
            subject.canonical_verification_bytes(malformed)
        bundle = self.load_fixture_bundle()
        with self.assertRaises(TypeError):
            bundle.records[self.certificate_id] = bundle.records[self.certificate_id]
        archive = archive_response(
            self.root, "archive/nist-known-answer", self.response()
        )
        replayed = subject.verify_archived_nist_pulse(
            root=self.root,
            archive=archive,
            trust_bundle=bundle,
            expected_unix_milliseconds=self.milliseconds,
            allow_fixture=True,
        )
        self.assertEqual(replayed["signedBytesSHA512"], result["signedBytesSHA512"])

    def test_fixture_is_rejected_by_both_default_interfaces(self) -> None:
        manifest = self.write_bundle()
        with self.assertRaisesRegex(subject.BeaconVerificationError, "fixture-only"):
            subject.load_offline_trust_bundle(
                manifest, expected_time=self.pulse_time
            )
        bundle = subject.load_offline_trust_bundle(
            manifest, expected_time=self.pulse_time, allow_fixture=True
        )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "fixture"):
            subject.verify_nist_pulse_response(
                response=self.response(),
                trust_bundle=bundle,
                expected_unix_milliseconds=self.milliseconds,
            )

    def test_signature_output_timestamp_and_certificate_tampering_fail_closed(self) -> None:
        cases = {
            "signed random field": ("localRandomValue", "signature"),
            "signature": ("signatureValue", "signature"),
            "output": ("outputValue", "outputValue"),
            "certificate": ("certificateId", "absent"),
        }
        for label, (field, error_pattern) in cases.items():
            with self.subTest(label=label):
                value = copy.deepcopy(self.vector["pulseResponse"])
                original = value["pulse"][field]
                value["pulse"][field] = (
                    ("0" if original[0] != "0" else "1") + original[1:]
                )
                with self.assertRaisesRegex(
                    subject.BeaconVerificationError, error_pattern
                ):
                    self.verify_fixture(value)

        value = copy.deepcopy(self.vector["pulseResponse"])
        value["pulse"]["timeStamp"] = "2018-07-23T19:26:01.000Z"
        with self.assertRaisesRegex(subject.BeaconVerificationError, "non-exact"):
            self.verify_fixture(value)

    def test_wrong_endpoint_old_http_date_and_duplicate_json_fail_closed(self) -> None:
        bundle = self.load_fixture_bundle()
        with self.assertRaisesRegex(subject.BeaconVerificationError, "different request URI"):
            subject.verify_nist_pulse_response(
                response=self.response(request_milliseconds=self.milliseconds + 1),
                trust_bundle=bundle,
                expected_unix_milliseconds=self.milliseconds,
                allow_fixture=True,
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "precedes"):
            subject.verify_nist_pulse_response(
                response=self.response(date=self.pulse_time - timedelta(seconds=1)),
                trust_bundle=bundle,
                expected_unix_milliseconds=self.milliseconds,
                allow_fixture=True,
            )
        duplicate = b'{"pulse":{},"pulse":{}}\n'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            subject.verify_nist_pulse_response(
                response=self.response(body=duplicate),
                trust_bundle=bundle,
                expected_unix_milliseconds=self.milliseconds,
                allow_fixture=True,
            )

    def test_bundle_commitments_canonical_json_and_pem_are_strict(self) -> None:
        manifest = self.write_bundle()
        with self.assertRaisesRegex(subject.BeaconVerificationError, "preregistered"):
            subject.load_offline_trust_bundle(
                manifest,
                expected_time=self.pulse_time,
                expected_manifest_sha256="0" * 64,
                allow_fixture=True,
            )
        der_path = self.root / "leaf.der"
        tampered = bytearray(der_path.read_bytes())
        tampered[-1] ^= 1
        der_path.write_bytes(tampered)
        with self.assertRaisesRegex(subject.BeaconVerificationError, "SHA-256"):
            subject.load_offline_trust_bundle(
                manifest, expected_time=self.pulse_time, allow_fixture=True
            )

        with self.assertRaisesRegex(subject.BeaconVerificationError, "canonical JSON"):
            subject.load_offline_trust_bundle(
                self.write_bundle(canonical=False),
                expected_time=self.pulse_time,
                allow_fixture=True,
            )

        with self.assertRaisesRegex(subject.BeaconVerificationError, "exactly one"):
            subject.load_offline_trust_bundle(
                self.write_bundle(pem=b"untrusted-prefix\n" + self.pem),
                expected_time=self.pulse_time,
                allow_fixture=True,
            )

    def test_leaf_only_material_cannot_be_labeled_normative(self) -> None:
        manifest = self.write_bundle(fixture_only=False)
        with self.assertRaisesRegex(subject.BeaconVerificationError, "preregistered"):
            subject.load_offline_trust_bundle(
                manifest,
                expected_time=self.pulse_time,
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "policy differs"):
            subject.load_offline_trust_bundle(
                manifest,
                expected_time=self.pulse_time,
                expected_manifest_sha256=hashlib.sha256(
                    manifest.read_bytes()
                ).hexdigest(),
            )

    def test_tracked_normative_chain_requires_the_preregistered_root(self) -> None:
        target_time = datetime(2026, 8, 27, 18, 0, 0, tzinfo=timezone.utc)
        bundle = subject.load_offline_trust_bundle(
            TRACKED_TRUST_MANIFEST,
            expected_time=target_time,
            expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
            expected_root_der_sha256=(subject.NIST_TRUST_ROOT_DER_SHA256,),
        )
        self.assertFalse(bundle.fixture_only)
        self.assertTrue(all(record.chain_verified for record in bundle.records.values()))
        for record in bundle.records.values():
            self.assertTrue(record.leaf.basic_constraints_present)
            self.assertFalse(record.leaf.is_ca)
            self.assertTrue(record.leaf.digital_signature)
            self.assertFalse(record.leaf.key_cert_sign)
            self.assertEqual(record.leaf.dns_names, ("engine.beacon.nist.gov",))
            for issuer in record.chain[1:]:
                self.assertTrue(issuer.basic_constraints_present)
                self.assertTrue(issuer.is_ca)
                self.assertTrue(issuer.key_cert_sign)
        with self.assertRaisesRegex(subject.BeaconVerificationError, "root pins"):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=target_time,
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "absent"):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=target_time,
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
                expected_root_der_sha256=("0" * 64,),
            )

    def test_truncated_der_and_symlinked_manifest_are_rejected(self) -> None:
        with self.assertRaises(subject.BeaconVerificationError):
            subject.parse_certificate_der(self.der[:-1])
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        manifest = self.write_bundle()
        symlink = self.root / "manifest-link.json"
        symlink.symlink_to(manifest)
        with self.assertRaisesRegex(subject.BeaconVerificationError, "missing/not regular"):
            subject.load_offline_trust_bundle(
                symlink, expected_time=self.pulse_time, allow_fixture=True
            )


if __name__ == "__main__":
    unittest.main()
