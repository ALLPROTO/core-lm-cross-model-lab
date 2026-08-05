from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

from blind_v1 import nist_beacon as subject
from blind_v1.mediawiki_snapshot import ArchivedHTTPResponse, archive_response
from blind_v1.protocol import canonical_json_bytes


VECTOR_PATH = Path(__file__).resolve().parents[1] / "test-vectors" / "nist-chain1-pulse1.json"
CERTIFICATE_PATH = Path(__file__).resolve().parents[1] / "test-vectors" / "nist-chain1-cert.pem"
TRACKED_TRUST_MANIFEST = Path(__file__).resolve().parents[1] / "trust" / "nist" / "manifest.json"
TRACKED_TRUST_MANIFEST_SHA256 = (
    "cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706"
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


def trust_policy(certificate_id: str) -> dict[str, object]:
    return {
        "allowedCertificateIds": [certificate_id],
        "rotationPolicy": subject.TRUST_ROTATION_POLICY,
        "revocationPolicy": subject.TRUST_REVOCATION_POLICY,
        "revocationChecked": False,
        "revocationResidualRisk": subject.TRUST_REVOCATION_RESIDUAL_RISK,
        "acceptedLeafExtendedKeyUsages": list(
            subject.TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES
        ),
    }


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
                subject.TRUST_FIXTURE_STATUS
                if fixture_only
                else subject.TRUST_FROZEN_STATUS
            ),
            "fixtureOnly": fixture_only,
            "trustPolicy": trust_policy(self.certificate_id),
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

    def test_nonzero_pulse_status_fails_closed_before_signature_acceptance(self) -> None:
        fixture_bundle = self.load_fixture_bundle()
        production_view = subject.OfflineTrustBundle(
            manifest_sha256=fixture_bundle.manifest_sha256,
            fixture_only=False,
            records=fixture_bundle.records,
        )
        for status_code in (1, 2, 3):
            with self.subTest(status_code=status_code):
                value = copy.deepcopy(self.vector["pulseResponse"])
                value["pulse"]["version"] = subject.PRODUCTION_PULSE_VERSION
                value["pulse"]["statusCode"] = status_code
                with self.assertRaisesRegex(
                    subject.BeaconVerificationError,
                    "statusCode is not zero/normal",
                ):
                    subject.verify_nist_pulse_response(
                        response=self.response(value),
                        trust_bundle=production_view,
                        expected_unix_milliseconds=self.milliseconds,
                    )

    def test_frozen_wire_spec_and_pem_byte_profiles_are_exact(self) -> None:
        trust_root = Path(__file__).resolve().parents[1] / "trust" / "nist"
        xsd = (trust_root / "spec" / "beacon-2.0.xsd").read_bytes()
        self.assertEqual(len(xsd), 19_033)
        self.assertEqual(
            hashlib.sha256(xsd).hexdigest(),
            "24c5b5b6508c0c33db2cda1902ea7f3b2009224895ba4e3fe275b7f4511675d6",
        )
        self.assertEqual(xsd.count(b"\r\n"), 356)
        self.assertNotIn(b"\n", xsd.replace(b"\r\n", b""))

        raw_server_pem = (
            trust_root / "source" / "engine-beacon-nist-gov.server.pem"
        ).read_bytes()
        normalized_pem = (
            trust_root / "certificates" / "engine-beacon-nist-gov.pem"
        ).read_bytes()
        self.assertEqual(len(raw_server_pem), 2_892)
        self.assertEqual(
            hashlib.sha256(raw_server_pem).hexdigest(),
            "acd33ba715a14c1d2c1601983c38cb7e671de151c3536fdf25097f28f9533229",
        )
        self.assertEqual(len(normalized_pem), 2_849)
        self.assertEqual(
            hashlib.sha256(normalized_pem).hexdigest(),
            "847bbfff2a1a842f07c2c5697e63a102d3cb7605559ec2da5cf8397ee0b5e9de",
        )
        self.assertEqual(
            raw_server_pem.replace(b"\r\n", b"\n") + b"\n",
            normalized_pem,
        )
        self.assertEqual(
            subject._pem_to_der(raw_server_pem),
            subject._pem_to_der(normalized_pem),
        )

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

    def test_machine_verifiable_trust_policy_fails_closed(self) -> None:
        mutations = {
            "revocation policy": (
                "revocationPolicy",
                "ONLINE_REVOCATION_ASSUMED",
                "revocation policy",
            ),
            "revocation truth flag": (
                "revocationChecked",
                True,
                "revocationChecked=false",
            ),
            "residual risk": (
                "revocationResidualRisk",
                "no residual risk",
                "residual-risk",
            ),
            "rotation": (
                "rotationPolicy",
                "ROTATE_ON_DEMAND",
                "rotation policy",
            ),
            "EKU": (
                "acceptedLeafExtendedKeyUsages",
                ["1.3.6.1.5.5.7.3.1"],
                "ExtendedKeyUsage policy",
            ),
            "second certificate ID": (
                "allowedCertificateIds",
                [self.certificate_id, "0" * 128],
                "exactly one",
            ),
        }
        for label, (field, replacement, error) in mutations.items():
            with self.subTest(label=label):
                path = self.write_bundle()
                manifest = json.loads(path.read_bytes())
                manifest["trustPolicy"][field] = replacement
                path.write_bytes(canonical_json_bytes(manifest))
                with self.assertRaisesRegex(subject.BeaconVerificationError, error):
                    subject.load_offline_trust_bundle(
                        path,
                        expected_time=self.pulse_time,
                        allow_fixture=True,
                    )

        path = self.write_bundle()
        manifest = json.loads(path.read_bytes())
        manifest["trustPolicy"]["allowedCertificateIds"] = ["0" * 128]
        path.write_bytes(canonical_json_bytes(manifest))
        with self.assertRaisesRegex(subject.BeaconVerificationError, "certificate map"):
            subject.load_offline_trust_bundle(
                path,
                expected_time=self.pulse_time,
                allow_fixture=True,
            )

    def test_exact_leaf_eku_and_end_entity_key_usage_are_enforced(self) -> None:
        leaf = subject.parse_certificate_der(self.der)
        self.assertEqual(
            leaf.extended_key_usages,
            subject.TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES,
        )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "ExtendedKeyUsage"):
            subject._verify_leaf_policy(
                replace(
                    leaf,
                    extended_key_usages=("1.3.6.1.5.5.7.3.1",),
                )
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "KeyUsage"):
            subject._verify_leaf_policy(replace(leaf, key_cert_sign=True))

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

    def test_tracked_chain_is_valid_at_blind_v1_target_and_requires_root(self) -> None:
        target_time = datetime(2026, 8, 21, 18, 0, 0, tzinfo=timezone.utc)
        with self.assertRaisesRegex(
            subject.BeaconVerificationError, "candidate.*not freeze-ready"
        ):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=target_time,
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
                expected_root_der_sha256=(subject.NIST_TRUST_ROOT_DER_SHA256,),
            )
        bundle = subject.load_offline_trust_bundle(
            TRACKED_TRUST_MANIFEST,
            expected_time=target_time,
            expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
            expected_root_der_sha256=(subject.NIST_TRUST_ROOT_DER_SHA256,),
            allow_candidate=True,
        )
        self.assertFalse(bundle.fixture_only)
        self.assertTrue(all(record.chain_verified for record in bundle.records.values()))
        for record in bundle.records.values():
            self.assertTrue(record.leaf.basic_constraints_present)
            self.assertFalse(record.leaf.is_ca)
            self.assertTrue(record.leaf.digital_signature)
            self.assertFalse(record.leaf.key_cert_sign)
            self.assertEqual(
                record.leaf.extended_key_usages,
                subject.TRUST_ACCEPTED_LEAF_EXTENDED_KEY_USAGES,
            )
            self.assertEqual(record.leaf.dns_names, ("engine.beacon.nist.gov",))
            for issuer in record.chain[1:]:
                self.assertTrue(issuer.basic_constraints_present)
                self.assertTrue(issuer.is_ca)
                self.assertTrue(issuer.key_cert_sign)
        with self.assertRaisesRegex(
            subject.BeaconVerificationError, "not valid at pulse time"
        ):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=datetime(2026, 9, 25, 18, tzinfo=timezone.utc),
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
                expected_root_der_sha256=(subject.NIST_TRUST_ROOT_DER_SHA256,),
                allow_candidate=True,
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "root pins"):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=target_time,
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
                allow_candidate=True,
            )
        with self.assertRaisesRegex(subject.BeaconVerificationError, "absent"):
            subject.load_offline_trust_bundle(
                TRACKED_TRUST_MANIFEST,
                expected_time=target_time,
                expected_manifest_sha256=TRACKED_TRUST_MANIFEST_SHA256,
                expected_root_der_sha256=("0" * 64,),
                allow_candidate=True,
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
