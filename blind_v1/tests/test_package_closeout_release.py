from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import blind_v1.tests.test_experiment_closeout as closeout_fixture
from blind_v1.experiment_closeout import (
    PublicationBindings,
    canonical_json_bytes,
    _historical_collect_empty_result_root_observation as collect_empty_result_root_observation,
    _historical_create_late_publication_invalid as create_late_publication_invalid,
    _historical_create_no_attempt_expired as create_no_attempt_expired,
    sha256_bytes,
)
from blind_v1.package_closeout_release import (
    BASIS_NAME,
    CLOSEOUT_RELEASE_ASSETS,
    CloseoutPackageError,
    MANIFEST_NAME,
    REPORT_NAME,
    STATEMENT_NAME,
    _historical_package_closeout_release as package_closeout_release,
    verify_closeout_release_package,
    verify_published_closeout_release,
)
from blind_v1.release_receipt import REQUIRED_ASSET_ROLES, VerifiedReleaseReceipt


FIXTURE_CRYPTOGRAPHIC_VERIFIER = closeout_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER


def seal(value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("contentSHA256", None)
    unsigned["contentSHA256"] = sha256_bytes(canonical_json_bytes(unsigned))
    return canonical_json_bytes(unsigned) + b"\n"


class CloseoutPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bindings = PublicationBindings(
            reserved_attempt_id="20260821T180000Z-0123456789abcdef",
            design_registration_sha256="1" * 64,
            design_publication_receipt_sha256="2" * 64,
            snapshot_registration_sha256="3" * 64,
            snapshot_publication_receipt_sha256="4" * 64,
            reservation_publication_receipt_sha256="5" * 64,
            execution_reservation_sha256="6" * 64,
            reservation_release_manifest_sha256="7" * 64,
            closeout_source_commit="a" * 40,
            closeout_source_tree="b" * 40,
        )
        self.result_root = self.root / "observed-result-root"
        self.result_root.mkdir()
        self.host_environment = b'{"fixture":"exact host environment"}\n'
        timestamps = iter(
            ("2026-08-22T18:00:00Z", "2026-08-22T18:00:01Z")
        )
        self.observation, self.audit_report = collect_empty_result_root_observation(
            result_root=self.result_root,
            host_environment_raw=self.host_environment,
            auditor_identity="independent empty-root audit fixture",
            now=lambda: next(timestamps),
        )
        self.closeout = create_no_attempt_expired(
            publication_bindings=self.bindings,
            empty_result_root_observation_raw=self.observation,
            classified_at="2026-08-23T18:00:02Z",
        )
        self.closeout_path = self.root / "source-closeout.json"
        self.basis_path = self.root / "source-observation.json"
        self.host_environment_path = self.root / "host-environment.json"
        self.audit_report_path = self.root / "source-audit-report.json"
        self.closeout_path.write_bytes(self.closeout)
        self.basis_path.write_bytes(self.observation)
        self.host_environment_path.write_bytes(self.host_environment)
        self.audit_report_path.write_bytes(self.audit_report)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def package(self, name: str = "closeout-release"):
        return package_closeout_release(
            closeout_path=self.closeout_path,
            basis_path=self.basis_path,
            output_directory=self.root / name,
            publication_bindings=self.bindings,
            verified_at="2026-08-23T18:00:03Z",
            host_environment_path=self.host_environment_path,
            audit_report_path=self.audit_report_path,
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )

    def published_receipt_result(
        self,
        *,
        attested_at: str = "2026-08-23T18:00:04Z",
    ) -> VerifiedReleaseReceipt:
        return VerifiedReleaseReceipt(
            repository="ALLPROTO/core-lm-cross-model-lab",
            kind="closeout",
            tag="corelm-blind-crossmodel-v1-closeout",
            release_id=123,
            commit=self.bindings.closeout_source_commit,
            tree=self.bindings.closeout_source_tree,
            signature_type="SSH",
            key_fingerprint=(
                "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM"
            ),
            public_key_sha256=(
                "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274"
            ),
            published_at=attested_at,
            attested_at=attested_at,
            attestation_bundle_sha256="7" * 64,
            attestation_output_sha256="6" * 64,
            receipt_sha256="9" * 64,
            asset_sha256=tuple((name, "8" * 64) for _role, name in CLOSEOUT_RELEASE_ASSETS),
        )

    @staticmethod
    def published_receipt_raw(
        role_names=CLOSEOUT_RELEASE_ASSETS,
    ) -> bytes:
        return json.dumps(
            {
                "requiredAssets": [
                    {"role": role, "name": name} for role, name in role_names
                ]
            }
        ).encode("utf-8")

    def test_no_attempt_package_has_exact_release_roles_and_reverifies(self) -> None:
        result = self.package()
        release_root = self.root / "closeout-release"
        self.assertEqual(
            set(path.name for path in release_root.iterdir()),
            {STATEMENT_NAME, BASIS_NAME, REPORT_NAME, MANIFEST_NAME},
        )
        self.assertEqual(
            REQUIRED_ASSET_ROLES["closeout"],
            (
                "closeout-statement",
                "closeout-basis",
                "closeout-verifier-report",
                "sha256-manifest",
            ),
        )
        self.assertEqual(result.classification, "NO_ATTEMPT_EXPIRED")
        again = verify_closeout_release_package(
            release_root=release_root,
            publication_bindings=self.bindings,
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )
        self.assertEqual(result, again)
        manifest = json.loads((release_root / MANIFEST_NAME).read_bytes())
        self.assertEqual(
            [entry["role"] for entry in manifest["entries"]],
            list(REQUIRED_ASSET_ROLES["closeout"][:-1]),
        )
        basis = json.loads((release_root / BASIS_NAME).read_bytes())
        self.assertEqual(
            [item["role"] for item in basis["supportingDocuments"]],
            [
                "host-environment",
                "empty-result-root-audit-report",
                "empty-result-root-audit-implementation",
            ],
        )
        report = json.loads((release_root / REPORT_NAME).read_bytes())
        self.assertEqual(
            report["publicationBindings"]["reservedAttemptId"],
            self.bindings.reserved_attempt_id,
        )

    def test_report_manifest_basis_and_extra_file_tampering_fail_closed(self) -> None:
        self.package()
        release_root = self.root / "closeout-release"
        report_path = release_root / REPORT_NAME
        os.chmod(report_path, 0o644)
        report = json.loads(report_path.read_bytes())
        report["countsTowardScientificVerdict"] = True
        report_path.write_bytes(seal(report))
        with self.assertRaisesRegex(CloseoutPackageError, "report differs"):
            verify_closeout_release_package(
                release_root=release_root,
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        second = self.root / "second"
        self.package("second")
        extra = second / "unregistered.bin"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(CloseoutPackageError, "inventory differs"):
            verify_closeout_release_package(
                release_root=second,
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_wrong_basis_bindings_and_late_only_arguments_are_rejected(self) -> None:
        wrong_basis = self.root / "wrong-observation.json"
        mutated = json.loads(self.observation)
        mutated["rootInode"] += 1
        wrong_basis.write_bytes(seal(mutated))
        with self.assertRaisesRegex(CloseoutPackageError, "verification failed"):
            package_closeout_release(
                closeout_path=self.closeout_path,
                basis_path=wrong_basis,
                output_directory=self.root / "wrong-basis-output",
                publication_bindings=self.bindings,
                verified_at="2026-08-23T18:00:03Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )
        wrong_environment = self.root / "wrong-environment.json"
        wrong_environment.write_bytes(b'{"fixture":"different host"}\n')
        with self.assertRaisesRegex(CloseoutPackageError, "environment.*differ"):
            package_closeout_release(
                closeout_path=self.closeout_path,
                basis_path=self.basis_path,
                output_directory=self.root / "wrong-environment-output",
                publication_bindings=self.bindings,
                verified_at="2026-08-23T18:00:03Z",
                host_environment_path=wrong_environment,
                audit_report_path=self.audit_report_path,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )
        with self.assertRaisesRegex(CloseoutPackageError, "forbids late-evidence"):
            package_closeout_release(
                closeout_path=self.closeout_path,
                basis_path=self.basis_path,
                output_directory=self.root / "wrong-mode-output",
                publication_bindings=self.bindings,
                verified_at="2026-08-23T18:00:03Z",
                evidence_asset_root=self.root,
                expected_commit="1" * 40,
                expected_tree="2" * 40,
                expected_key_fingerprint="SHA256:" + "A" * 43,
                expected_public_key_sha256="9" * 64,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_symlinked_basis_is_rejected(self) -> None:
        symlink = self.root / "basis-link.json"
        symlink.symlink_to(self.basis_path)
        with self.assertRaisesRegex(CloseoutPackageError, "no-follow"):
            package_closeout_release(
                closeout_path=self.closeout_path,
                basis_path=symlink,
                output_directory=self.root / "symlink-output",
                publication_bindings=self.bindings,
                verified_at="2026-08-23T18:00:03Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        self.package("real-release")
        root_link = self.root / "release-link"
        root_link.symlink_to(self.root / "real-release", target_is_directory=True)
        with self.assertRaisesRegex(CloseoutPackageError, "no-follow directory"):
            verify_closeout_release_package(
                release_root=root_link,
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_late_package_requires_and_replays_exact_external_evidence_assets(self) -> None:
        fixture = closeout_fixture.ExperimentCloseoutTests()
        fixture.setUp()
        try:
            asset_root, receipt, receipt_raw = fixture.evidence_fixture(
                "package-late-assets"
            )
            late_bindings = fixture.bindings
            late_closeout = create_late_publication_invalid(
                publication_bindings=late_bindings,
                evidence_release_receipt_raw=receipt_raw,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=fixture.fingerprint,
                expected_public_key_sha256=fixture.public_key_sha256,
                classified_at="2026-08-26T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )
            late_path = self.root / "late-closeout.json"
            receipt_path = self.root / "late-receipt.json"
            late_path.write_bytes(late_closeout)
            receipt_path.write_bytes(receipt_raw)
            result = package_closeout_release(
                closeout_path=late_path,
                basis_path=receipt_path,
                output_directory=self.root / "late-closeout-release",
                publication_bindings=late_bindings,
                verified_at="2026-08-26T18:03:02Z",
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=fixture.fingerprint,
                expected_public_key_sha256=fixture.public_key_sha256,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )
            self.assertEqual(result.classification, "LATE_PUBLICATION_INVALID")
            missing = asset_root / receipt["requiredAssets"][0]["name"]
            missing.unlink()
            with self.assertRaisesRegex(CloseoutPackageError, "verification failed"):
                verify_closeout_release_package(
                    release_root=self.root / "late-closeout-release",
                    publication_bindings=late_bindings,
                    evidence_asset_root=asset_root,
                    expected_commit=receipt["source"]["commit"],
                    expected_tree=receipt["source"]["tree"],
                    expected_key_fingerprint=fixture.fingerprint,
                    expected_public_key_sha256=fixture.public_key_sha256,
                    cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
                )
        finally:
            fixture.tearDown()

    def test_published_verifier_fixes_source_release_identity_and_time(self) -> None:
        expected_package = self.package()
        receipt_result = self.published_receipt_result()
        with patch(
            "blind_v1.package_closeout_release.verify_release_receipt",
            return_value=receipt_result,
        ) as receipt_verifier:
            result = verify_published_closeout_release(
                release_root=self.root / "closeout-release",
                release_receipt_raw=self.published_receipt_raw(),
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )
        self.assertEqual(result.package, expected_package)
        self.assertEqual(result.release_receipt, receipt_result)
        receipt_verifier.assert_called_once_with(
            self.published_receipt_raw(),
            self.root / "closeout-release",
            expected_repository="ALLPROTO/core-lm-cross-model-lab",
            expected_kind="closeout",
            expected_tag="corelm-blind-crossmodel-v1-closeout",
            expected_commit="a" * 40,
            expected_tree="b" * 40,
            expected_deadline="2026-08-30T18:00:00Z",
            expected_signature_type="SSH",
            expected_key_fingerprint=(
                "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM"
            ),
            expected_public_key_sha256=(
                "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274"
            ),
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )

    def test_published_verifier_rejects_role_remap_and_predated_release(self) -> None:
        self.package()
        remapped = list(CLOSEOUT_RELEASE_ASSETS)
        remapped[0] = (remapped[0][0], remapped[1][1])
        remapped[1] = (remapped[1][0], remapped[0][1])
        with patch(
            "blind_v1.package_closeout_release.verify_release_receipt",
            return_value=self.published_receipt_result(),
        ), self.assertRaisesRegex(CloseoutPackageError, "role/name mapping"):
            verify_published_closeout_release(
                release_root=self.root / "closeout-release",
                release_receipt_raw=self.published_receipt_raw(tuple(remapped)),
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        with patch(
            "blind_v1.package_closeout_release.verify_release_receipt",
            return_value=self.published_receipt_result(
                attested_at="2026-08-23T18:00:02Z"
            ),
        ), self.assertRaisesRegex(CloseoutPackageError, "offline verification"):
            verify_published_closeout_release(
                release_root=self.root / "closeout-release",
                release_receipt_raw=self.published_receipt_raw(),
                publication_bindings=self.bindings,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_offline_report_cannot_predate_closeout_classification(self) -> None:
        with self.assertRaisesRegex(CloseoutPackageError, "predates classification"):
            package_closeout_release(
                closeout_path=self.closeout_path,
                basis_path=self.basis_path,
                output_directory=self.root / "predated-report",
                publication_bindings=self.bindings,
                verified_at="2026-08-23T18:00:01Z",
                host_environment_path=self.host_environment_path,
                audit_report_path=self.audit_report_path,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )


if __name__ == "__main__":
    unittest.main()
