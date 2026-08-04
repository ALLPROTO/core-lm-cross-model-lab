from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch

import v3.tests.test_release_receipt as release_fixture
from v3.experiment_closeout import (
    ATTEMPT_TERMINAL_STATES,
    CLOSEOUT_RELEASE_PLAN,
    DEADLINES,
    EMPTY_INVENTORY_SHA256,
    EVIDENCE_PUBLICATION_DEADLINE,
    ExperimentCloseoutError,
    OBSERVATION_SCHEMA,
    OBSERVATION_SCOPE,
    PublicationBindings,
    canonical_json_bytes,
    create_late_publication_invalid,
    create_no_attempt_expired,
    sha256_bytes,
    validate_empty_result_root_observation,
    verify_experiment_closeout,
)
from v3.release_receipt import ReleaseReceiptError, verify_release_receipt


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
EVIDENCE_REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
EVIDENCE_HTML = f"https://github.com/{EVIDENCE_REPOSITORY}"
EVIDENCE_API = f"https://api.github.com/repos/{EVIDENCE_REPOSITORY}"
EVIDENCE_TAG = "corelm-crossmodel-livewiki-v3-evidence"
FIXTURE_CRYPTOGRAPHIC_VERIFIER = release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER


def canonical_line(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def seal(value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("contentSHA256", None)
    unsigned["contentSHA256"] = sha256_bytes(canonical_json_bytes(unsigned))
    return canonical_line(unsigned)


class ExperimentCloseoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.signing_identity = release_fixture._generate_test_key(
            self.root,
            "evidence-signing-key",
        )
        (
            _private_key,
            self.public_key,
            self.allowed_signers,
            self.fingerprint,
            self.public_key_sha256,
        ) = self.signing_identity
        self.trust_patch = patch.multiple(
            "v3.release_receipt",
            TRACKED_SSH_PUBLIC_KEY_PATH=self.public_key,
            TRACKED_SSH_ALLOWED_SIGNERS_PATH=self.allowed_signers,
        )
        self.trust_patch.start()
        commit_payload = (
            f"tree {release_fixture.TREE}\n"
            "author Unit Test <unit@example.invalid> 1785751200 +0000\n"
            "committer Unit Test <unit@example.invalid> 1785751200 +0000\n"
            "\npublication fixture\n"
        ).encode("ascii")
        self.bindings = PublicationBindings(
            design_registration_sha256="1" * 64,
            design_publication_receipt_sha256="2" * 64,
            snapshot_registration_sha256="3" * 64,
            snapshot_publication_receipt_sha256="4" * 64,
            closeout_source_commit=release_fixture._git_oid(
                "commit", commit_payload
            ),
            closeout_source_tree=release_fixture.TREE,
        )

    def tearDown(self) -> None:
        self.trust_patch.stop()
        self.temporary.cleanup()

    def observation(
        self,
        *,
        observed_at: str = "2026-09-04T18:00:00Z",
        created_at: str = "2026-09-04T18:00:01Z",
    ) -> bytes:
        return seal(
            {
                "schemaVersion": OBSERVATION_SCHEMA,
                "suiteId": SUITE_ID,
                "auditMethod": "NOFOLLOW_DIRECTORY_FD_EXACT_EMPTY_INVENTORY",
                "observedAt": observed_at,
                "observationCreatedAt": created_at,
                "hostEnvironmentSHA256": "5" * 64,
                "resultRootPathSHA256": "6" * 64,
                "rootDevice": 16777234,
                "rootInode": 987654321,
                "entryCount": 0,
                "emptyInventorySHA256": EMPTY_INVENTORY_SHA256,
                "claimScope": OBSERVATION_SCOPE,
                "globalAbsenceEstablished": False,
                "auditImplementationSHA256": "7" * 64,
                "auditReportSHA256": "8" * 64,
                "auditorIdentity": "explicit audited fixture observation",
            }
        )

    @staticmethod
    def late_headers(request_id: str) -> bytes:
        server_date = format_datetime(
            datetime(2026, 9, 7, 18, 1, tzinfo=timezone.utc),
            usegmt=True,
        )
        return (
            "HTTP/2 200\r\n"
            f"date: {server_date}\r\n"
            "content-type: application/json; charset=utf-8\r\n"
            f"x-github-api-version-selected: {release_fixture.GITHUB_API_VERSION}\r\n"
            f"x-github-request-id: {request_id}\r\n"
            "\r\n"
        ).encode("ascii")

    def evidence_fixture(
        self,
        name: str,
        *,
        published_at: str = EVIDENCE_PUBLICATION_DEADLINE,
    ):
        asset_root = self.root / name
        asset_root.mkdir()
        replacements = {
            "REPOSITORY": EVIDENCE_REPOSITORY,
            "HTML_BASE": EVIDENCE_HTML,
            "API_BASE": EVIDENCE_API,
            "TAG": EVIDENCE_TAG,
            "DEADLINE": EVIDENCE_PUBLICATION_DEADLINE,
            "PUBLISHED": published_at,
            "SERVER_DATE": "2026-09-07T18:01:00Z",
            "CAPTURED_AT": "2026-09-07T18:02:00Z",
            "RECEIPT_CREATED": "2026-09-07T18:03:00Z",
        }
        with patch.multiple(release_fixture, **replacements), patch.object(
            release_fixture,
            "_headers",
            new=self.late_headers,
        ):
            receipt, raw = release_fixture._build_fixture(
                asset_root,
                kind="evidence",
                signing_identity=self.signing_identity,
            )
        return asset_root, receipt, raw

    def test_no_attempt_is_public_closeout_not_attempt_outcome(self) -> None:
        observation = self.observation()
        raw = create_no_attempt_expired(
            publication_bindings=self.bindings,
            empty_result_root_observation_raw=observation,
            classified_at="2026-09-04T18:00:02Z",
        )
        closeout = json.loads(raw)
        self.assertEqual(closeout["classification"], "NO_ATTEMPT_EXPIRED")
        self.assertIsNone(closeout["attemptTerminalOutcome"])
        self.assertEqual(
            closeout["attemptTerminalStatesExcluded"],
            list(ATTEMPT_TERMINAL_STATES),
        )
        self.assertNotIn(
            closeout["classification"], closeout["attemptTerminalStatesExcluded"]
        )
        self.assertEqual(closeout["deadlines"], DEADLINES)
        self.assertEqual(closeout["closeoutReleasePlan"], CLOSEOUT_RELEASE_PLAN)
        self.assertIsNone(
            closeout["publicationBindings"]["evidenceReleaseReceiptSHA256"]
        )
        self.assertEqual(closeout["basis"]["claimScope"], OBSERVATION_SCOPE)
        self.assertIs(closeout["basis"]["globalAbsenceEstablished"], False)
        verified = verify_experiment_closeout(
            raw,
            expected_publication_bindings=self.bindings,
            empty_result_root_observation_raw=observation,
        )
        self.assertEqual(verified.classification, "NO_ATTEMPT_EXPIRED")
        self.assertEqual(verified.basis_sha256, sha256_bytes(observation))
        self.assertEqual(raw, canonical_line(closeout))

    def test_no_attempt_requires_post_deadline_limited_audited_observation(self) -> None:
        before = self.observation(
            observed_at="2026-09-04T17:59:59Z",
            created_at="2026-09-04T18:00:00Z",
        )
        with self.assertRaisesRegex(ExperimentCloseoutError, "predates"):
            create_no_attempt_expired(
                publication_bindings=self.bindings,
                empty_result_root_observation_raw=before,
                classified_at="2026-09-04T18:00:01Z",
            )

        overclaim = json.loads(self.observation())
        overclaim["claimScope"] = "ALL_HOSTS_AND_ALL_RESULT_ROOTS"
        overclaim["globalAbsenceEstablished"] = True
        with self.assertRaisesRegex(ExperimentCloseoutError, "scope"):
            validate_empty_result_root_observation(seal(overclaim))

        nonempty = json.loads(self.observation())
        nonempty["entryCount"] = 1
        with self.assertRaisesRegex(ExperimentCloseoutError, "inventory"):
            validate_empty_result_root_observation(seal(nonempty))

    def test_no_attempt_verifier_requires_exact_observation_and_bindings(self) -> None:
        observation = self.observation()
        raw = create_no_attempt_expired(
            publication_bindings=self.bindings,
            empty_result_root_observation_raw=observation,
            classified_at="2026-09-04T18:00:02Z",
        )
        with self.assertRaisesRegex(ExperimentCloseoutError, "requires only"):
            verify_experiment_closeout(
                raw,
                expected_publication_bindings=self.bindings,
            )
        wrong_bindings = PublicationBindings(
            design_registration_sha256="9" * 64,
            design_publication_receipt_sha256="2" * 64,
            snapshot_registration_sha256="3" * 64,
            snapshot_publication_receipt_sha256="4" * 64,
            closeout_source_commit="a" * 40,
            closeout_source_tree="b" * 40,
        )
        with self.assertRaisesRegex(ExperimentCloseoutError, "digest binding"):
            verify_experiment_closeout(
                raw,
                expected_publication_bindings=wrong_bindings,
                empty_result_root_observation_raw=observation,
            )

        tampered = json.loads(raw)
        tampered["attemptTerminalOutcome"] = "PASS"
        with self.assertRaisesRegex(ExperimentCloseoutError, "common boundary"):
            verify_experiment_closeout(
                seal(tampered),
                expected_publication_bindings=self.bindings,
                empty_result_root_observation_raw=observation,
            )

        tampered_plan = json.loads(raw)
        tampered_plan["closeoutReleasePlan"]["tag"] = "unsigned-alternate"
        with self.assertRaisesRegex(ExperimentCloseoutError, "common boundary"):
            verify_experiment_closeout(
                seal(tampered_plan),
                expected_publication_bindings=self.bindings,
                empty_result_root_observation_raw=observation,
            )

        tampered_source = json.loads(raw)
        tampered_source["publicationBindings"]["closeoutSourceCommit"] = "c" * 40
        with self.assertRaisesRegex(ExperimentCloseoutError, "digest binding"):
            verify_experiment_closeout(
                seal(tampered_source),
                expected_publication_bindings=self.bindings,
                empty_result_root_observation_raw=observation,
            )

    def test_late_receipt_at_deadline_is_fully_verified_and_classified(self) -> None:
        asset_root, receipt, receipt_raw = self.evidence_fixture("late-assets")
        raw = create_late_publication_invalid(
            publication_bindings=self.bindings,
            evidence_release_receipt_raw=receipt_raw,
            evidence_asset_root=asset_root,
            expected_commit=receipt["source"]["commit"],
            expected_tree=receipt["source"]["tree"],
            expected_key_fingerprint=self.fingerprint,
            expected_public_key_sha256=self.public_key_sha256,
            classified_at="2026-09-07T18:03:01Z",
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )
        closeout = json.loads(raw)
        self.assertEqual(
            closeout["classification"], "LATE_PUBLICATION_INVALID"
        )
        self.assertIsNone(closeout["attemptTerminalOutcome"])
        self.assertEqual(
            closeout["basis"]["latenessRelation"],
            "ATTESTED_AT_OR_AFTER_DEADLINE",
        )
        self.assertEqual(
            closeout["basis"]["publishedAt"], EVIDENCE_PUBLICATION_DEADLINE
        )
        self.assertEqual(
            closeout["basis"]["attestedAt"], EVIDENCE_PUBLICATION_DEADLINE
        )
        self.assertEqual(len(closeout["basis"]["requiredAssets"]), 4)
        self.assertEqual(
            closeout["publicationBindings"]["evidenceReleaseReceiptSHA256"],
            sha256_bytes(receipt_raw),
        )
        verified = verify_experiment_closeout(
            raw,
            expected_publication_bindings=self.bindings,
            evidence_release_receipt_raw=receipt_raw,
            evidence_asset_root=asset_root,
            expected_commit=receipt["source"]["commit"],
            expected_tree=receipt["source"]["tree"],
            expected_key_fingerprint=self.fingerprint,
            expected_public_key_sha256=self.public_key_sha256,
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )
        self.assertEqual(verified.classification, "LATE_PUBLICATION_INVALID")
        self.assertEqual(
            verified.evidence_release_receipt_sha256,
            sha256_bytes(receipt_raw),
        )

        with self.assertRaisesRegex(
            ExperimentCloseoutError, "frozen design lab source"
        ):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=receipt_raw,
                evidence_asset_root=asset_root,
                expected_commit="f" * 40,
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        # The ordinary verifier remains strict and still rejects the same late
        # original receipt against the registered deadline.
        with self.assertRaisesRegex(ReleaseReceiptError, "attestation failed binding replay"):
            verify_release_receipt(
                receipt_raw,
                asset_root,
                expected_repository=EVIDENCE_REPOSITORY,
                expected_kind="evidence",
                expected_tag=EVIDENCE_TAG,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_deadline=EVIDENCE_PUBLICATION_DEADLINE,
                expected_signature_type="SSH",
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_on_time_receipt_cannot_be_mislabeled_late(self) -> None:
        asset_root, receipt, raw = self.evidence_fixture(
            "on-time-assets",
            published_at="2026-09-07T17:59:59Z",
        )
        with self.assertRaisesRegex(ExperimentCloseoutError, "on time"):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=raw,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_late_receipt_requires_independent_cryptographic_verifier(self) -> None:
        asset_root, receipt, raw = self.evidence_fixture(
            "missing-cryptographic-verifier-assets"
        )
        with self.assertRaisesRegex(ExperimentCloseoutError, "ordinary integrity"):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=raw,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
            )

    def test_late_receipt_signature_assets_deadline_and_time_fail_closed(self) -> None:
        asset_root, receipt, raw = self.evidence_fixture("bad-late-assets")
        unsigned = copy.deepcopy(receipt)
        unsigned["signatureVerification"]["status"] = "UNVERIFIED"
        bad_signature = release_fixture._rehash(unsigned)
        with self.assertRaisesRegex(ExperimentCloseoutError, "ordinary integrity"):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=bad_signature,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        wrong_deadline = copy.deepcopy(receipt)
        wrong_deadline["release"]["deadline"] = "2026-09-08T18:00:00Z"
        with self.assertRaisesRegex(ExperimentCloseoutError, "deadline differs"):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=release_fixture._rehash(wrong_deadline),
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        with self.assertRaisesRegex(
            ExperimentCloseoutError, "predates release attestation"
        ):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=raw,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T17:59:59Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

        missing_asset = asset_root / receipt["requiredAssets"][0]["name"]
        missing_asset.unlink()
        with self.assertRaisesRegex(ExperimentCloseoutError, "ordinary integrity"):
            create_late_publication_invalid(
                publication_bindings=self.bindings,
                evidence_release_receipt_raw=raw,
                evidence_asset_root=asset_root,
                expected_commit=receipt["source"]["commit"],
                expected_tree=receipt["source"]["tree"],
                expected_key_fingerprint=self.fingerprint,
                expected_public_key_sha256=self.public_key_sha256,
                classified_at="2026-09-07T18:03:01Z",
                cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
            )

    def test_schema_tracks_both_distinct_closeout_branches(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "experiment-closeout.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(
            set(schema["properties"]["classification"]["enum"]),
            {"NO_ATTEMPT_EXPIRED", "LATE_PUBLICATION_INVALID"},
        )
        self.assertEqual(
            schema["properties"]["attemptTerminalStatesExcluded"]["const"],
            list(ATTEMPT_TERMINAL_STATES),
        )
        self.assertEqual(
            schema["$defs"]["deadlines"]["properties"],
            {
                key: {"const": value}
                for key, value in DEADLINES.items()
            },
        )
        self.assertEqual(len(schema["allOf"]), 2)

        def walk(value):
            yield value
            if isinstance(value, dict):
                for child in value.values():
                    yield from walk(child)
            elif isinstance(value, list):
                for child in value:
                    yield from walk(child)

        def resolve(reference: str):
            self.assertTrue(reference.startswith("#/"))
            value = schema
            for token in reference[2:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                self.assertIsInstance(value, dict)
                self.assertIn(token, value)
                value = value[token]
            return value

        for node in walk(schema):
            if not isinstance(node, dict):
                continue
            if "$ref" in node:
                resolve(node["$ref"])
            if node.get("type") == "object" and "properties" in node:
                self.assertIs(node.get("additionalProperties"), False)
                self.assertEqual(
                    set(node.get("required", [])), set(node["properties"])
                )

    def test_publication_bindings_hash_exact_bytes(self) -> None:
        frozen_design = canonical_line(
            {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-design-v1",
                "status": "PUBLIC_DESIGN_FROZEN",
                "labSource": {
                    "status": "FROZEN_BOUND",
                    "commit": "c" * 40,
                    "tree": "d" * 40,
                }
            }
        )
        bindings = PublicationBindings.from_exact_bytes(
            design_registration=frozen_design,
            design_publication_receipt=b"design receipt\n",
            snapshot_registration=b"snapshot\n",
            snapshot_publication_receipt=b"snapshot receipt\n",
            closeout_source_commit="c" * 40,
            closeout_source_tree="d" * 40,
        )
        self.assertEqual(
            bindings.design_registration_sha256,
            sha256_bytes(frozen_design),
        )
        self.assertEqual(bindings.closeout_source_commit, "c" * 40)
        self.assertEqual(bindings.closeout_source_tree, "d" * 40)
        with self.assertRaisesRegex(ExperimentCloseoutError, "supplied together"):
            PublicationBindings.from_exact_bytes(
                design_registration=b"design\n",
                design_publication_receipt=b"design receipt\n",
                snapshot_registration=b"snapshot\n",
                snapshot_publication_receipt=b"snapshot receipt\n",
                closeout_source_commit="a" * 40,
            )

        with self.assertRaisesRegex(
            ExperimentCloseoutError, "differs from frozen design lab source"
        ):
            PublicationBindings.from_exact_bytes(
                design_registration=frozen_design,
                design_publication_receipt=b"design receipt\n",
                snapshot_registration=b"snapshot\n",
                snapshot_publication_receipt=b"snapshot receipt\n",
                closeout_source_commit="a" * 40,
                closeout_source_tree="b" * 40,
            )
        derived = PublicationBindings.from_exact_bytes(
            design_registration=frozen_design,
            design_publication_receipt=b"design receipt\n",
            snapshot_registration=b"snapshot\n",
            snapshot_publication_receipt=b"snapshot receipt\n",
        )
        self.assertEqual(derived.closeout_source_commit, "c" * 40)
        self.assertEqual(derived.closeout_source_tree, "d" * 40)
        with self.assertRaisesRegex(ExperimentCloseoutError, "source binding is absent"):
            PublicationBindings.from_exact_bytes(
                design_registration=canonical_line(
                    {
                        "schemaVersion": "corelm-crossmodel-livewiki-v3-design-v1",
                        "status": "PUBLIC_DESIGN_FROZEN",
                        "labSource": {"status": "UNBOUND"},
                    }
                ),
                design_publication_receipt=b"design receipt\n",
                snapshot_registration=b"snapshot\n",
                snapshot_publication_receipt=b"snapshot receipt\n",
            )
        with self.assertRaisesRegex(ExperimentCloseoutError, "duplicate JSON key"):
            PublicationBindings.from_exact_bytes(
                design_registration=(
                    b'{"schemaVersion":"corelm-crossmodel-livewiki-v3-design-v1",'
                    b'"status":"PUBLIC_DESIGN_FROZEN","labSource":'
                    b'{"status":"FROZEN_BOUND","commit":"'
                    + b"c" * 40
                    + b'","tree":"'
                    + b"d" * 40
                    + b'"},"status":"PUBLIC_DESIGN_FROZEN"}\n'
                ),
                design_publication_receipt=b"design receipt\n",
                snapshot_registration=b"snapshot\n",
                snapshot_publication_receipt=b"snapshot receipt\n",
            )
        with self.assertRaises(ExperimentCloseoutError):
            PublicationBindings(
                design_registration_sha256="not-a-digest",
                design_publication_receipt_sha256="2" * 64,
                snapshot_registration_sha256="3" * 64,
                snapshot_publication_receipt_sha256="4" * 64,
                closeout_source_commit="a" * 40,
                closeout_source_tree="b" * 40,
            )

    def test_closeout_classification_must_precede_its_release_deadline(self) -> None:
        observation = self.observation()
        with self.assertRaisesRegex(ExperimentCloseoutError, "release deadline"):
            create_no_attempt_expired(
                publication_bindings=self.bindings,
                empty_result_root_observation_raw=observation,
                classified_at="2026-09-14T18:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
