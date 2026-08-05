from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from blind_v1.evidence import CONTAINER_SCHEMA, PAGE_TOKEN_SCHEMA, RAW_TOKEN_SCHEMA
from blind_v1.github_gate_receipt import (
    AUTHOR_GITHUB_LOGIN,
    AUTHOR_NAME,
    AUTHOR_ORCID,
    AUTHOR_VERIFICATION_MODE,
    EVIDENCE_BOUNDARY,
)
from blind_v1.protocol import (
    EXPECTED_CONTINUOUS_INTEGRATION,
    EXPECTED_DEVELOPMENT_CONTROLS,
    load_json_strict,
)


BLIND_V1_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = BLIND_V1_ROOT / "schemas"
SCHEMA_NAMES = {
    "attempt-reservation.schema.json",
    "attempt.schema.json",
    "ci-artifact-verification.schema.json",
    "container-evidence.schema.json",
    "closeout-basis.schema.json",
    "design.schema.json",
    "development-control-archive-manifest.schema.json",
    "development-control-report.schema.json",
    "evidence-release-manifest.schema.json",
    "execution-reservation-release-manifest.schema.json",
    "execution-reservation.schema.json",
    "experiment-closeout.schema.json",
    "freeze-manifest.schema.json",
    "github-gate-receipt.schema.json",
    "independent-model-replay.schema.json",
    "nist-trust-bundle.schema.json",
    "outcome.schema.json",
    "page-token-evidence.schema.json",
    "private-snapshot-manifest.schema.json",
    "prior-observations.schema.json",
    "raw-token-evidence.schema.json",
    "release-receipt.schema.json",
    "result.schema.json",
    "snapshot.schema.json",
    "zenodo-deposit-manifest.schema.json",
    "zenodo-deposit-receipt.schema.json",
}


def walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def resolve_local_ref(document: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise AssertionError(f"non-local schema reference: {reference}")
    value: Any = document
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise AssertionError(f"unresolved schema reference: {reference}")
        value = value[token]
    return value


class SchemaIntegrityTests(unittest.TestCase):
    def load_schemas(self) -> dict[str, dict[str, Any]]:
        observed = {path.name for path in SCHEMA_ROOT.glob("*.json")}
        self.assertEqual(observed, SCHEMA_NAMES)
        return {
            name: load_json_strict(SCHEMA_ROOT / name)
            for name in sorted(SCHEMA_NAMES)
        }

    def test_schemas_are_strict_closed_draft_2020_12_documents(self) -> None:
        schemas = self.load_schemas()
        identifiers: set[str] = set()
        for name, schema in schemas.items():
            Draft202012Validator.check_schema(schema)
            self.assertEqual(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertTrue(schema["$id"].endswith(f"/blind_v1/schemas/{name}"))
            self.assertNotIn(schema["$id"], identifiers)
            identifiers.add(schema["$id"])
            self.assertEqual(schema["type"], "object")
            self.assertIs(schema["additionalProperties"], False)
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            self.assertEqual(len(schema["required"]), len(set(schema["required"])))

            for node in walk(schema):
                if not isinstance(node, dict):
                    continue
                reference = node.get("$ref")
                if reference is not None:
                    resolve_local_ref(schema, reference)
                if node.get("type") == "object" and "properties" in node:
                    self.assertIs(node.get("additionalProperties"), False)
                    required = node.get("required", [])
                    self.assertEqual(len(required), len(set(required)))
                    self.assertTrue(set(required).issubset(node["properties"]))

    def test_nist_trust_schema_validates_candidate_and_exact_residual_risk(self) -> None:
        schema = self.load_schemas()["nist-trust-bundle.schema.json"]
        manifest = load_json_strict(BLIND_V1_ROOT / "trust" / "nist" / "manifest.json")
        Draft202012Validator(schema).validate(manifest)
        self.assertEqual(manifest["status"], "CANDIDATE_OFFLINE_TRUST_BUNDLE")
        self.assertIs(manifest["fixtureOnly"], False)
        policy = manifest["trustPolicy"]
        self.assertEqual(
            policy["revocationPolicy"],
            "EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK",
        )
        self.assertIs(policy["revocationChecked"], False)
        self.assertIn("can still be accepted", policy["revocationResidualRisk"])
        self.assertEqual(policy["rotationPolicy"], "NO_ROTATION_AFTER_FREEZE")
        self.assertEqual(
            policy["acceptedLeafExtendedKeyUsages"],
            ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
        )
        self.assertEqual(
            policy["allowedCertificateIds"], list(manifest["certificates"])
        )
        self.assertEqual(len(manifest["certificates"]), 1)

    def test_development_archive_schema_binds_exact_pud_rights_and_count(self) -> None:
        archive = self.load_schemas()[
            "development-control-archive-manifest.schema.json"
        ]
        self.assertEqual(
            archive["properties"]["artifactCount"],
            {"type": "integer", "const": 2088},
        )
        self.assertEqual(archive["properties"]["rights"], {"$ref": "#/$defs/rights"})
        rights = archive["$defs"]["rights"]
        expected = {
            "developmentCorpusLicense": "CC-BY-SA-3.0",
            "rightsStatus": "CONSISTENT_UPSTREAM_LICENSE_DECLARATION",
            "rightsScope": (
                "UPSTREAM_DECLARATION_ONLY_NO_OWNERSHIP_OR_CHAIN_OF_TITLE_CLAIM"
            ),
            "sourceRepository": "UniversalDependencies/UD_English-PUD",
            "sourceRevision": "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
            "sourceFile": "en_pud-ud-test.conllu",
            "corpusManifestPath": "inputs/development-corpus.draft.json",
            "licensePath": (
                "inputs/LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
            ),
            "readmePath": (
                "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md"
            ),
            "attributionPath": "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md",
            "sourceDerivedEvidenceLicense": "CC-BY-SA-3.0",
            "repositoryCodeLicense": "MIT",
            "noEndorsement": True,
        }
        self.assertEqual(set(rights["required"]), set(expected))
        self.assertEqual(
            {
                field: specification["const"]
                for field, specification in rights["properties"].items()
            },
            expected,
        )

    def test_github_gate_schema_requires_the_structural_evidence_boundary(self) -> None:
        schema = self.load_schemas()["github-gate-receipt.schema.json"]
        self.assertIn("evidenceBoundary", schema["required"])
        self.assertEqual(
            schema["properties"]["evidenceBoundary"],
            {"const": EVIDENCE_BOUNDARY},
        )

    def test_design_schema_covers_the_exact_tracked_registration_boundary(self) -> None:
        schemas = self.load_schemas()
        schema = schemas["design.schema.json"]
        registration = load_json_strict(BLIND_V1_ROOT / "design-registration.draft.json")
        self.assertEqual(set(registration), set(schema["required"]))
        self.assertIn(
            registration["schemaVersion"],
            schema["properties"]["schemaVersion"]["enum"],
        )
        execution = registration["execution"]
        self.assertIs(execution["pulseFetchAfterAttemptMarker"], True)
        self.assertEqual(execution["pulseFetchAuthority"], "supervisor-only")
        self.assertEqual(
            execution["inferenceChildNetwork"],
            "forbidden-from-process-creation",
        )
        self.assertEqual(
            execution["networkAfterPulseSeal"],
            "trusted-supervisor-python-socket-denial; OS-sandbox network denial for registered children",
        )
        self.assertEqual(
            execution["supervisorNetworkIsolationClaim"],
            "trusted-control-flow guard, not OS capability isolation",
        )
        self.assertNotIn("privateChildAuthorization", execution)
        self.assertEqual(
            execution["privateChildHandoff"],
            "one-use-anonymous-pipe-bound-to-live-parent-child-pids-new-process-group-and-canonical-private/result-paths",
        )
        self.assertEqual(
            execution["outerSupervisorIdentityClaim"],
            "none;the-handoff-does-not-authenticate-parent-implementation-or-prove-watchdog-behavior-and-a-custom-same-user-parent-can-reproduce-it",
        )
        self.assertEqual(
            execution["directPrivateExecution"],
            "forbidden-by-protocol;without-a-conforming-inherited-handoff-fails-closed",
        )
        replay = execution["independentModelReplay"]
        self.assertIs(replay["requiredForTerminalGateVerdict"], True)
        self.assertEqual(
            replay["implementation"], "blind_v1/independent_model_replay.py"
        )
        self.assertEqual(replay["producerModuleImports"], "forbidden")
        self.assertIs(replay["modelsSequential"], True)
        self.assertIs(replay["retokenizeFrozenCorpusBytes"], True)
        self.assertIs(replay["compareEveryPrediction"], True)
        self.assertEqual(replay["fixtureBackendScientificUse"], "forbidden")
        self.assertNotIn("networkAfterAttemptMarker", execution)
        self.assertNotIn("filesystemModelLoadAfterMarker", execution)
        self.assertIn("NIST-selected samples", registration["claim"])
        self.assertIn(
            "thirty-two selected creation revisions",
            registration["scientificBoundary"],
        )
        controls = registration["developmentControls"]
        self.assertEqual(
            set(controls), set(schema["$defs"]["developmentControls"]["required"])
        )
        self.assertIs(controls["syntheticInputsForbidden"], True)
        self.assertIs(controls["countsTowardScientificVerdict"], False)
        self.assertIs(controls["usedForCandidateSelectionOrTuning"], False)
        self.assertEqual(controls, EXPECTED_DEVELOPMENT_CONTROLS)
        self.assertEqual(
            schema["$defs"]["developmentControls"]["properties"]["dataset"],
            {"const": controls["dataset"]},
        )
        self.assertEqual(
            controls["dataset"]["datasetId"],
            "UniversalDependencies/UD_English-PUD:r2.18:test",
        )
        self.assertEqual(controls["dataset"]["manifestBytes"], 1982)
        self.assertEqual(
            controls["dataset"]["manifestSHA256"],
            "6b271476a157677580586b33932febcc83915a4f3cdb632fe227e2accb20a7a5",
        )
        gate = controls["realDataE2EFreezeGate"]
        gate_schema = schema["$defs"]["developmentControls"]["properties"][
            "realDataE2EFreezeGate"
        ]
        self.assertEqual(set(gate), set(gate_schema["required"]))
        self.assertIs(gate["serverTimestampedArchiveRequired"], True)
        self.assertEqual(
            gate["archiveRequiredAssetRoles"],
            [
                "development-control-report",
                "development-control-artifacts",
                "sha256-manifest",
            ],
        )
        ci = registration["continuousIntegration"]
        self.assertEqual(ci, EXPECTED_CONTINUOUS_INTEGRATION)
        self.assertEqual(ci["workflowFileBytes"], 14012)
        self.assertEqual(
            ci["workflowFileSHA256"],
            "6c0b54bc4c318a2b55069852e07ae3355686ffb49a72c3ca4542396cf5375e87",
        )
        workflow = (
            BLIND_V1_ROOT.parent / ci["workflowPath"]
        ).read_bytes()
        self.assertEqual(len(workflow), ci["workflowFileBytes"])
        self.assertEqual(hashlib.sha256(workflow).hexdigest(), ci["workflowFileSHA256"])
        exact_checkout = (
            "      - name: Check out the lab source\n"
            "        uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
            "        with:\n"
            "          ref: ${{ github.event_name == 'pull_request' && "
            "github.event.pull_request.head.sha || github.sha }}\n"
            "          persist-credentials: false\n"
        )
        workflow_text = workflow.decode("utf-8")
        self.assertEqual(workflow_text.count(exact_checkout), 2)
        self.assertEqual(workflow_text.count('      - "AGENTS.md"\n'), 2)
        self.assertEqual(
            workflow_text.count("sudo -n /usr/bin/unshare --net --"),
            1,
        )
        self.assertEqual(
            workflow_text.count(
                "-p '(version 1)(allow default)(deny network*)'"
            ),
            1,
        )
        self.assertEqual(
            workflow_text.count(
                "--network-isolation LINUX_UNSHARE_NETWORK_NAMESPACE"
            ),
            1,
        )
        self.assertEqual(
            workflow_text.count(
                "--network-isolation MACOS_SANDBOX_DENY_NETWORK"
            ),
            1,
        )
        normative_python_files = (
            "bootstrap_runtime.sh",
            "create_runtime_manifest.py",
            "development_runtime.py",
            "preflight.py",
            "runner.py",
        )
        for name in normative_python_files:
            source = (BLIND_V1_ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("3.12.13", source)
            self.assertNotIn("(3, 12, 13)", source)
        bootstrap_source = (BLIND_V1_ROOT / "bootstrap_runtime.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"$PYTHON_BIN" -I -B -m venv --copies "$STAGING"',
            bootstrap_source,
        )
        self.assertIn("target_status.st_uid in allowed_owners", bootstrap_source)
        self.assertIn("not target_status.st_mode & 0o022", bootstrap_source)
        self.assertIn('expected_version="3.12.10"', bootstrap_source)
        self.assertIn(
            "Linux base Python has an unsafe owner/mode chain", bootstrap_source
        )
        self.assertEqual(ci["verificationMode"], AUTHOR_VERIFICATION_MODE)
        self.assertEqual(ci["authorName"], AUTHOR_NAME)
        self.assertEqual(ci["authorORCID"], AUTHOR_ORCID)
        self.assertEqual(ci["authorGitHubLogin"], AUTHOR_GITHUB_LOGIN)
        self.assertIs(ci["independentHumanReviewRequired"], False)
        self.assertIs(ci["independentHumanReviewPerformed"], False)
        self.assertIn("No independent human review was performed", ci["authorDeclaration"])
        self.assertIn("No independent human review", ci["claimBoundary"])
        self.assertEqual(
            [job["machine"] for job in ci["requiredJobs"]],
            ["x86_64", "arm64"],
        )

    def test_design_lifecycle_branches_fail_closed_and_snapshot_plan_is_exact(self) -> None:
        schemas = self.load_schemas()
        design = schemas["design.schema.json"]
        branches = {
            branch["if"]["properties"]["status"]["const"]: branch["then"][
                "properties"
            ]
            for branch in design["allOf"]
        }
        draft = branches["DRAFT_NOT_PREREGISTERED"]
        self.assertEqual(
            draft["schemaVersion"]["const"],
            "corelm-blind-crossmodel-v1-design-draft-v1",
        )
        self.assertIs(draft["readyToFreeze"]["const"], False)
        self.assertIs(draft["countsTowardScientificVerdict"]["const"], False)
        self.assertEqual(
            draft["labSource"]["properties"]["status"]["const"],
            "UNBOUND_DRAFT",
        )
        for field in ("commit", "tree", "freezeManifestSHA256"):
            self.assertEqual(
                draft["labSource"]["properties"][field]["type"], "null"
            )
        self.assertEqual(draft["freezeBlockers"]["minItems"], 1)

        frozen = branches["PUBLIC_DESIGN_FROZEN"]
        self.assertEqual(
            frozen["schemaVersion"]["const"],
            "corelm-blind-crossmodel-v1-design-v1",
        )
        self.assertIs(frozen["readyToFreeze"]["const"], True)
        self.assertIs(frozen["countsTowardScientificVerdict"]["const"], False)
        self.assertEqual(
            frozen["labSource"]["properties"]["status"]["const"],
            "FROZEN_BOUND",
        )
        self.assertEqual(
            frozen["runtime"]["properties"]["status"]["const"],
            "FROZEN_BOUND",
        )
        self.assertEqual(
            draft["beacon"]["properties"]["trustBundleStatus"]["const"],
            "CANDIDATE_OFFLINE_TRUST_BUNDLE",
        )
        self.assertEqual(
            draft["beacon"]["properties"]["offlineTrustBundleSHA256"][
                "const"
            ],
            "cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706",
        )
        self.assertEqual(
            frozen["beacon"]["properties"]["trustBundleStatus"]["const"],
            "FROZEN_OFFLINE_TRUST_BUNDLE",
        )
        self.assertEqual(
            frozen["beacon"]["properties"]["offlineTrustBundleSHA256"][
                "const"
            ],
            "5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a",
        )
        self.assertEqual(frozen["freezeBlockers"]["maxItems"], 0)

        release_plan = design["$defs"]["releasePlan"]
        self.assertIn("sourcePolicy", release_plan["required"])
        self.assertEqual(
            release_plan["properties"]["sourcePolicy"]["const"],
            "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        )

        execution = design["$defs"]["execution"]
        self.assertEqual(
            execution["properties"]["weightLoadOrder"]["const"],
            "verified-owned-bytes->deserialize-owned-state->destroy-weight-bytes->construct-fp32-model->strict-copy",
        )
        self.assertEqual(
            execution["properties"]["maximumSimultaneousWeightPayloadCopies"][
                "const"
            ],
            2,
        )
        self.assertIs(
            execution["properties"]["weightBytesDestroyedBeforeModelConstruction"][
                "const"
            ],
            True,
        )
        self.assertEqual(
            execution["properties"]["staticWorstCaseWeightStorageOverlapBytes"][
                "const"
            ],
            2_894_634_160,
        )
        self.assertIn("oneShotNotBefore", execution["required"])
        self.assertIn("markerNoLaterThan", execution["required"])
        self.assertEqual(
            execution["properties"]["oneShotNotBefore"]["const"],
            "2026-08-21T18:00:00Z",
        )
        self.assertEqual(
            execution["properties"]["markerNoLaterThan"]["const"],
            "2026-08-21T18:15:00Z",
        )
        self.assertEqual(
            execution["properties"]["hardDeadline"]["const"],
            "2026-08-22T18:00:00Z",
        )
        self.assertIn("independentModelReplay", execution["required"])
        replay = design["$defs"]["independentModelReplay"]
        self.assertEqual(
            replay["properties"]["comparisons"]["const"],
            [
                "first512TokenIds",
                "targetTokenId",
                "baselineLossF32Bits",
                "candidateLossF32Bits",
                "baselineTop1TokenId",
                "candidateTop1TokenId",
            ],
        )
        self.assertEqual(
            replay["properties"]["fixtureBackendScientificUse"]["const"],
            "forbidden",
        )
        state = design["$defs"]["oneShotStateMachine"]
        self.assertIn(
            "attemptReservationBeforeMarker", state["required"]
        )
        self.assertIn(
            "attemptMarkerBeforeSelectionOrSelectedDataOpen", state["required"]
        )
        snapshot = schemas["snapshot.schema.json"]
        self.assertEqual(
            snapshot["properties"]["status"]["const"],
            "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION",
        )
        self.assertEqual(
            snapshot["properties"]["designPublicationReceiptSHA256"]["$ref"],
            "#/$defs/sha256",
        )
        release_plan = snapshot["properties"]["snapshotReleasePlan"]
        self.assertEqual(
            release_plan["properties"]["tag"]["const"],
            "corelm-blind-crossmodel-v1-snapshot",
        )
        self.assertEqual(
            release_plan["properties"]["publishNoLaterThan"]["const"],
            "2026-08-20T18:00:00Z",
        )
        for field in (
            "serverTimestampRequired",
            "immutableReleaseRequired",
            "signedAnnotatedTagRequired",
        ):
            self.assertIs(release_plan["properties"][field]["const"], True)
        self.assertTrue(
            {
                "modelAssetSourceManifestSHA256",
                "fullAssetReceiptSHA256",
            }.issubset(snapshot["required"])
        )
        for self_referential_field in (
            "designRelease",
            "snapshotRelease",
            "evidenceRelease",
        ):
            self.assertNotIn(self_referential_field, snapshot["properties"])
        public_reservation = schemas["execution-reservation.schema.json"]
        self.assertTrue(
            {"attemptId", "markerNoLaterThan"}.issubset(
                public_reservation["required"]
            )
        )
        self.assertEqual(
            public_reservation["properties"]["attemptId"]["pattern"],
            "^20260821T180000Z-[0-9a-f]{16}$",
        )
        self.assertEqual(
            public_reservation["properties"]["markerNoLaterThan"]["const"],
            "2026-08-21T18:15:00Z",
        )
        self.assertIn("publicAttemptIdDerivation", state["required"])
        self.assertEqual(
            state["properties"]["publicAttemptIdDerivation"]["const"],
            "20260821T180000Z- + first16hex(SHA-256(canonical reservation "
            "JSON before attemptId and reservationContentSHA256))",
        )

    def test_attempt_and_outcome_commit_the_normative_integrity_fields(self) -> None:
        schemas = self.load_schemas()
        reservation = schemas["attempt-reservation.schema.json"]
        self.assertEqual(
            reservation["properties"]["status"]["const"], "RESERVED"
        )
        self.assertIs(
            reservation["properties"]["countsTowardScientificVerdict"]["const"],
            False,
        )
        self.assertIs(
            reservation["properties"]["retryPermitted"]["const"], False
        )
        attempt_required = set(schemas["attempt.schema.json"]["required"])
        reservation_required = set(
            schemas["attempt-reservation.schema.json"]["required"]
        )
        commitment_fields = {
            "designSHA256",
            "snapshotRegistrationSHA256",
            "designPublicationReceiptSHA256",
            "snapshotPublicationReceiptSHA256",
            "runtimeManifestSHA256",
            "modelAssetSourceManifestSHA256",
            "fullAssetReceiptSHA256",
            "githubGateReceiptSHA256",
            "privateSnapshotManifestSHA256",
            "corpusManifestSHA256",
            "codecCommit",
            "codecTree",
            "labCommit",
            "labTree",
            "targetPulseTimestamp",
        }
        self.assertTrue(
            (commitment_fields | {"markerContentSHA256"}).issubset(
                attempt_required
            )
        )
        self.assertTrue(
            (commitment_fields | {"reservationContentSHA256"}).issubset(
                reservation_required
            )
        )

    def test_private_snapshot_schema_binds_every_pre_attempt_input_class(self) -> None:
        schemas = self.load_schemas()
        schema = schemas["private-snapshot-manifest.schema.json"]
        self.assertTrue(
            {
                "designSHA256",
                "snapshotRegistrationSHA256",
                "reservationPublicationReceiptSHA256",
                "runtimeManifestSHA256",
                "modelAssetSourceManifestSHA256",
                "fullAssetReceiptSHA256",
                "corpusManifestSHA256",
                "freezeManifestSHA256",
                "githubGateReceiptSHA256",
                "transportCABundleSHA256",
                "offlineTrustBundleSHA256",
                "cosignBinarySHA256",
                "labCommit",
                "labTree",
                "codecCommit",
                "codecTree",
                "labSourceManifestSHA256",
                "codecSourceManifestSHA256",
                "files",
                "contentSHA256",
            }.issubset(schema["required"])
        )
        entry = schema["$defs"]["file"]
        self.assertEqual(
            set(entry["required"]), {"path", "bytes", "sha256", "role"}
        )
        roles = set(schema["$defs"]["role"]["enum"])
        self.assertTrue(
            {
                "lab-source",
                "lab-source-manifest",
                "codec-source",
                "codec-source-manifest",
                "model-asset",
                "eligible-corpus-record",
                "development-control-artifact",
                "development-control-archive-asset",
                "pinned-cosign-binary",
                "reservation-publication-receipt",
                "reservation-release-asset",
            }.issubset(
                roles
            )
        )
        files = schema["properties"]["files"]
        self.assertEqual(len(files["allOf"]), 6)
        self.assertTrue(
            any(
                rule.get("minContains") == 3
                and rule.get("maxContains") == 3
                and rule["contains"]["properties"]["role"].get("const")
                == "reservation-release-asset"
                for rule in files["allOf"]
            )
        )

    def test_state_result_and_publication_schema_identities_are_consistent(self) -> None:
        schemas = self.load_schemas()
        self.assertEqual(
            schemas["attempt.schema.json"]["properties"]["status"]["const"],
            "STARTED",
        )
        attempt_pattern = "^20260821T180000Z-[0-9a-f]{16}$"
        for name in (
            "attempt-reservation.schema.json",
            "attempt.schema.json",
            "outcome.schema.json",
            "page-token-evidence.schema.json",
            "raw-token-evidence.schema.json",
            "container-evidence.schema.json",
            "result.schema.json",
            "independent-model-replay.schema.json",
            "evidence-release-manifest.schema.json",
        ):
            self.assertEqual(
                schemas[name]["properties"]["attemptId"]["pattern"],
                attempt_pattern,
            )
        outcome_required = set(schemas["outcome.schema.json"]["required"])
        self.assertTrue(
            {
                "terminalState",
                "attemptMarkerFileSHA256",
                "resultSHA256",
                "evidenceManifestSHA256",
                "independentVerifierSHA256",
                "completedAt",
            }.issubset(outcome_required)
        )
        result_required = set(schemas["result.schema.json"]["required"])
        self.assertTrue(
            {
                "selectionSHA256",
                "pulseVerificationSHA256",
                "cells",
                "modelAggregates",
                "suitePass",
            }.issubset(result_required)
        )
        receipt_required = set(schemas["release-receipt.schema.json"]["required"])
        self.assertTrue(
            {
                "kind",
                "tag",
                "release",
                "source",
                "annotatedTag",
                "signatureVerification",
                "requiredAssets",
                "githubAPIResponses",
                "contentSHA256",
            }.issubset(receipt_required)
        )

    def test_evidence_record_field_sets_match_the_protocol_contract(self) -> None:
        schemas = self.load_schemas()
        self.assertEqual(
            schemas["raw-token-evidence.schema.json"]["properties"][
                "schemaVersion"
            ]["const"],
            RAW_TOKEN_SCHEMA,
        )
        self.assertEqual(
            schemas["page-token-evidence.schema.json"]["properties"][
                "schemaVersion"
            ]["const"],
            PAGE_TOKEN_SCHEMA,
        )
        self.assertEqual(
            schemas["container-evidence.schema.json"]["properties"][
                "schemaVersion"
            ]["const"],
            CONTAINER_SCHEMA,
        )
        raw_required = set(schemas["raw-token-evidence.schema.json"]["required"])
        self.assertEqual(
            raw_required,
            {
                "schemaVersion",
                "suiteId",
                "attemptId",
                "modelKey",
                "corpusProject",
                "pageRevisionId",
                "pageSelectionIndex",
                "predictionIndex",
                "targetTokenId",
                "baselineLossF32Bits",
                "candidateLossF32Bits",
                "baselineTop1TokenId",
                "candidateTop1TokenId",
            },
        )
        for field in ("baselineLossF32Bits", "candidateLossF32Bits"):
            reference = schemas["raw-token-evidence.schema.json"]["properties"][field][
                "$ref"
            ]
            definition = resolve_local_ref(
                schemas["raw-token-evidence.schema.json"], reference
            )
            self.assertEqual(definition["pattern"], "^[0-9a-f]{8}$")

        container_required = set(
            schemas["container-evidence.schema.json"]["required"]
        )
        self.assertEqual(
            container_required,
            {
                "schemaVersion",
                "suiteId",
                "attemptId",
                "modelKey",
                "corpusProject",
                "pageRevisionId",
                "pageSelectionIndex",
                "layerIndex",
                "denseBF16Bytes",
                "containerBytes",
                "containerSHA256",
                "relativePath",
                "structuralReplay",
            },
        )
        page_token_required = set(
            schemas["page-token-evidence.schema.json"]["required"]
        )
        self.assertEqual(
            page_token_required,
            {
                "schemaVersion",
                "suiteId",
                "attemptId",
                "modelKey",
                "corpusProject",
                "pageRevisionId",
                "pageSelectionIndex",
                "vocabSize",
                "first512TokenIds",
                "first512StreamSHA256",
            },
        )
        token_array = schemas["page-token-evidence.schema.json"]["properties"][
            "first512TokenIds"
        ]
        self.assertEqual(token_array["minItems"], 512)
        self.assertEqual(token_array["maxItems"], 512)
        for name in (
            "raw-token-evidence.schema.json",
            "container-evidence.schema.json",
            "page-token-evidence.schema.json",
        ):
            self.assertEqual(
                schemas[name]["properties"]["pageSelectionIndex"]["maximum"],
                15,
            )
        self.assertIs(
            schemas["container-evidence.schema.json"]["properties"][
                "structuralReplay"
            ]["const"],
            True,
        )
        self.assertIs(
            schemas["result.schema.json"]["$defs"]["cell"]["properties"][
                "structuralReplay"
            ]["const"],
            True,
        )


if __name__ == "__main__":
    unittest.main()
