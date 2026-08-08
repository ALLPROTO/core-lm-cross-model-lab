from __future__ import annotations

import unittest
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from blind_v1.evidence import (
    PAGE_TOKEN_SCHEMA,
    EvidenceError,
    canonical_json_line,
    float32_to_bits,
    token_id_stream,
)
from blind_v1.create_sbom import build_sbom
from blind_v1.protocol import canonical_json_bytes
from blind_v1.reproducibility import with_content_digest
from blind_v1.state_machine import (
    RESERVATION_FILENAME,
    _historical_create_attempt_marker as create_attempt_marker,
)
from blind_v1.verify_evidence import (
    PRIVATE_SNAPSHOT_MANIFEST_PATH,
    canonical_scientific_result,
    load_canonical_line,
    validate_frozen_design,
    verify_manifested_source_tree,
    verify_external_attempt_time_anchor,
    verify_attempt_reservation,
    verify_execution_reservation_publication_provenance,
    verify_private_snapshot_manifest,
    verify_publication_inputs,
    verify_registered_ci_workflow_bytes,
    verify_runtime_asset_sbom_bindings,
    verify_worker_bindings,
)


PRIVATE_ROLES = {
    "asset-source-manifest",
    "codec-source-manifest",
    "codec-source",
    "corpus-manifest",
    "design-publication-receipt",
    "design-release-asset",
    "development-control-archive-asset",
    "development-control-archive-receipt",
    "development-control-artifact",
    "development-control-report",
    "eligible-corpus-record",
    "eligible-ledger",
    "freeze-manifest",
    "frozen-design",
    "frozen-snapshot-registration",
    "full-asset-manifest",
    "github-gate-receipt",
    "lab-source",
    "lab-source-manifest",
    "model-asset",
    "nist-certificate-chain",
    "nist-trust-manifest",
    "pinned-cosign-binary",
    "release-signing-public-key",
    "reservation-publication-receipt",
    "reservation-release-asset",
    "runtime-manifest",
    "snapshot-publication-receipt",
    "snapshot-release-asset",
    "transport-ca-bundle",
}

RESERVATION_ASSET_PATHS = (
    "publication/reservation-assets/execution-reservation.json",
    "publication/reservation-assets/snapshot-publication-receipt.json",
    "publication/reservation-assets/sha256-manifest.json",
)


def private_file_entries(
    *, omit_roles: set[str] | None = None
) -> list[dict[str, object]]:
    omitted = omit_roles or set()
    pairs: list[tuple[str, str]] = []
    for role in sorted(PRIVATE_ROLES - omitted):
        if role == "pinned-cosign-binary":
            paths = ("tools/cosign",)
        elif role == "reservation-publication-receipt":
            paths = ("publication/reservation-receipt.json",)
        elif role == "reservation-release-asset":
            paths = RESERVATION_ASSET_PATHS
        else:
            paths = (f"sealed/{len(pairs):02d}-{role}.bin",)
        pairs.extend((path, role) for path in paths)
    return sorted(
        [
            {
                "path": path,
                "bytes": 1,
                "sha256": f"{index + 1:064x}",
                "role": role,
            }
            for index, (path, role) in enumerate(pairs)
        ],
        key=lambda item: str(item["path"]).encode(),
    )


def frozen_design_fixture() -> dict[str, object]:
    project_root = Path(__file__).resolve().parents[2]
    design = json.loads((project_root / "blind_v1/design-registration.draft.json").read_text())
    design["schemaVersion"] = "corelm-blind-crossmodel-v1-design-v1"
    design["status"] = "PUBLIC_DESIGN_FROZEN"
    design["readyToFreeze"] = True
    design["freezeBlockers"] = []
    design["labSource"].update(
        status="FROZEN_BOUND",
        commit="1" * 40,
        tree="2" * 40,
        freezeManifestSHA256="3" * 64,
    )
    design["runtime"].update(
        status="FROZEN_BOUND",
        runtimeManifestSHA256="4" * 64,
    )
    design["developmentControls"]["realDataE2EFreezeGate"].update(
        status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
        executionId="development-execution-20260814T100000Z-0123456789abcdef",
        archiveReceiptSHA256="7" * 64,
        archivePublishedAt="2026-08-08T10:05:00Z",
        archiveAttestedAt="2026-08-08T10:05:01Z",
        releaseAttestationBundleSHA256="b" * 64,
        releaseAttestationOutputSHA256="c" * 64,
        reportSHA256="8" * 64,
        artifactSetSHA256="9" * 64,
        controlConfigurationSHA256="a" * 64,
        completedAt="2026-08-08T10:00:00Z",
    )
    design["beacon"].update(
        trustBundleStatus="FROZEN_OFFLINE_TRUST_BUNDLE",
        transportCABundleSHA256="5" * 64,
        offlineTrustBundleSHA256=design["beacon"][
            "frozenOfflineTrustBundleSHA256"
        ],
    )
    return design


class IndependentVerifierContractTests(unittest.TestCase):
    def test_publication_inputs_share_one_explicit_cryptographic_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            design_path = root / "design.json"
            snapshot_path = root / "snapshot.json"
            design = {
                "designRelease": {
                    "tag": "design-tag",
                    "publishNoLaterThan": "2026-08-09T00:00:00Z",
                    "signingKeyFingerprint": "design-fingerprint",
                    "signingPublicKeySHA256": "1" * 64,
                },
                "snapshotRelease": {
                    "tag": "snapshot-tag",
                    "publishNoLaterThan": "2026-08-20T18:00:00Z",
                    "signingKeyFingerprint": "snapshot-fingerprint",
                    "signingPublicKeySHA256": "1" * 64,
                },
                "reservationRelease": {
                    "tag": "reservation-tag",
                    "publishNotBefore": "2026-08-20T18:00:00Z",
                    "publishNoLaterThan": "2026-08-21T17:45:00Z",
                    "signingKeyFingerprint": "reservation-fingerprint",
                    "signingPublicKeySHA256": "1" * 64,
                },
                "beacon": {
                    "targetTimestamp": "2026-08-21T18:00:00.000Z",
                },
            }
            design_path.write_bytes(canonical_json_bytes(design) + b"\n")
            snapshot_path.write_bytes(
                canonical_json_bytes(
                    {"designPublicationReceiptSHA256": "a" * 64}
                )
                + b"\n"
            )
            marker = {
                "attemptId": "20260821T180000Z-0123456789abcdef",
                "designPublicationReceiptSHA256": "a" * 64,
                "snapshotPublicationReceiptSHA256": "b" * 64,
            }
            reservation_receipt_raw = b"unit reservation receipt\n"
            reservation_receipt_digest = hashlib.sha256(
                reservation_receipt_raw
            ).hexdigest()
            private_manifest = {
                "reservationPublicationReceiptSHA256": (
                    reservation_receipt_digest
                ),
            }
            verifier = object()
            publications = (
                SimpleNamespace(receipt_sha256="a" * 64),
                SimpleNamespace(receipt_sha256="b" * 64),
                SimpleNamespace(
                    receipt_sha256=reservation_receipt_digest,
                    source_commit="1" * 40,
                    source_tree="2" * 40,
                    role_sha256=(
                        ("execution-reservation", "d" * 64),
                        ("sha256-manifest", "e" * 64),
                        ("snapshot-publication-receipt", "b" * 64),
                    ),
                    receipt=SimpleNamespace(
                        kind="reservation",
                        tag="reservation-tag",
                        receipt_sha256=reservation_receipt_digest,
                        published_at="2026-08-20T18:05:00Z",
                        attested_at="2026-08-20T18:06:00Z",
                    ),
                ),
            )
            with mock.patch(
                "blind_v1.verify_evidence.verify_publication",
                side_effect=publications,
            ) as publication, mock.patch(
                "blind_v1.verify_evidence.require_frozen_lab_publication_source"
            ) as source_check, mock.patch(
                "blind_v1.verify_evidence.verify_design_release_package",
                return_value=SimpleNamespace(ci_artifacts=()),
            ), mock.patch(
                "blind_v1.verify_evidence.verify_execution_reservation_package",
                return_value={
                    "status": "VERIFIED_EXECUTION_RESERVATION_RELEASE_ASSETS",
                    "reservationFileSHA256": "d" * 64,
                    "snapshotReceiptFileSHA256": "b" * 64,
                    "manifestFileSHA256": "e" * 64,
                    "reservedAt": "2026-08-20T18:04:00Z",
                    "attemptId": "20260821T180000Z-0123456789abcdef",
                    "markerNoLaterThan": "2026-08-21T18:15:00Z",
                    "networkUsed": False,
                    "modelInferenceUsed": False,
                    "selectionDerived": False,
                },
            ) as reservation_package, mock.patch(
                "blind_v1.verify_evidence._private_committed_file",
                return_value=reservation_receipt_raw,
            ):
                result = verify_publication_inputs(
                    root,
                    marker=marker,
                    private_manifest=private_manifest,
                    design=design,
                    design_path=design_path,
                    snapshot_path=snapshot_path,
                    cryptographic_attestation_verifier=verifier,
                )
                with self.assertRaisesRegex(EvidenceError, "digest binding"):
                    verify_publication_inputs(
                        root,
                        marker=marker,
                        private_manifest={
                            "reservationPublicationReceiptSHA256": "0" * 64
                        },
                        design=design,
                        design_path=design_path,
                        snapshot_path=snapshot_path,
                        cryptographic_attestation_verifier=verifier,
                    )
            self.assertEqual(publication.call_count, 3)
            for call in publication.call_args_list:
                self.assertIs(
                    call.kwargs["cryptographic_attestation_verifier"],
                    verifier,
                )
            self.assertIn(
                "development-control-report",
                publication.call_args_list[0].kwargs["expected_role_paths"],
            )
            self.assertEqual(publication.call_args_list[2].kwargs["kind"], "reservation")
            self.assertEqual(
                set(publication.call_args_list[2].kwargs["expected_role_paths"]),
                {
                    "execution-reservation",
                    "snapshot-publication-receipt",
                    "sha256-manifest",
                },
            )
            reservation_package.assert_called_once_with(
                root / "publication" / "reservation-assets",
                design_raw=design_path.read_bytes(),
                snapshot_raw=snapshot_path.read_bytes(),
            )
            self.assertEqual(result[2], reservation_receipt_digest)
            self.assertEqual(
                result[4]["status"],
                "VERIFIED_PUBLIC_EXECUTION_RESERVATION_PROVENANCE",
            )
            self.assertEqual(
                [call.kwargs["kind"] for call in source_check.call_args_list],
                ["design", "snapshot", "reservation"],
            )

    def test_execution_reservation_publication_uses_half_open_pre_pulse_window(
        self,
    ) -> None:
        design = {
            "reservationRelease": {
                "tag": "reservation-tag",
                "publishNotBefore": "2026-08-20T18:00:00Z",
                "publishNoLaterThan": "2026-08-21T17:45:00Z",
            },
            "beacon": {"targetTimestamp": "2026-08-21T18:00:00.000Z"},
        }
        verification = {
            "status": "VERIFIED_EXECUTION_RESERVATION_RELEASE_ASSETS",
            "reservationFileSHA256": "1" * 64,
            "snapshotReceiptFileSHA256": "2" * 64,
            "manifestFileSHA256": "3" * 64,
            "reservedAt": "2026-08-20T18:00:00Z",
            "networkUsed": False,
            "modelInferenceUsed": False,
            "selectionDerived": False,
        }

        def publication(attested_at: str) -> SimpleNamespace:
            return SimpleNamespace(
                receipt_sha256="4" * 64,
                source_commit="5" * 40,
                source_tree="6" * 40,
                role_sha256=(
                    ("execution-reservation", "1" * 64),
                    ("sha256-manifest", "3" * 64),
                    ("snapshot-publication-receipt", "2" * 64),
                ),
                receipt=SimpleNamespace(
                    kind="reservation",
                    tag="reservation-tag",
                    receipt_sha256="4" * 64,
                    published_at="2026-08-20T18:01:00Z",
                    attested_at=attested_at,
                ),
            )

        report = verify_execution_reservation_publication_provenance(
            publication("2026-08-20T18:02:00Z"), design, verification
        )
        self.assertIs(report["prePulseHalfOpenWindowVerified"], True)
        self.assertIs(report["countsTowardScientificVerdict"], False)
        with self.assertRaisesRegex(EvidenceError, "half-open window"):
            verify_execution_reservation_publication_provenance(
                publication("2026-08-21T17:45:00Z"), design, verification
            )

    def test_frozen_design_replays_every_normative_scientific_field(self) -> None:
        design = frozen_design_fixture()
        validate_frozen_design(design)
        design["candidate"]["groupSize"] += 1
        with self.assertRaisesRegex(EvidenceError, "validation"):
            validate_frozen_design(design)

    def test_registered_ci_workflow_bytes_are_reopened_from_lab_source(self) -> None:
        design = frozen_design_fixture()
        workflow = b"name: exact workflow\n"
        design["continuousIntegration"]["workflowFileBytes"] = len(workflow)
        design["continuousIntegration"]["workflowFileSHA256"] = hashlib.sha256(
            workflow
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / design["continuousIntegration"]["workflowPath"]
            path.parent.mkdir(parents=True)
            path.write_bytes(workflow)
            self.assertEqual(
                verify_registered_ci_workflow_bytes(root, design),
                hashlib.sha256(workflow).hexdigest(),
            )
            path.write_bytes(workflow + b"# tampered\n")
            with self.assertRaisesRegex(EvidenceError, "workflow bytes differ"):
                verify_registered_ci_workflow_bytes(root, design)

    def test_independent_verifier_replays_external_attempt_time_anchor(self) -> None:
        design = frozen_design_fixture()
        self.assertEqual(
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:00:00Z"}, design
            ),
            "2026-08-21T18:00:00Z",
        )
        self.assertEqual(
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:14:59Z"}, design
            ),
            "2026-08-21T18:14:59Z",
        )
        with self.assertRaisesRegex(EvidenceError, "outside"):
            verify_external_attempt_time_anchor(
                {"responseDate": "2026-08-21T18:15:00Z"}, design
            )

    def test_runtime_assets_private_bytes_and_sbom_are_semantically_replayed(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        source_raw = (project_root / "blind_v1/model-assets.draft.json").read_bytes()
        receipt_raw = (
            project_root / "blind_v1/manifests/model-assets.full-rehash.json"
        ).read_bytes()
        source = json.loads(source_raw)
        receipt = json.loads(receipt_raw)
        design = frozen_design_fixture()
        runtime = with_content_digest(
            {
                "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                "countsTowardScientificVerdict": False,
                "networkUsed": False,
                "modelInferenceUsed": False,
                "python": {
                    "registeredVersion": "3.12.10",
                    "version": "3.12.10",
                    "platformTag": "macosx-11.0-arm64",
                    "executable": {
                        "bytes": 1024,
                        "mode": "0755",
                        "sha256": "5" * 64,
                    },
                },
                "host": {
                    "system": "Darwin",
                    "machine": "arm64",
                    "macVersion": "26.3",
                },
                "environment": {},
                "requirementsLocks": [
                    {
                        "name": "pip-bootstrap.txt",
                        "bytes": 173,
                        "sha256": design["runtime"]["pipBootstrapLockSHA256"],
                    },
                    {
                        "name": "requirements.lock",
                        "bytes": 55_781,
                        "sha256": design["runtime"]["requirementsLockSHA256"],
                    }
                ],
                "installedDistributions": [
                    {
                        "name": "unit-contract",
                        "normalizedName": "unit-contract",
                        "version": "1.0",
                        "metadataSHA256": None,
                        "recordSHA256": None,
                        "licenseExpression": "MIT",
                        "licenseDeclared": None,
                        "requiresDist": [],
                    }
                ],
                "installedDistributionCount": 1,
                "runtimeTree": {"entryCount": 1, "treeSHA256": "6" * 64},
                "basePythonTree": {"entryCount": 1, "treeSHA256": "7" * 64},
                "basePythonDistinctFromRuntime": False,
                "labSource": {
                    "origin": design["labSource"]["repository"],
                    "commit": design["labSource"]["commit"],
                    "tree": design["labSource"]["tree"],
                    "worktreeClean": True,
                    "worktreeStatusSHA256": "8" * 64,
                },
                "codecSource": {
                    "origin": design["codecSource"]["repository"],
                    "commit": design["codecSource"]["commit"],
                    "tree": design["codecSource"]["tree"],
                    "worktreeClean": True,
                    "worktreeStatusSHA256": "9" * 64,
                },
            }
        )
        runtime_raw = canonical_json_bytes(runtime) + b"\n"
        sbom_raw = canonical_json_bytes(build_sbom(runtime, receipt)) + b"\n"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bindings = root / "bindings"
            bindings.mkdir()
            documents = {
                "bindings/runtime-manifest.json": (runtime_raw, "runtime-manifest"),
                "bindings/model-assets-source.json": (
                    source_raw,
                    "asset-source-manifest",
                ),
                "bindings/asset-receipt.json": (
                    receipt_raw,
                    "full-asset-manifest",
                ),
                "bindings/sbom.cdx.json": (sbom_raw, "design-release-asset"),
            }
            entries = []
            for relative, (raw, role) in documents.items():
                path = root / relative
                path.write_bytes(raw)
                entries.append(
                    {
                        "path": relative,
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "role": role,
                    }
                )
            for model_key, model in receipt["models"].items():
                for filename, commitment in model["files"].items():
                    entries.append(
                        {
                            "path": f"models/{model_key}/{filename}",
                            "bytes": commitment["bytes"],
                            "sha256": commitment["sha256"],
                            "role": "model-asset",
                        }
                    )
            marker = {
                "runtimeManifestSHA256": hashlib.sha256(runtime_raw).hexdigest(),
                "modelAssetSourceManifestSHA256": hashlib.sha256(
                    source_raw
                ).hexdigest(),
                "fullAssetReceiptSHA256": hashlib.sha256(receipt_raw).hexdigest(),
            }
            design["runtime"]["runtimeManifestSHA256"] = marker[
                "runtimeManifestSHA256"
            ]
            report = verify_runtime_asset_sbom_bindings(
                root,
                {"files": entries},
                marker=marker,
                design=design,
                host_environment={"pythonExecutableSHA256": "5" * 64},
            )
            self.assertEqual(report["sbomSHA256"], hashlib.sha256(sbom_raw).hexdigest())

            private_asset = next(
                entry for entry in entries if entry["role"] == "model-asset"
            )
            private_asset["sha256"] = "0" * 64
            with self.assertRaisesRegex(EvidenceError, "private model bytes"):
                verify_runtime_asset_sbom_bindings(
                    root,
                    {"files": entries},
                    marker=marker,
                    design=design,
                    host_environment={"pythonExecutableSHA256": "5" * 64},
                )

    def test_scientific_result_has_exact_canonical_schema_fields(self) -> None:
        verification = {
            "suiteId": "corelm-blind-crossmodel-v1",
            "attemptId": "20260821T180000Z-0123456789abcdef",
            "verdict": "FAIL_GATES",
            "cells": [
                {
                    "modelKey": "pythia-160m",
                    "corpusProject": "de.wikipedia.org",
                    "pages": 16,
                    "predictions": 2048,
                    "denseBF16Bytes": 200,
                    "containerBytes": 100,
                    "compressionRatioVsBF16": 2.0,
                    "deltaNLLNatPerToken": 0.02,
                    "top1ExactMatches": 2048,
                    "top1Agreement": 1.0,
                    "structuralReplay": True,
                    "pass": False,
                }
            ],
            "modelAggregates": [
                {
                    "modelKey": "pythia-160m",
                    "blocks": 32,
                    "predictions": 4096,
                    "totalExactMatches": 4096,
                    "deltaUpper": 0.02,
                    "top1Lower": 1.0,
                    "wilsonLower": 0.999,
                    "pass": False,
                }
            ],
        }
        result = canonical_scientific_result(
            verification,
            selection_sha256="1" * 64,
            pulse_verification_sha256="2" * 64,
        )
        self.assertEqual(
            set(result),
            {
                "schemaVersion",
                "suiteId",
                "attemptId",
                "selectionSHA256",
                "pulseVerificationSHA256",
                "cells",
                "modelAggregates",
                "suitePass",
                "countsTowardScientificVerdict",
            },
        )
        self.assertNotIn("top1ExactMatches", result["cells"][0])
        self.assertEqual(result["modelAggregates"][0]["pages"], 32)
        self.assertNotIn("blocks", result["modelAggregates"][0])
        self.assertNotIn("totalExactMatches", result["modelAggregates"][0])
        self.assertIs(result["suitePass"], False)

    def test_normative_json_files_require_exact_canonical_json_plus_lf(self) -> None:
        value = {"b": 2, "a": 1}
        raw = canonical_json_bytes(value) + b"\n"
        self.assertEqual(load_canonical_line(raw, label="fixture"), value)
        with self.assertRaisesRegex(EvidenceError, "canonical LF"):
            load_canonical_line(raw[:-1], label="fixture")
        with self.assertRaisesRegex(EvidenceError, "canonical JSON"):
            load_canonical_line(b'{"b":2,"a":1}\n', label="fixture")

    def test_private_snapshot_manifest_is_bound_to_attempt_marker_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = {
                "suiteId": "corelm-blind-crossmodel-v1",
                "createdAt": "2026-08-21T18:00:00Z",
                "designSHA256": "1" * 64,
                "snapshotRegistrationSHA256": "2" * 64,
                "designPublicationReceiptSHA256": "b" * 64,
                "snapshotPublicationReceiptSHA256": "c" * 64,
                "runtimeManifestSHA256": "3" * 64,
                "modelAssetSourceManifestSHA256": "4" * 64,
                "fullAssetReceiptSHA256": "5" * 64,
                "corpusManifestSHA256": "6" * 64,
                "githubGateReceiptSHA256": "e" * 64,
                "labCommit": "1" * 40,
                "labTree": "2" * 40,
                "codecCommit": "3" * 40,
                "codecTree": "4" * 40,
            }
            design = {
                "labSource": {"freezeManifestSHA256": "6" * 64},
                "designRelease": {"signingPublicKeySHA256": "d" * 64},
                "execution": {
                    "oneShotNotBefore": "2026-08-21T18:00:00Z",
                    "markerNoLaterThan": "2026-08-21T18:15:00Z",
                    "hardDeadline": "2026-08-22T18:00:00Z",
                },
                "beacon": {
                    "targetTimestamp": "2026-08-21T18:00:00.000Z",
                    "transportCABundleSHA256": "7" * 64,
                    "offlineTrustBundleSHA256": "8" * 64,
                },
            }
            entries = private_file_entries()
            manifest = {
                "schemaVersion": "corelm-blind-crossmodel-v1-private-snapshot-manifest-v1",
                "suiteId": marker["suiteId"],
                "status": "SEALED_BEFORE_ATTEMPT",
                "createdAt": "2026-08-21T17:59:59Z",
                "countsTowardScientificVerdict": False,
                "designSHA256": marker["designSHA256"],
                "snapshotRegistrationSHA256": marker["snapshotRegistrationSHA256"],
                "designPublicationReceiptSHA256": marker[
                    "designPublicationReceiptSHA256"
                ],
                "snapshotPublicationReceiptSHA256": marker[
                    "snapshotPublicationReceiptSHA256"
                ],
                "reservationPublicationReceiptSHA256": next(
                    str(item["sha256"])
                    for item in entries
                    if item["role"] == "reservation-publication-receipt"
                ),
                "signingPublicKeySHA256": design["designRelease"][
                    "signingPublicKeySHA256"
                ],
                "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
                "modelAssetSourceManifestSHA256": marker[
                    "modelAssetSourceManifestSHA256"
                ],
                "fullAssetReceiptSHA256": marker["fullAssetReceiptSHA256"],
                "corpusManifestSHA256": marker["corpusManifestSHA256"],
                "freezeManifestSHA256": design["labSource"]["freezeManifestSHA256"],
                "githubGateReceiptSHA256": marker["githubGateReceiptSHA256"],
                "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
                "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
                "cosignBinarySHA256": next(
                    str(item["sha256"])
                    for item in entries
                    if item["role"] == "pinned-cosign-binary"
                ),
                "labCommit": marker["labCommit"],
                "labTree": marker["labTree"],
                "codecCommit": marker["codecCommit"],
                "codecTree": marker["codecTree"],
                "labSourceManifestSHA256": "9" * 64,
                "codecSourceManifestSHA256": "a" * 64,
                "files": entries,
            }
            manifest["contentSHA256"] = hashlib.sha256(
                canonical_json_bytes(manifest)
            ).hexdigest()
            raw = canonical_json_bytes(manifest) + b"\n"
            (root / PRIVATE_SNAPSHOT_MANIFEST_PATH).write_bytes(raw)
            marker = create_attempt_marker(
                root,
                suite_id=marker["suiteId"],
                attempt_id="20260821T180000Z-0123456789abcdef",
                design_sha256=marker["designSHA256"],
                snapshot_registration_sha256=marker[
                    "snapshotRegistrationSHA256"
                ],
                design_publication_receipt_sha256=marker[
                    "designPublicationReceiptSHA256"
                ],
                snapshot_publication_receipt_sha256=marker[
                    "snapshotPublicationReceiptSHA256"
                ],
                private_snapshot_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                runtime_manifest_sha256=marker["runtimeManifestSHA256"],
                model_asset_source_manifest_sha256=marker[
                    "modelAssetSourceManifestSHA256"
                ],
                full_asset_receipt_sha256=marker["fullAssetReceiptSHA256"],
                github_gate_receipt_sha256=marker[
                    "githubGateReceiptSHA256"
                ],
                corpus_manifest_sha256=marker["corpusManifestSHA256"],
                codec_commit=marker["codecCommit"],
                codec_tree=marker["codecTree"],
                lab_commit=marker["labCommit"],
                lab_tree=marker["labTree"],
                created_at=marker["createdAt"],
            )
            reservation, reservation_digest = verify_attempt_reservation(
                root, marker, design
            )
            self.assertEqual(reservation["attemptId"], marker["attemptId"])
            self.assertEqual(
                reservation_digest,
                hashlib.sha256((root / RESERVATION_FILENAME).read_bytes()).hexdigest(),
            )
            value = verify_private_snapshot_manifest(root, marker, design)
            self.assertEqual(value["schemaVersion"], manifest["schemaVersion"])
            marker["privateSnapshotManifestSHA256"] = "0" * 64
            with self.assertRaisesRegex(EvidenceError, "attempt marker"):
                verify_private_snapshot_manifest(root, marker, design)

    def test_independent_reservation_binding_rejects_rewritten_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            design = {
                "execution": {
                    "oneShotNotBefore": "2026-08-21T18:00:00Z",
                    "markerNoLaterThan": "2026-08-21T18:15:00Z",
                    "hardDeadline": "2026-08-22T18:00:00Z",
                },
                "beacon": {"targetTimestamp": "2026-08-21T18:00:00.000Z"},
            }
            marker = create_attempt_marker(
                root,
                suite_id="corelm-blind-crossmodel-v1",
                attempt_id="20260821T180000Z-0123456789abcdef",
                design_sha256="1" * 64,
                snapshot_registration_sha256="2" * 64,
                design_publication_receipt_sha256="3" * 64,
                snapshot_publication_receipt_sha256="4" * 64,
                private_snapshot_manifest_sha256="5" * 64,
                runtime_manifest_sha256="6" * 64,
                model_asset_source_manifest_sha256="7" * 64,
                full_asset_receipt_sha256="8" * 64,
                github_gate_receipt_sha256="9" * 64,
                corpus_manifest_sha256="a" * 64,
                codec_commit="1" * 40,
                codec_tree="2" * 40,
                lab_commit="3" * 40,
                lab_tree="4" * 40,
                created_at="2026-08-21T18:00:00Z",
            )
            reservation_path = root / RESERVATION_FILENAME
            reservation = json.loads(reservation_path.read_bytes())
            late_reservation = dict(reservation)
            late_reservation["createdAt"] = "2026-08-21T18:15:00Z"
            late_unsigned = dict(late_reservation)
            late_unsigned.pop("reservationContentSHA256")
            late_reservation["reservationContentSHA256"] = hashlib.sha256(
                canonical_json_bytes(late_unsigned)
            ).hexdigest()
            reservation_path.write_bytes(
                canonical_json_bytes(late_reservation) + b"\n"
            )
            late_marker = dict(marker)
            late_marker["createdAt"] = late_reservation["createdAt"]
            with self.assertRaisesRegex(EvidenceError, "marker window"):
                verify_attempt_reservation(root, late_marker, design)

            reservation["githubGateReceiptSHA256"] = "f" * 64
            unsigned = dict(reservation)
            unsigned.pop("reservationContentSHA256")
            reservation["reservationContentSHA256"] = hashlib.sha256(
                canonical_json_bytes(unsigned)
            ).hexdigest()
            reservation_path.write_bytes(canonical_json_bytes(reservation) + b"\n")
            with self.assertRaisesRegex(
                EvidenceError,
                "durable reservation: githubGateReceiptSHA256",
            ):
                verify_attempt_reservation(root, marker, design)

    def test_private_snapshot_requires_every_sealed_input_role(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = {
                "suiteId": "corelm-blind-crossmodel-v1",
                "createdAt": "2026-08-21T18:00:00Z",
                "designSHA256": "1" * 64,
                "snapshotRegistrationSHA256": "2" * 64,
                "designPublicationReceiptSHA256": "b" * 64,
                "snapshotPublicationReceiptSHA256": "c" * 64,
                "runtimeManifestSHA256": "3" * 64,
                "modelAssetSourceManifestSHA256": "4" * 64,
                "fullAssetReceiptSHA256": "5" * 64,
                "corpusManifestSHA256": "6" * 64,
                "githubGateReceiptSHA256": "e" * 64,
                "labCommit": "1" * 40,
                "labTree": "2" * 40,
                "codecCommit": "3" * 40,
                "codecTree": "4" * 40,
            }
            design = {
                "labSource": {"freezeManifestSHA256": "6" * 64},
                "designRelease": {"signingPublicKeySHA256": "d" * 64},
                "beacon": {
                    "transportCABundleSHA256": "7" * 64,
                    "offlineTrustBundleSHA256": "8" * 64,
                },
            }
            entries = private_file_entries(omit_roles={"model-asset"})
            manifest = {
                "schemaVersion": "corelm-blind-crossmodel-v1-private-snapshot-manifest-v1",
                "suiteId": marker["suiteId"],
                "status": "SEALED_BEFORE_ATTEMPT",
                "createdAt": "2026-08-21T17:59:59Z",
                "countsTowardScientificVerdict": False,
                "designSHA256": marker["designSHA256"],
                "snapshotRegistrationSHA256": marker["snapshotRegistrationSHA256"],
                "designPublicationReceiptSHA256": marker[
                    "designPublicationReceiptSHA256"
                ],
                "snapshotPublicationReceiptSHA256": marker[
                    "snapshotPublicationReceiptSHA256"
                ],
                "reservationPublicationReceiptSHA256": next(
                    str(item["sha256"])
                    for item in entries
                    if item["role"] == "reservation-publication-receipt"
                ),
                "signingPublicKeySHA256": design["designRelease"][
                    "signingPublicKeySHA256"
                ],
                "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
                "modelAssetSourceManifestSHA256": marker[
                    "modelAssetSourceManifestSHA256"
                ],
                "fullAssetReceiptSHA256": marker["fullAssetReceiptSHA256"],
                "corpusManifestSHA256": marker["corpusManifestSHA256"],
                "freezeManifestSHA256": design["labSource"]["freezeManifestSHA256"],
                "githubGateReceiptSHA256": marker["githubGateReceiptSHA256"],
                "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
                "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
                "cosignBinarySHA256": next(
                    str(item["sha256"])
                    for item in entries
                    if item["role"] == "pinned-cosign-binary"
                ),
                "labCommit": marker["labCommit"],
                "labTree": marker["labTree"],
                "codecCommit": marker["codecCommit"],
                "codecTree": marker["codecTree"],
                "labSourceManifestSHA256": "9" * 64,
                "codecSourceManifestSHA256": "a" * 64,
                "files": entries,
            }
            manifest["contentSHA256"] = hashlib.sha256(
                canonical_json_bytes(manifest)
            ).hexdigest()
            raw = canonical_json_bytes(manifest) + b"\n"
            (root / PRIVATE_SNAPSHOT_MANIFEST_PATH).write_bytes(raw)
            marker["privateSnapshotManifestSHA256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(EvidenceError, "role coverage"):
                verify_private_snapshot_manifest(root, marker, design)

    def test_worker_jobs_summaries_and_jsonl_are_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = "corelm-blind-crossmodel-v1"
            attempt = "20260821T180000Z-0123456789abcdef"
            model_key = "pythia-160m"
            corpora = ["a.wikipedia.org", "b.wikipedia.org"]
            selected_pages = {
                corpus: [
                    {"revid": 1000 * (corpus_index + 1) + page_index}
                    for page_index in range(16)
                ]
                for corpus_index, corpus in enumerate(corpora)
            }
            selection = {
                "selectedCorpora": corpora,
                "selectedPages": selected_pages,
            }
            filenames = {
                "config.json",
                "model.safetensors",
                "tokenizer.json",
            }
            private_entries = []
            job_files = {}
            for filename in sorted(filenames):
                path = f"models/{model_key}/{filename}"
                digest = hashlib.sha256(path.encode()).hexdigest()
                private_entries.append(
                    {
                        "path": path,
                        "bytes": 1,
                        "sha256": digest,
                        "role": "model-asset",
                    }
                )
                job_files[filename] = {
                    "path": path,
                    "bytes": 1,
                    "sha256": digest,
                }
            job_pages = {}
            for corpus in corpora:
                job_pages[corpus] = []
                for page_index, selected in enumerate(selected_pages[corpus]):
                    path = f"records/{corpus}/{selected['revid']}.bin"
                    digest = hashlib.sha256(path.encode()).hexdigest()
                    private_entries.append(
                        {
                            "path": path,
                            "bytes": 1,
                            "sha256": digest,
                            "role": "eligible-corpus-record",
                        }
                    )
                    job_pages[corpus].append(
                        {
                            "pageSelectionIndex": page_index,
                            "pageRevisionId": selected["revid"],
                            "recordPath": path,
                            "recordBytes": 1,
                            "recordSHA256": digest,
                        }
                    )
            private_manifest = {
                "files": sorted(private_entries, key=lambda item: item["path"].encode())
            }
            candidate = {
                "backend": "voidtoken-v5",
                "groupSize": 128,
                "transformBlockSize": 128,
                "codeCompression": "zlib-9",
                "scaleCompression": "zlib-9",
                "signMode": "none",
            }
            design = {
                "candidate": candidate,
                "models": [
                    {
                        "key": model_key,
                        "architecture": "gpt-neox-mha",
                        "layers": 3,
                        "kvHeads": 1,
                        "vocabSize": 100,
                        "candidateBitsByLayer": [8, 8, 8],
                    }
                ],
                "execution": {
                    "maximumWorkerRSSBytes": 4294967296,
                    "watchdogPollMilliseconds": 250,
                    "hardDeadline": "2026-08-22T18:00:00Z",
                },
            }
            marker = {"suiteId": suite, "attemptId": attempt}
            job = {
                "schemaVersion": "corelm-blind-crossmodel-v1-worker-job-v1",
                "suiteId": suite,
                "attemptId": attempt,
                "countsTowardScientificVerdict": True,
                "model": {
                    "key": model_key,
                    "files": job_files,
                    "layers": 3,
                    "vocabSize": 100,
                    "candidateBitsByLayer": [8, 8, 8],
                },
                "selectedCorpora": corpora,
                "pages": job_pages,
                "candidate": candidate,
                "seed": 0,
            }
            job_path = root / "jobs" / f"{model_key}.json"
            job_path.parent.mkdir(parents=True)
            job_path.write_bytes(canonical_json_bytes(job) + b"\n")

            loss_bits = float32_to_bits(1.0)
            raw_records = []
            container_records = []
            page_token_records = []
            summary_pages = []
            for corpus in corpora:
                for page_index, selected in enumerate(selected_pages[corpus]):
                    token_ids = [1] * 512
                    page_token_records.append(
                        {
                            "schemaVersion": PAGE_TOKEN_SCHEMA,
                            "suiteId": suite,
                            "attemptId": attempt,
                            "modelKey": model_key,
                            "corpusProject": corpus,
                            "pageRevisionId": selected["revid"],
                            "pageSelectionIndex": page_index,
                            "vocabSize": 100,
                            "first512TokenIds": token_ids,
                            "first512StreamSHA256": hashlib.sha256(
                                token_id_stream(token_ids)
                            ).hexdigest(),
                        }
                    )
                    for prediction_index in range(128):
                        raw_records.append(
                            {
                                "schemaVersion": "corelm-blind-crossmodel-v1-raw-token-evidence-v1",
                                "suiteId": suite,
                                "attemptId": attempt,
                                "modelKey": model_key,
                                "corpusProject": corpus,
                                "pageRevisionId": selected["revid"],
                                "pageSelectionIndex": page_index,
                                "predictionIndex": prediction_index,
                                "targetTokenId": 1,
                                "baselineLossF32Bits": loss_bits,
                                "candidateLossF32Bits": loss_bits,
                                "baselineTop1TokenId": 1,
                                "candidateTop1TokenId": 1,
                            }
                        )
                    for layer_index in range(3):
                        container_records.append(
                            {
                                "schemaVersion": "corelm-blind-crossmodel-v1-container-evidence-v1",
                                "suiteId": suite,
                                "attemptId": attempt,
                                "modelKey": model_key,
                                "corpusProject": corpus,
                                "pageRevisionId": selected["revid"],
                                "pageSelectionIndex": page_index,
                                "layerIndex": layer_index,
                                "denseBF16Bytes": 256,
                                "containerBytes": 128,
                                "containerSHA256": "a" * 64,
                                "relativePath": f"containers/{model_key}/{corpus}/{page_index}/{layer_index}.vtl5",
                                "structuralReplay": True,
                            }
                        )
                    summary_pages.append(
                        {
                            "corpusProject": corpus,
                            "pageSelectionIndex": page_index,
                            "pageRevisionId": selected["revid"],
                            "denseBF16Bytes": 768,
                            "containerBytes": 384,
                            "compressionRatioVsBF16": 2.0,
                            "deltaNLLNatPerToken": 0.0,
                            "top1ExactMatches": 128,
                        }
                    )
            worker_raw = b"".join(canonical_json_line(item) for item in raw_records)
            worker_containers = b"".join(
                canonical_json_line(item) for item in container_records
            )
            worker_page_tokens = b"".join(
                canonical_json_line(item) for item in page_token_records
            )
            worker_root = root / "workers" / model_key
            worker_root.mkdir(parents=True)
            (worker_root / "raw-token-evidence.jsonl").write_bytes(worker_raw)
            (worker_root / "container-evidence.jsonl").write_bytes(worker_containers)
            (worker_root / "page-token-evidence.jsonl").write_bytes(
                worker_page_tokens
            )
            (root / "raw-token-evidence.jsonl").write_bytes(worker_raw)
            (root / "container-evidence.jsonl").write_bytes(worker_containers)
            (root / "page-token-evidence.jsonl").write_bytes(worker_page_tokens)
            supervision_root = root / "supervision"
            supervision_root.mkdir()
            supervisor = {
                "schemaVersion": "corelm-blind-crossmodel-v1-supervisor-receipt-v1",
                "role": "model-worker",
                "subject": model_key,
                "processGroupId": 123,
                "startedAt": "2026-08-21T18:00:00Z",
                "completedAt": "2026-08-21T18:00:01Z",
                "durationNanoseconds": 1,
                "exitCode": 0,
                "peakAggregateRSSBytes": 1024,
                "maximumAggregateRSSBytes": 4294967296,
                "watchdogPollMilliseconds": 250,
                "hardDeadline": "2026-08-22T18:00:00Z",
                "descendantsRemainingAtExit": False,
                "terminationApplied": False,
                "countsTowardScientificVerdict": True,
            }
            (supervision_root / f"{model_key}.json").write_bytes(
                canonical_json_bytes(supervisor) + b"\n"
            )
            summary = {
                "schemaVersion": "corelm-blind-crossmodel-v1-worker-summary-v1",
                "suiteId": suite,
                "attemptId": attempt,
                "modelKey": model_key,
                "geometry": {
                    "modelType": "gpt_neox",
                    "attentionLayout": "multi-head",
                    "layers": 3,
                    "attentionHeads": 1,
                    "kvHeads": 1,
                    "headDimension": 64,
                    "hiddenSize": 64,
                    "trajectoryWidth": 128,
                },
                "pages": summary_pages,
                "rawTokenEvidence": {
                    "path": "raw-token-evidence.jsonl",
                    "bytes": len(worker_raw),
                    "sha256": hashlib.sha256(worker_raw).hexdigest(),
                },
                "containerEvidence": {
                    "path": "container-evidence.jsonl",
                    "bytes": len(worker_containers),
                    "sha256": hashlib.sha256(worker_containers).hexdigest(),
                },
                "pageTokenEvidence": {
                    "path": "page-token-evidence.jsonl",
                    "bytes": len(worker_page_tokens),
                    "sha256": hashlib.sha256(worker_page_tokens).hexdigest(),
                },
                "durationNanoseconds": 1,
                "networkUsed": False,
                "modelLoad": (
                    "verified-owned-bytes-deserialize-drop-before-fp32-model-"
                    "no-mmap-no-pickle-no-from_pretrained"
                ),
                "countsTowardScientificVerdict": True,
            }
            summary_path = worker_root / "worker-summary.json"
            summary_path.write_bytes(canonical_json_bytes(summary) + b"\n")

            required, digest = verify_worker_bindings(
                root,
                private_manifest=private_manifest,
                selection=selection,
                design=design,
                marker=marker,
                model_order=[model_key],
                raw_relative="raw-token-evidence.jsonl",
                container_relative="container-evidence.jsonl",
                page_token_relative="page-token-evidence.jsonl",
            )
            self.assertIn(f"jobs/{model_key}.json", required)
            self.assertIn(f"logs/{model_key}.log", required)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

            summary["rawTokenEvidence"]["sha256"] = "0" * 64
            summary_path.write_bytes(canonical_json_bytes(summary) + b"\n")
            with self.assertRaisesRegex(EvidenceError, "evidence receipt"):
                verify_worker_bindings(
                    root,
                    private_manifest=private_manifest,
                    selection=selection,
                    design=design,
                    marker=marker,
                    model_order=[model_key],
                    raw_relative="raw-token-evidence.jsonl",
                    container_relative="container-evidence.jsonl",
                    page_token_relative="page-token-evidence.jsonl",
                )

    def test_executable_source_tree_has_no_unmanifested_or_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "blind_v1").mkdir()
            source = b"print('sealed')\n"
            (root / "blind_v1" / "runner.py").write_bytes(source)
            manifest = {
                "files": [
                    {
                        "path": "lab/blind_v1/runner.py",
                        "bytes": len(source),
                        "sha256": hashlib.sha256(source).hexdigest(),
                        "role": "lab-source",
                    }
                ]
            }
            digest = verify_manifested_source_tree(
                root, manifest, prefix="lab", role="lab-source"
            )
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            (root / "untracked.py").write_bytes(b"pass\n")
            with self.assertRaisesRegex(EvidenceError, "unmanifested"):
                verify_manifested_source_tree(
                    root, manifest, prefix="lab", role="lab-source"
                )


if __name__ == "__main__":
    unittest.main()
