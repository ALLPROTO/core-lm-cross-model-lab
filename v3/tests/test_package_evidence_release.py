from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import v3.package_evidence_release as subject

from v3.package_evidence_release import (
    ARTIFACT_PATHS,
    EvidenceReleaseError,
    HARD_DEADLINE,
    canonical_json_bytes,
    package_release,
    sha256_bytes,
    verify_release,
)


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
ATTEMPT_ID = "20260903T180000Z-0123456789abcdef"


def canonical_line(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def with_digest(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["contentSHA256"] = sha256_bytes(canonical_json_bytes(value))
    return result


class EvidenceReleasePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        for directory, child_directories, filenames in os.walk(
            self.root, topdown=False, followlinks=False
        ):
            for filename in filenames:
                path = Path(directory) / filename
                if not path.is_symlink():
                    os.chmod(path, 0o600)
            for child in child_directories:
                path = Path(directory) / child
                if not path.is_symlink():
                    os.chmod(path, 0o700)
            os.chmod(directory, 0o700)
        self.temporary.cleanup()

    def write(self, relative: str, raw: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def build_sources(self, state: str | None) -> dict[str, Path]:
        corpus_root = self.root / "corpus-source"
        corpus_files = {
            "crawl-1-manifest.json": b"{}",
            "crawl-2-manifest.json": b"{}",
            "archive/crawl-1/en.wikipedia.org/page-000000/request-uri.txt": b"one\n",
            "archive/crawl-2/en.wikipedia.org/page-000000/response-body.json": b"{}",
            "archive/revisions/en.wikipedia.org/1/response-headers.bin": b"HTTP/1.1 200 OK\r\n",
            "ledgers/en.wikipedia.org.json": b"[]",
            "records/en.wikipedia.org/1.bin": b"canonical-record-bytes",
        }
        for relative, raw in corpus_files.items():
            path = corpus_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        trust_root = self.root / "trust-source"
        trust_cert = trust_root / "certificates" / "leaf.der"
        trust_cert.parent.mkdir(parents=True, exist_ok=True)
        trust_cert.write_bytes(b"nist-leaf-certificate")
        trust_raw = canonical_line(
            {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-nist-trust-bundle-v1",
                "certificates": {"fixture": {"chain": ["certificates/leaf.der"]}},
            }
        )
        (trust_root / "manifest.json").write_bytes(trust_raw)
        ca_raw = b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
        ca_path = self.write("bindings-source/transport-ca.pem", ca_raw)
        design_receipt_raw = canonical_line({"kind": "design", "fixture": True})
        snapshot_receipt_raw = canonical_line({"kind": "snapshot", "fixture": True})
        signing_key_raw = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTURE corelm-test\n"
        design_receipt_path = self.write(
            "bindings-source/design-publication-receipt.json", design_receipt_raw
        )
        snapshot_receipt_path = self.write(
            "bindings-source/snapshot-publication-receipt.json",
            snapshot_receipt_raw,
        )
        signing_key_path = self.write(
            "bindings-source/release-signing-key.pub", signing_key_raw
        )
        design_release_assets = self.root / "design-release-assets"
        snapshot_release_assets = self.root / "snapshot-release-assets"
        design_release_assets.mkdir()
        snapshot_release_assets.mkdir()
        (design_release_assets / "design-asset.bin").write_bytes(b"design asset")
        github_gate_raw = canonical_line(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-github-gate-receipt-v1"
                ),
                "fixture": True,
            }
        )
        (design_release_assets / "github-gate-receipt.json").write_bytes(
            github_gate_raw
        )
        (snapshot_release_assets / "snapshot-asset.bin").write_bytes(
            b"snapshot asset"
        )

        freeze_raw = canonical_line(
            with_digest(
                {
                    "schemaVersion": (
                        "corelm-crossmodel-livewiki-v3-freeze-manifest-v1"
                    )
                }
            )
        )
        runtime_document = with_digest(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-runtime-manifest-v1"
                ),
                "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
            }
        )
        runtime_raw = canonical_line(runtime_document)
        asset_source_raw = canonical_line(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-model-assets-draft-v1"
                ),
                "status": "DRAFT_METADATA_VERIFIED_NO_WEIGHT_DOWNLOAD",
                "completeRuntimeFileList": True,
                "weightsRedistributed": False,
            }
        )
        asset_document = with_digest(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-asset-receipt-v1"
                ),
                "status": "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED",
                "fullSafetensorsBytesLocallyVerified": True,
            }
        )
        asset_raw = canonical_line(asset_document)
        freeze_path = self.write("bindings-source/freeze.json", freeze_raw)
        runtime_path = self.write("bindings-source/runtime.json", runtime_raw)
        asset_source_path = self.write(
            "bindings-source/model-assets-source.json", asset_source_raw
        )
        asset_path = self.write("bindings-source/assets.json", asset_raw)
        sbom_path = self.write(
            "bindings-source/sbom.json",
            canonical_line(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "properties": [
                            {
                                "name": (
                                    "corelm:runtime-manifest-content-sha256"
                                ),
                                "value": runtime_document["contentSHA256"],
                            },
                            {
                                "name": "corelm:asset-receipt-content-sha256",
                                "value": asset_document["contentSHA256"],
                            },
                            {
                                "name": (
                                    "corelm:counts-toward-scientific-verdict"
                                ),
                                "value": "false",
                            },
                        ]
                    },
                }
            ),
        )
        design_raw = canonical_line(
            {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-design-v1",
                "suiteId": SUITE_ID,
                "status": "PUBLIC_DESIGN_FROZEN",
                "readyToFreeze": True,
                "designRelease": {
                    "signingPublicKeySHA256": sha256_bytes(signing_key_raw)
                },
                "labSource": {"freezeManifestSHA256": sha256_bytes(freeze_raw)},
                "runtime": {"runtimeManifestSHA256": sha256_bytes(runtime_raw)},
                "beacon": {
                    "offlineTrustBundleSHA256": sha256_bytes(trust_raw),
                    "transportCABundleSHA256": sha256_bytes(ca_raw),
                },
            }
        )
        design_path = self.write("bindings-source/design.json", design_raw)
        corpus_manifest_raw = canonical_json_bytes(
            {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-corpus-manifest-v1",
                "suiteId": SUITE_ID,
            }
        )
        (corpus_root / "corpus-manifest.json").write_bytes(corpus_manifest_raw)
        snapshot_raw = canonical_line(
            {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-snapshot-v1",
                "suiteId": SUITE_ID,
                "designPublicationReceiptSHA256": sha256_bytes(
                    design_receipt_raw
                ),
                "modelAssetSourceManifestSHA256": sha256_bytes(
                    asset_source_raw
                ),
                "fullAssetReceiptSHA256": sha256_bytes(asset_raw),
                "githubGateReceiptSHA256": sha256_bytes(github_gate_raw),
                "corpusManifestSHA256": sha256_bytes(corpus_manifest_raw),
            }
        )
        snapshot_path = self.write("bindings-source/snapshot.json", snapshot_raw)

        attempt_root = self.root / "attempt-source"
        attempt_root.mkdir()
        private_raw = canonical_line(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-private-snapshot-manifest-v1"
                ),
                "designSHA256": sha256_bytes(design_raw),
                "snapshotRegistrationSHA256": sha256_bytes(snapshot_raw),
                "designPublicationReceiptSHA256": sha256_bytes(
                    design_receipt_raw
                ),
                "snapshotPublicationReceiptSHA256": sha256_bytes(
                    snapshot_receipt_raw
                ),
                "runtimeManifestSHA256": sha256_bytes(runtime_raw),
                "modelAssetSourceManifestSHA256": sha256_bytes(
                    asset_source_raw
                ),
                "fullAssetReceiptSHA256": sha256_bytes(asset_raw),
                "corpusManifestSHA256": sha256_bytes(corpus_manifest_raw),
                "codecCommit": "1" * 40,
                "codecTree": "2" * 40,
                "labCommit": "3" * 40,
                "labTree": "4" * 40,
            }
        )
        marker = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-attempt-v1",
            "status": "STARTED",
            "suiteId": SUITE_ID,
            "attemptId": ATTEMPT_ID,
            "createdAt": "2026-09-03T18:00:00Z",
            "designSHA256": sha256_bytes(design_raw),
            "snapshotRegistrationSHA256": sha256_bytes(snapshot_raw),
            "designPublicationReceiptSHA256": sha256_bytes(design_receipt_raw),
            "snapshotPublicationReceiptSHA256": sha256_bytes(
                snapshot_receipt_raw
            ),
            "privateSnapshotManifestSHA256": sha256_bytes(private_raw),
            "runtimeManifestSHA256": sha256_bytes(runtime_raw),
            "modelAssetSourceManifestSHA256": sha256_bytes(asset_source_raw),
            "fullAssetReceiptSHA256": sha256_bytes(asset_raw),
            "githubGateReceiptSHA256": sha256_bytes(github_gate_raw),
            "corpusManifestSHA256": sha256_bytes(corpus_manifest_raw),
            "codecCommit": "1" * 40,
            "codecTree": "2" * 40,
            "labCommit": "3" * 40,
            "labTree": "4" * 40,
            "targetPulseTimestamp": "2026-09-02T18:00:00.000Z",
            "countsTowardScientificVerdict": True,
            "retryPermitted": False,
        }
        marker["markerContentSHA256"] = sha256_bytes(canonical_json_bytes(marker))
        marker_raw = canonical_line(marker)
        reservation = {
            key: value
            for key, value in marker.items()
            if key not in {"schemaVersion", "status", "markerContentSHA256"}
        }
        reservation.update(
            {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-attempt-reservation-v1"
                ),
                "status": "RESERVED",
                "countsTowardScientificVerdict": False,
            }
        )
        reservation["reservationContentSHA256"] = sha256_bytes(
            canonical_json_bytes(reservation)
        )
        (attempt_root / "attempt-reservation.json").write_bytes(
            canonical_line(reservation)
        )
        (attempt_root / "attempt-marker.json").write_bytes(marker_raw)

        if state in {"PASS", "FAIL_GATES"}:
            fixed = {
                "private-snapshot-manifest.json": private_raw,
                "environment/host-preflight.json": canonical_line({"safe": True}),
                "nist/request-uri.txt": b"https://beacon.nist.gov/example\n",
                "nist/response-headers.bin": b"HTTP/1.1 200 OK\r\n",
                "nist/response-body.json": b"{}",
                "nist/verification.json": canonical_line({"verified": True}),
                "selection.json": canonical_line({"selected": True}),
                "page-token-evidence.jsonl": b"{}\n",
                "raw-token-evidence.jsonl": b"{}\n",
                "container-evidence.jsonl": b"{}\n",
                "logs/independent-verifier.log": b"verified\n",
            }
            for relative, raw in fixed.items():
                path = attempt_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            for model_key in (
                "gpt-neo-125m",
                "smollm2-360m",
                "tiny-starcoder-py",
            ):
                path = (
                    attempt_root
                    / "workers"
                    / model_key
                    / "page-token-evidence.jsonl"
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"{}\n")
            suite_pass = state == "PASS"
            result_raw = canonical_line(
                {
                    "schemaVersion": "corelm-crossmodel-livewiki-v3-result-v1",
                    "suiteId": SUITE_ID,
                    "attemptId": ATTEMPT_ID,
                    "suitePass": suite_pass,
                    "countsTowardScientificVerdict": True,
                }
            )
            (attempt_root / "result.json").write_bytes(result_raw)
            replay_summary = {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v3-independent-model-replay-v1"
                ),
                "suiteId": SUITE_ID,
                "attemptId": ATTEMPT_ID,
                "replayComplete": True,
                "exactTokenIds": True,
                "exactLossFloat32Bits": True,
                "exactTop1TokenIds": True,
                "allContainerInputsBoundToBaselineCache": True,
                "countsTowardScientificVerdict": True,
            }
            replay_summary["contentSHA256"] = sha256_bytes(
                canonical_json_bytes(replay_summary)
            )
            report_raw = canonical_line(
                {
                    "schemaVersion": "corelm-crossmodel-livewiki-v3-independent-verification-v1",
                    "suiteId": SUITE_ID,
                    "attemptId": ATTEMPT_ID,
                    "verdict": state,
                    "producerResultExactMatch": True,
                    "modelReplaySummary": replay_summary,
                    "modelReplaySummarySHA256": replay_summary[
                        "contentSHA256"
                    ],
                }
            )
            (attempt_root / "independent-verifier-report.json").write_bytes(
                report_raw
            )
            manifest_paths = [
                "attempt-marker.json",
                "attempt-reservation.json",
                "page-token-evidence.jsonl",
                "workers/gpt-neo-125m/page-token-evidence.jsonl",
                "workers/smollm2-360m/page-token-evidence.jsonl",
                "workers/tiny-starcoder-py/page-token-evidence.jsonl",
            ]
            evidence_entries = []
            for relative in manifest_paths:
                raw = (attempt_root / relative).read_bytes()
                evidence_entries.append(
                    {
                        "path": relative,
                        "bytes": len(raw),
                        "sha256": sha256_bytes(raw),
                    }
                )
            evidence_manifest_raw = canonical_line(
                {
                    "schemaVersion": "corelm-crossmodel-livewiki-v3-evidence-manifest-v1",
                    "entries": evidence_entries,
                    "entriesSHA256": sha256_bytes(canonical_json_bytes(evidence_entries)),
                }
            )
            (attempt_root / "evidence-manifest.json").write_bytes(
                evidence_manifest_raw
            )
            outcome = {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-outcome-v1",
                "suiteId": SUITE_ID,
                "attemptId": ATTEMPT_ID,
                "terminalState": state,
                "completedAt": "2026-09-03T19:00:00Z",
                "attemptMarkerFileSHA256": sha256_bytes(marker_raw),
                "resultSHA256": sha256_bytes(result_raw),
                "evidenceManifestSHA256": sha256_bytes(evidence_manifest_raw),
                "independentVerifierSHA256": sha256_bytes(report_raw),
                "failureReason": None,
                "retryPermitted": False,
                "countsTowardScientificVerdict": True,
            }
            (attempt_root / "terminal-outcome.json").write_bytes(
                canonical_line(outcome)
            )
        elif state in {"FAIL_EXECUTION", "CONSUMED_INCOMPLETE"}:
            outcome = {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-outcome-v1",
                "suiteId": SUITE_ID,
                "attemptId": ATTEMPT_ID,
                "terminalState": state,
                "completedAt": "2026-09-03T18:01:00Z",
                "attemptMarkerFileSHA256": sha256_bytes(marker_raw),
                "resultSHA256": None,
                "evidenceManifestSHA256": None,
                "independentVerifierSHA256": None,
                "failureReason": "fixture process failure",
                "retryPermitted": False,
                "countsTowardScientificVerdict": False,
            }
            (attempt_root / "terminal-outcome.json").write_bytes(
                canonical_line(outcome)
            )

        return {
            "attempt_root": attempt_root,
            "corpus_root": corpus_root,
            "design": design_path,
            "snapshot_registration": snapshot_path,
            "freeze_manifest": freeze_path,
            "runtime_manifest": runtime_path,
            "asset_source_manifest": asset_source_path,
            "asset_receipt": asset_path,
            "sbom": sbom_path,
            "design_publication_receipt": design_receipt_path,
            "snapshot_publication_receipt": snapshot_receipt_path,
            "signing_public_key": signing_key_path,
            "design_release_assets": design_release_assets,
            "snapshot_release_assets": snapshot_release_assets,
            "nist_trust_root": trust_root,
            "transport_ca_bundle": ca_path,
        }

    def package(self, state: str | None, name: str = "release") -> tuple[Path, dict[str, object]]:
        sources = self.build_sources(state)
        output = self.root / name
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        return output, report

    def test_complete_pass_inventory_is_canonical_and_verifiable(self) -> None:
        output, report = self.package("PASS")
        self.assertEqual(report["status"], "VERIFIED_COMPLETE_TERMINAL")
        self.assertEqual(report["terminalState"], "PASS")
        self.assertIs(report["attemptCountsTowardScientificVerdict"], True)
        self.assertEqual(report, verify_release(output))
        manifest = json.loads((output / "evidence-release-manifest.json").read_bytes())
        self.assertEqual(manifest["missingArtifacts"], [])
        self.assertTrue(all(manifest["artifactPresence"].values()))
        self.assertIn(
            "payload/corpus/archive/revisions/en.wikipedia.org/1/response-headers.bin",
            {entry["path"] for entry in manifest["entries"]},
        )
        self.assertIn(
            "payload/bindings/nist-trust/certificates/leaf.der",
            {entry["path"] for entry in manifest["entries"]},
        )

    def test_concurrent_empty_output_after_precheck_is_never_replaced(self) -> None:
        sources = self.build_sources("PASS")
        output = self.root.resolve() / "concurrent-output"
        sentinel_raw = b"concurrent publisher owns this directory\n"
        real_mkdir = os.mkdir
        raced = False

        def racing_mkdir(path: object, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
            nonlocal raced
            candidate = Path(path) if dir_fd is None else None
            if candidate == output and not raced:
                raced = True
                real_mkdir(output, 0o700)
                (output / "sentinel").write_bytes(sentinel_raw)
            if dir_fd is None:
                real_mkdir(path, mode)
            else:
                real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(subject.os, "mkdir", side_effect=racing_mkdir):
            with self.assertRaisesRegex(
                EvidenceReleaseError,
                "output appeared during package construction",
            ):
                package_release(
                    **sources,
                    output_directory=output,
                    created_at="2026-09-03T20:00:00Z",
                )

        self.assertTrue(raced)
        self.assertTrue(output.is_dir())
        self.assertEqual((output / "sentinel").read_bytes(), sentinel_raw)
        self.assertEqual(sorted(path.name for path in output.iterdir()), ["sentinel"])
        partials = sorted(self.root.resolve().glob(".concurrent-output.partial-*"))
        self.assertEqual(len(partials), 1)
        self.assertTrue((partials[0] / "evidence-release-manifest.json").is_file())

    def test_complete_attempt_without_reservation_is_rejected(self) -> None:
        sources = self.build_sources("PASS")
        (sources["attempt_root"] / "attempt-reservation.json").unlink()
        with self.assertRaisesRegex(
            EvidenceReleaseError, "no durable attempt reservation"
        ):
            package_release(
                **sources,
                output_directory=self.root / "marker-without-reservation",
                created_at="2026-09-03T20:00:00Z",
            )

    def test_complete_inner_manifest_must_commit_durable_reservation(self) -> None:
        sources = self.build_sources("PASS")
        manifest_path = sources["attempt_root"] / "evidence-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["entries"] = [
            entry
            for entry in manifest["entries"]
            if entry["path"] != "attempt-reservation.json"
        ]
        manifest["entriesSHA256"] = sha256_bytes(
            canonical_json_bytes(manifest["entries"])
        )
        manifest_raw = canonical_line(manifest)
        manifest_path.write_bytes(manifest_raw)
        outcome_path = sources["attempt_root"] / "terminal-outcome.json"
        outcome = json.loads(outcome_path.read_bytes())
        outcome["evidenceManifestSHA256"] = sha256_bytes(manifest_raw)
        outcome_path.write_bytes(canonical_line(outcome))
        with self.assertRaisesRegex(
            EvidenceReleaseError,
            "omits durable attempt state: attempt-reservation.json",
        ):
            package_release(
                **sources,
                output_directory=self.root / "inner-manifest-without-reservation",
                created_at="2026-09-03T20:00:00Z",
            )

    def test_fail_execution_is_terminal_but_does_not_fabricate_absent_files(self) -> None:
        output, report = self.package("FAIL_EXECUTION")
        self.assertEqual(report["status"], "VERIFIED_COMPLETE_TERMINAL")
        self.assertEqual(report["terminalState"], "FAIL_EXECUTION")
        self.assertIs(report["attemptCountsTowardScientificVerdict"], False)
        self.assertIn(ARTIFACT_PATHS["producerResult"], report["missingArtifacts"])
        self.assertFalse(
            (output / ARTIFACT_PATHS["producerResult"]).exists()
        )

    def test_fail_gates_is_a_complete_scientific_terminal_outcome(self) -> None:
        _output, report = self.package("FAIL_GATES")
        self.assertEqual(report["status"], "VERIFIED_COMPLETE_TERMINAL")
        self.assertEqual(report["terminalState"], "FAIL_GATES")
        self.assertIs(report["attemptCountsTowardScientificVerdict"], True)
        self.assertEqual(report["missingArtifacts"], [])

    def test_late_handcrafted_gate_outcome_is_forensic_partial(self) -> None:
        sources = self.build_sources("PASS")
        outcome_path = sources["attempt_root"] / "terminal-outcome.json"
        outcome = json.loads(outcome_path.read_bytes())
        outcome["completedAt"] = HARD_DEADLINE
        outcome_path.write_bytes(canonical_line(outcome))
        output = self.root / "late-gate-outcome"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-04T19:00:00Z",
        )
        self.assertEqual(report["status"], "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE")
        self.assertEqual(report["recoveryClassification"], "CONSUMED_INCOMPLETE")
        self.assertEqual(
            report["forensicArtifacts"][0]["condition"],
            "PARTIAL_OR_NONCANONICAL_TERMINAL_OUTCOME",
        )

    def test_reserved_started_attempt_without_outcome_is_explicit_partial(self) -> None:
        _output, report = self.package(None)
        self.assertEqual(report["status"], "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE")
        self.assertIsNone(report["terminalState"])
        self.assertEqual(report["recoveryClassification"], "CONSUMED_INCOMPLETE")
        self.assertIn(ARTIFACT_PATHS["terminalOutcome"], report["missingArtifacts"])

    def test_reservation_only_attempt_is_publishable_consumed_incomplete(self) -> None:
        sources = self.build_sources(None)
        (sources["attempt_root"] / "attempt-marker.json").unlink()
        output = self.root / "reservation-only"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(report["status"], "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE")
        self.assertIn(ARTIFACT_PATHS["attemptMarker"], report["missingArtifacts"])
        self.assertEqual(report["forensicArtifacts"], [])

    def test_partial_marker_raw_bytes_are_preserved_and_hashed(self) -> None:
        sources = self.build_sources(None)
        raw = b'{"schemaVersion":"interrupted"'
        (sources["attempt_root"] / "attempt-marker.json").write_bytes(raw)
        output = self.root / "partial-marker"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(report["status"], "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE")
        forensic = report["forensicArtifacts"]
        self.assertEqual(len(forensic), 1)
        self.assertEqual(
            forensic[0]["condition"],
            "PARTIAL_OR_NONCANONICAL_ATTEMPT_MARKER",
        )
        self.assertEqual(forensic[0]["sha256"], sha256_bytes(raw))
        self.assertEqual(
            (output / ARTIFACT_PATHS["attemptMarker"]).read_bytes(), raw
        )

    def test_partial_outcome_raw_bytes_are_preserved_and_hashed(self) -> None:
        sources = self.build_sources(None)
        raw = b'{"terminalState":"FAIL_EXECUTION"'
        (sources["attempt_root"] / "terminal-outcome.json").write_bytes(raw)
        output = self.root / "partial-outcome"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(report["status"], "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE")
        forensic = report["forensicArtifacts"]
        self.assertEqual(len(forensic), 1)
        self.assertEqual(
            forensic[0]["condition"],
            "PARTIAL_OR_NONCANONICAL_TERMINAL_OUTCOME",
        )
        self.assertEqual(forensic[0]["bytes"], len(raw))
        self.assertEqual(forensic[0]["sha256"], sha256_bytes(raw))

    def test_pending_marker_is_explicit_forensic_evidence(self) -> None:
        sources = self.build_sources(None)
        (sources["attempt_root"] / "attempt-marker.json").unlink()
        pending = b'{"interrupted":'
        (sources["attempt_root"] / "attempt-marker.pending").write_bytes(pending)
        output = self.root / "pending-marker"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(
            report["forensicArtifacts"][0]["condition"],
            "INTERRUPTED_ATTEMPT_MARKER_PUBLICATION",
        )
        self.assertEqual(report["forensicArtifacts"][0]["sha256"], sha256_bytes(pending))

    def test_pending_outcome_is_explicit_forensic_evidence(self) -> None:
        sources = self.build_sources(None)
        pending = b'{"terminalState":'
        (sources["attempt_root"] / "terminal-outcome.pending").write_bytes(pending)
        output = self.root / "pending-outcome"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(
            report["forensicArtifacts"][0]["condition"],
            "INTERRUPTED_TERMINAL_OUTCOME_PUBLICATION",
        )
        self.assertEqual(report["forensicArtifacts"][0]["sha256"], sha256_bytes(pending))

    def test_reservation_cleanup_residue_is_explicit_forensic_evidence(self) -> None:
        sources = self.build_sources(None)
        pending = (sources["attempt_root"] / "attempt-reservation.json").read_bytes()
        (sources["attempt_root"] / "attempt-reservation.pending").write_bytes(pending)
        output = self.root / "reservation-cleanup-residue"
        report = package_release(
            **sources,
            output_directory=output,
            created_at="2026-09-03T20:00:00Z",
        )
        self.assertEqual(
            report["forensicArtifacts"][0]["condition"],
            "INTERRUPTED_RESERVATION_PUBLICATION_CLEANUP",
        )
        self.assertEqual(report["forensicArtifacts"][0]["bytes"], len(pending))

    def test_tampered_packaged_byte_is_rejected(self) -> None:
        output, _report = self.package("PASS")
        target = output / "payload" / "attempt" / "result.json"
        os.chmod(target.parent, 0o700)
        os.chmod(target, 0o600)
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaises(EvidenceReleaseError):
            verify_release(output)

    def test_gate_outcome_without_page_token_evidence_is_not_publishable(self) -> None:
        sources = self.build_sources("PASS")
        (sources["attempt_root"] / "page-token-evidence.jsonl").unlink()
        output = self.root / "missing-page-tokens"
        with self.assertRaisesRegex(EvidenceReleaseError, "missing required evidence"):
            package_release(
                **sources,
                output_directory=output,
                created_at="2026-09-03T20:00:00Z",
            )
        self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_source_symlink_is_rejected_and_no_final_package_is_published(self) -> None:
        sources = self.build_sources("FAIL_EXECUTION")
        os.symlink(
            sources["attempt_root"] / "attempt-marker.json",
            sources["attempt_root"] / "marker-link.json",
        )
        output = self.root / "unsafe-release"
        with self.assertRaises(EvidenceReleaseError):
            package_release(
                **sources,
                output_directory=output,
                created_at="2026-09-03T20:00:00Z",
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
