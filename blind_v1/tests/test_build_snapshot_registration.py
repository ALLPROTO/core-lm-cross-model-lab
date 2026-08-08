from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import blind_v1.tests.test_release_receipt as release_fixture
from blind_v1.build_snapshot_registration import (
    SnapshotRegistrationBuildError,
    _load_verified_tokenizers,
    _historical_build_snapshot_registration as build_snapshot_registration,
    _historical_build_snapshot_registration_to_path as build_snapshot_registration_to_path,
    parse_arguments,
)
from blind_v1.github_release_attestation import build_attestation_record
from blind_v1.protocol import (
    canonical_json_bytes,
    load_json_strict,
    load_json_strict_bytes,
    sha256_bytes,
    validate_snapshot_registration,
)
from blind_v1.release_receipt import API_ROLES, GITHUB_API_VERSION, REQUIRED_ASSET_ROLES
from blind_v1.reproducibility import with_content_digest


BLIND_V1_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
FIXTURE_CRYPTOGRAPHIC_VERIFIER = release_fixture.FIXTURE_CRYPTOGRAPHIC_VERIFIER


class SnapshotRegistrationBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.corpus_root = self.root / "corpus"
        self.corpus_root.mkdir()
        self.asset_root = self.root / "assets"
        self.asset_root.mkdir()
        self.design_release_asset_root = self.root / "design-release-assets"
        self.design_release_asset_root.mkdir()
        self.signing_public_key_path = self.root / "release-signing-key.pub"
        self.signing_public_key_path.write_bytes(
            (BLIND_V1_ROOT / "signing/corelm-blind-crossmodel-v1-signing.pub").read_bytes()
        )
        self.design_path = self.root / "frozen-design.json"
        self.asset_manifest_path = self.root / "model-assets.draft.json"
        self.asset_receipt_path = self.root / "full-asset-receipt.json"
        self.design_receipt_path = self.root / "design-publication-receipt.json"
        self.output = self.root / "snapshot-registration.json"

        self.design = copy.deepcopy(
            load_json_strict(BLIND_V1_ROOT / "design-registration.draft.json")
        )
        self.design["schemaVersion"] = "corelm-blind-crossmodel-v1-design-v1"
        self.design["status"] = "PUBLIC_DESIGN_FROZEN"
        self.design["readyToFreeze"] = True
        self.design["freezeBlockers"] = []
        self.design["labSource"].update(
            status="FROZEN_BOUND",
            commit="1" * 40,
            tree="2" * 40,
            freezeManifestSHA256="3" * 64,
        )
        self.design["runtime"].update(
            status="FROZEN_BOUND", runtimeManifestSHA256="4" * 64
        )
        self.design["developmentControls"]["realDataE2EFreezeGate"].update(
            status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
            executionId="development-execution-20260906T100000Z-0123456789abcdef",
            archiveReceiptSHA256="7" * 64,
            archivePublishedAt="2026-08-08T10:05:00Z",
            archiveAttestedAt="2026-08-08T10:06:00Z",
            releaseAttestationBundleSHA256="b" * 64,
            releaseAttestationOutputSHA256="c" * 64,
            reportSHA256="8" * 64,
            artifactSetSHA256="9" * 64,
            controlConfigurationSHA256="a" * 64,
            completedAt="2026-08-08T10:00:00Z",
        )
        self.design["beacon"].update(
            trustBundleStatus="FROZEN_OFFLINE_TRUST_BUNDLE",
            transportCABundleSHA256="5" * 64,
            offlineTrustBundleSHA256=self.design["beacon"][
                "frozenOfflineTrustBundleSHA256"
            ],
        )
        self.design_raw = canonical_json_bytes(self.design) + b"\n"
        self.design_path.write_bytes(self.design_raw)

        self.asset_manifest_raw = (BLIND_V1_ROOT / "model-assets.draft.json").read_bytes()
        self.asset_manifest_path.write_bytes(self.asset_manifest_raw)
        self.asset_receipt_raw = (
            BLIND_V1_ROOT / "manifests/model-assets.full-rehash.json"
        ).read_bytes()
        self.asset_receipt_path.write_bytes(self.asset_receipt_raw)
        self._write_corpus()
        self._write_design_receipt()

    def _write_corpus(self) -> None:
        projects: dict[str, object] = {}
        self.ledger_paths: dict[str, Path] = {}
        for index, project in enumerate(self.design["futureCorpus"]["projects"]):
            raw = canonical_json_bytes([{"project": project, "fixture": index}])
            relative = f"ledgers/{project}.json"
            path = self.corpus_root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            self.ledger_paths[project] = path
            projects[project] = {
                "crawls": [],
                "unionRevisionCount": 64,
                "inventory": [],
                "eligibleRevisionCount": 64,
                "ledger": {
                    "relativePath": relative,
                    "bytes": len(raw),
                    "sha256": sha256_bytes(raw),
                },
            }
        manifest = {
            "schemaVersion": "corelm-blind-crossmodel-v1-corpus-manifest-v1",
            "suiteId": self.design["suiteId"],
            "status": "SNAPSHOT_READY_FOR_FREEZE",
            "countsTowardScientificVerdict": False,
            "projects": projects,
        }
        self.corpus_manifest_raw = canonical_json_bytes(manifest)
        (self.corpus_root / "corpus-manifest.json").write_bytes(
            self.corpus_manifest_raw
        )

    def _asset(self, role: str, index: int) -> dict[str, object]:
        raw_by_role = {
            "design-registration": self.design_raw,
            "asset-source-manifest": self.asset_manifest_raw,
            "full-asset-receipt": self.asset_receipt_raw,
        }
        raw = raw_by_role.get(role, f"published {role}\n".encode("ascii"))
        name = role.replace("-", "_") + ".bin"
        return {
            "role": role,
            "assetId": 1000 + index,
            "name": name,
            "apiURL": f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{1000 + index}",
            "downloadURL": (
                f"https://github.com/{REPOSITORY}/releases/download/"
                f"{self.design['designRelease']['tag']}/{name}"
            ),
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        }

    def _write_design_receipt(self) -> None:
        release = self.design["designRelease"]
        receipt = {
            "schemaVersion": "corelm-github-release-receipt-v2",
            "suiteId": self.design["suiteId"],
            "githubAPIVersion": GITHUB_API_VERSION,
            "repository": {
                "slug": REPOSITORY,
                "htmlURL": f"https://github.com/{REPOSITORY}",
                "apiURL": f"https://api.github.com/repos/{REPOSITORY}",
            },
            "kind": "design",
            "tag": release["tag"],
            "release": {
                "id": 12345,
                "apiURL": f"https://api.github.com/repos/{REPOSITORY}/releases/12345",
                "htmlURL": f"https://github.com/{REPOSITORY}/releases/tag/{release['tag']}",
                "publishedAt": "2026-08-08T12:00:00Z",
                "deadline": release["publishNoLaterThan"],
            },
            "source": {
                "commit": self.design["labSource"]["commit"],
                "tree": self.design["labSource"]["tree"],
                "commitObject": {"fixture": "opaque-to-builder"},
            },
            "annotatedTag": {
                "objectOID": "7" * 40,
                "targetType": "commit",
                "targetCommit": self.design["labSource"]["commit"],
                "rawPayload": {"fixture": "opaque-to-builder"},
            },
            "signatureVerification": {
                "status": "VERIFIED",
                "signatureType": release["signatureType"],
                "exitCode": 0,
                "keyFingerprint": release["signingKeyFingerprint"],
                "publicKeySHA256": release["signingPublicKeySHA256"],
                "targetCommit": self.design["labSource"]["commit"],
            },
            "githubReleaseAttestation": build_attestation_record(
                canonical_json_bytes(
                    {"fixture": "opaque-pinned-gh-release-verification-output"}
                )
                + b"\n",
                {},
            ),
            "requiredAssets": [
                self._asset(role, index)
                for index, role in enumerate(REQUIRED_ASSET_ROLES["design"])
            ],
            "githubAPIResponses": [{"role": role} for role in API_ROLES],
            "receiptCreatedAt": "2026-08-08T12:10:00Z",
        }
        self.design_receipt = with_content_digest(receipt)
        self.design_receipt_raw = canonical_json_bytes(self.design_receipt) + b"\n"
        self.design_receipt_path.write_bytes(self.design_receipt_raw)

    def publication_result(self) -> SimpleNamespace:
        return SimpleNamespace(
            receipt_sha256=sha256_bytes(self.design_receipt_raw),
            source_commit=self.design["labSource"]["commit"],
            source_tree=self.design["labSource"]["tree"],
            role_sha256=tuple(
                sorted(
                    (item["role"], item["sha256"])
                    for item in self.design_receipt["requiredAssets"]
                )
            ),
        )

    def replay_result(self) -> dict[str, object]:
        return {
            "schemaVersion": "corelm-blind-crossmodel-v1-corpus-verification-v1",
            "status": "VERIFIED_SNAPSHOT_BYTES",
            "readyForFreeze": True,
            "eligibleRecords": 192,
            "manifestSHA256": sha256_bytes(self.corpus_manifest_raw),
            "tokenCommitmentsRecomputed": True,
            "modelInferenceUsed": False,
        }

    def build(self) -> bytes:
        return build_snapshot_registration(
            frozen_design_path=self.design_path,
            corpus_root=self.corpus_root,
            asset_root=self.asset_root,
            design_release_asset_root=self.design_release_asset_root,
            signing_public_key_path=self.signing_public_key_path,
            design_publication_receipt_path=self.design_receipt_path,
            asset_source_manifest_path=self.asset_manifest_path,
            full_asset_receipt_path=self.asset_receipt_path,
            created_at="2026-08-19T06:30:00Z",
            cryptographic_attestation_verifier=FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )

    def test_derives_one_deterministic_registration_and_invokes_replay(self) -> None:
        owned = {model["key"]: object() for model in self.design["models"]}
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ) as publication, mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value=owned,
        ) as load_tokenizers, mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            return_value=self.replay_result(),
        ) as replay:
            first = self.build()
            second = self.build()
        self.assertEqual(first, second)
        self.assertEqual(publication.call_count, 2)
        publication_kwargs = publication.call_args.kwargs
        self.assertEqual(publication_kwargs["kind"], "design")
        self.assertIs(
            publication_kwargs["cryptographic_attestation_verifier"],
            FIXTURE_CRYPTOGRAPHIC_VERIFIER,
        )
        self.assertEqual(
            tuple(publication_kwargs["expected_role_paths"]),
            REQUIRED_ASSET_ROLES["design"],
        )
        self.assertEqual(
            set(publication_kwargs["expected_role_paths"].values()),
            {
                self.design_release_asset_root / item["name"]
                for item in self.design_receipt["requiredAssets"]
            },
        )
        self.assertEqual(load_tokenizers.call_count, 2)
        self.assertEqual(replay.call_count, 2)
        replay.assert_called_with(self.corpus_root, tokenizers=owned)
        snapshot = load_json_strict_bytes(first, label="built snapshot")
        self.assertEqual(first, canonical_json_bytes(snapshot) + b"\n")
        validate_snapshot_registration(snapshot, allow_fixture=False)
        self.assertEqual(
            snapshot["projects"], self.design["futureCorpus"]["projects"]
        )
        self.assertEqual(
            snapshot["models"], [model["key"] for model in self.design["models"]]
        )
        self.assertEqual(
            snapshot["designPublicationReceiptSHA256"],
            sha256_bytes(self.design_receipt_raw),
        )
        for project, path in self.ledger_paths.items():
            self.assertEqual(snapshot["ledgers"][project], sha256_bytes(path.read_bytes()))

    def test_cross_bindings_and_asset_receipt_fail_closed(self) -> None:
        wrong = copy.deepcopy(self.design_receipt)
        target = next(
            item
            for item in wrong["requiredAssets"]
            if item["role"] == "full-asset-receipt"
        )
        target["sha256"] = "0" * 64
        self.design_receipt_path.write_bytes(
            canonical_json_bytes(with_content_digest({
                key: value for key, value in wrong.items() if key != "contentSHA256"
            })) + b"\n"
        )
        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "binds another full-asset-receipt"
        ):
            self.build()

        self.design_receipt_path.write_bytes(self.design_receipt_raw)
        receipt = load_json_strict_bytes(
            self.asset_receipt_raw, label="asset receipt fixture"
        )
        unsigned = copy.deepcopy(receipt)
        del unsigned["contentSHA256"]
        unsigned["models"]["pythia-160m"]["files"]["config.json"]["sha256"] = "0" * 64
        self.asset_receipt_path.write_bytes(
            canonical_json_bytes(with_content_digest(unsigned)) + b"\n"
        )
        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "asset receipt commitment differs"
        ):
            self.build()

    def test_legacy_design_receipt_without_attestation_is_rejected(self) -> None:
        legacy = copy.deepcopy(self.design_receipt)
        del legacy["githubReleaseAttestation"]
        del legacy["contentSHA256"]
        self.design_receipt_path.write_bytes(
            canonical_json_bytes(with_content_digest(legacy)) + b"\n"
        )
        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError,
            "design publication receipt fields differ",
        ):
            self.build()

    def test_created_at_replay_and_post_replay_ledger_are_fail_closed(self) -> None:
        common = {
            "frozen_design_path": self.design_path,
            "corpus_root": self.corpus_root,
            "asset_root": self.asset_root,
            "design_release_asset_root": self.design_release_asset_root,
            "signing_public_key_path": self.signing_public_key_path,
            "design_publication_receipt_path": self.design_receipt_path,
            "asset_source_manifest_path": self.asset_manifest_path,
            "full_asset_receipt_path": self.asset_receipt_path,
            "cryptographic_attestation_verifier": (
                FIXTURE_CRYPTOGRAPHIC_VERIFIER
            ),
        }
        for timestamp in ("2026-08-19T05:59:59Z", "2026-08-20T18:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                SnapshotRegistrationBuildError, "outside the pre-publication window"
            ):
                build_snapshot_registration(created_at=timestamp, **common)

        failed = self.replay_result()
        failed["readyForFreeze"] = False
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ), mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value={model["key"]: object() for model in self.design["models"]},
        ), mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            return_value=failed,
        ), self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "replay is not freeze-ready"
        ):
            self.build()

        project = self.design["futureCorpus"]["projects"][0]

        def mutate_after_replay(
            _root: Path, *, tokenizers: object
        ) -> dict[str, object]:
            self.assertIsNotNone(tokenizers)
            self.ledger_paths[project].write_bytes(b"tampered after replay")
            return self.replay_result()

        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ), mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value={model["key"]: object() for model in self.design["models"]},
        ), mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            side_effect=mutate_after_replay,
        ), self.assertRaisesRegex(SnapshotRegistrationBuildError, "ledger bytes differ"):
            self.build()

    def test_output_is_exclusive_and_noncanonical_design_is_rejected(self) -> None:
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ), mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value={model["key"]: object() for model in self.design["models"]},
        ), mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            return_value=self.replay_result(),
        ):
            raw = build_snapshot_registration_to_path(
                output=self.output,
                frozen_design_path=self.design_path,
                corpus_root=self.corpus_root,
                asset_root=self.asset_root,
                design_release_asset_root=self.design_release_asset_root,
                signing_public_key_path=self.signing_public_key_path,
                design_publication_receipt_path=self.design_receipt_path,
                asset_source_manifest_path=self.asset_manifest_path,
                full_asset_receipt_path=self.asset_receipt_path,
                created_at="2026-08-19T06:30:00Z",
                cryptographic_attestation_verifier=(
                    FIXTURE_CRYPTOGRAPHIC_VERIFIER
                ),
            )
            self.assertEqual(self.output.read_bytes(), raw)
            with self.assertRaisesRegex(
                SnapshotRegistrationBuildError, "output publication failed"
            ):
                build_snapshot_registration_to_path(
                    output=self.output,
                    frozen_design_path=self.design_path,
                    corpus_root=self.corpus_root,
                    asset_root=self.asset_root,
                    design_release_asset_root=self.design_release_asset_root,
                    signing_public_key_path=self.signing_public_key_path,
                    design_publication_receipt_path=self.design_receipt_path,
                    asset_source_manifest_path=self.asset_manifest_path,
                    full_asset_receipt_path=self.asset_receipt_path,
                    created_at="2026-08-19T06:30:00Z",
                    cryptographic_attestation_verifier=(
                        FIXTURE_CRYPTOGRAPHIC_VERIFIER
                    ),
                )
        self.assertEqual(self.output.read_bytes(), raw)

        self.design_path.write_bytes(json.dumps(self.design, indent=2).encode() + b"\n")
        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "not canonical JSON plus LF"
        ):
            self.build()

    def test_owned_tokenizer_loader_cross_checks_receipt_and_is_cli_mandatory(self) -> None:
        model_order = [model["key"] for model in self.design["models"]]
        tokenizer_raw = b'{"version":"unit"}'
        digest = sha256_bytes(tokenizer_raw)
        manifest = {
            "models": {
                key: {
                    "files": {
                        "tokenizer.json": {
                            "bytes": len(tokenizer_raw),
                            "sha256": digest,
                        }
                    }
                }
                for key in model_order
            }
        }
        receipt = {
            "fileCount": 18,
            "totalBytes": 1234,
            "models": {
                key: {
                    "files": {
                        "tokenizer.json": {
                            "bytes": len(tokenizer_raw),
                            "sha256": digest,
                        }
                    }
                }
                for key in model_order
            },
        }
        manifest_raw = b"exact manifest bytes\n"
        verified = SimpleNamespace(
            manifest_sha256=sha256_bytes(manifest_raw),
            file_count=18,
            total_bytes=1234,
            tokenizer_bytes={key: tokenizer_raw for key in model_order},
        )
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_assets_and_load_tokenizer_bytes",
            return_value=verified,
        ) as verify_assets, mock.patch(
            "blind_v1.build_snapshot_registration.default_tokenizer_factory",
            side_effect=lambda key, raw: (key, raw),
        ) as factory:
            observed = _load_verified_tokenizers(
                asset_root=self.asset_root,
                asset_manifest_path=self.asset_manifest_path,
                asset_manifest_raw=manifest_raw,
                asset_manifest=manifest,
                asset_receipt=receipt,
                model_order=model_order,
            )
        verify_assets.assert_called_once_with(
            manifest_path=self.asset_manifest_path,
            expected_manifest_sha256=sha256_bytes(manifest_raw),
            asset_root=self.asset_root,
        )
        self.assertEqual(factory.call_count, len(model_order))
        self.assertEqual(list(observed), model_order)

        argv = [
            "build_snapshot_registration.py",
            "--frozen-design", str(self.design_path),
            "--corpus-root", str(self.corpus_root),
            "--design-release-asset-root", str(self.design_release_asset_root),
            "--signing-public-key", str(self.signing_public_key_path),
            "--design-publication-receipt", str(self.design_receipt_path),
            "--asset-source-manifest", str(self.asset_manifest_path),
            "--full-asset-receipt", str(self.asset_receipt_path),
            "--created-at", "2026-08-19T06:30:00Z",
            "--cosign", str(self.root / "cosign"),
            "--output", str(self.output),
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch(
            "sys.stderr", new=io.StringIO()
        ), self.assertRaises(SystemExit):
            parse_arguments()
        complete = [*argv[:5], "--asset-root", str(self.asset_root), *argv[5:]]
        with mock.patch.object(sys, "argv", complete):
            arguments = parse_arguments()
        self.assertEqual(arguments.cosign, self.root / "cosign")
        cosign_index = complete.index("--cosign")
        without_cosign = complete[:cosign_index] + complete[cosign_index + 2 :]
        with mock.patch.object(sys, "argv", without_cosign), mock.patch(
            "sys.stderr", new=io.StringIO()
        ), self.assertRaises(SystemExit):
            parse_arguments()

    def test_replay_must_report_token_commitments_recomputed(self) -> None:
        replay = self.replay_result()
        replay["tokenCommitmentsRecomputed"] = False
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ), mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value={model["key"]: object() for model in self.design["models"]},
        ), mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            return_value=replay,
        ), self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "replay is not freeze-ready"
        ):
            self.build()

    def test_complete_publication_verifier_is_mandatory(self) -> None:
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            side_effect=ValueError("archived tag signature differs"),
        ) as publication, mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers"
        ) as load_tokenizers, mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot"
        ) as replay, self.assertRaisesRegex(
            SnapshotRegistrationBuildError,
            "failed complete offline verification",
        ):
            self.build()
        publication.assert_called_once()
        load_tokenizers.assert_not_called()
        replay.assert_not_called()

    def test_symlinked_parent_ledgers_and_internal_output_are_rejected(self) -> None:
        linked_parent = self.root / "linked-input-parent"
        linked_parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "contains a symlink"
        ):
            build_snapshot_registration(
                frozen_design_path=linked_parent / self.design_path.name,
                corpus_root=self.corpus_root,
                asset_root=self.asset_root,
                design_release_asset_root=self.design_release_asset_root,
                signing_public_key_path=self.signing_public_key_path,
                design_publication_receipt_path=self.design_receipt_path,
                asset_source_manifest_path=self.asset_manifest_path,
                full_asset_receipt_path=self.asset_receipt_path,
                created_at="2026-08-19T06:30:00Z",
                cryptographic_attestation_verifier=(
                    FIXTURE_CRYPTOGRAPHIC_VERIFIER
                ),
            )

        ledgers = self.corpus_root / "ledgers"
        owned_ledgers = self.corpus_root / "owned-ledgers"
        ledgers.rename(owned_ledgers)
        ledgers.symlink_to(owned_ledgers.name, target_is_directory=True)
        with mock.patch(
            "blind_v1.build_snapshot_registration.verify_publication",
            return_value=self.publication_result(),
        ), mock.patch(
            "blind_v1.build_snapshot_registration._load_verified_tokenizers",
            return_value={model["key"]: object() for model in self.design["models"]},
        ), mock.patch(
            "blind_v1.build_snapshot_registration.verify_corpus_snapshot",
            return_value=self.replay_result(),
        ), self.assertRaisesRegex(
            SnapshotRegistrationBuildError, "contains a symlink"
        ):
            self.build()

        with self.assertRaisesRegex(
            SnapshotRegistrationBuildError,
            "outside the author-verified lab checkout",
        ):
            build_snapshot_registration_to_path(
                output=BLIND_V1_ROOT / ".working/forbidden-snapshot-registration.json",
                frozen_design_path=self.design_path,
                corpus_root=self.corpus_root,
                asset_root=self.asset_root,
                design_release_asset_root=self.design_release_asset_root,
                signing_public_key_path=self.signing_public_key_path,
                design_publication_receipt_path=self.design_receipt_path,
                asset_source_manifest_path=self.asset_manifest_path,
                full_asset_receipt_path=self.asset_receipt_path,
                created_at="2026-08-19T06:30:00Z",
                cryptographic_attestation_verifier=(
                    FIXTURE_CRYPTOGRAPHIC_VERIFIER
                ),
            )


if __name__ == "__main__":
    unittest.main()
