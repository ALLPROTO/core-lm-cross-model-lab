from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

try:
    import numpy as np
except ModuleNotFoundError:  # dependency-free protocol controls still run
    np = None

if np is not None:
    from v3.cache_adapter import (
        build_dynamic_cache,
        flatten_kv_numpy,
        geometry_from_config,
        rebuild_kv_numpy,
        validate_trajectory_layers,
    )
    try:
        import torch
        from transformers import GPTBigCodeConfig, GPTNeoConfig, LlamaConfig
    except ModuleNotFoundError:
        torch = None
else:
    torch = None

from v3.protocol import (
    candidate_bits,
    candidate_configuration,
    canonical_json_bytes,
    decode_output_value,
    evaluate_model_aggregate,
    load_json_strict_bytes,
    resolve_selection,
    sha256_bytes,
    unbiased_draw,
    validate_design_registration,
    validate_design_registration_lifecycle,
    validate_frozen_design_registration,
    validate_ledger,
    validate_model_asset_manifest,
    validate_snapshot_registration,
)


V3_ROOT = Path(__file__).resolve().parents[1]


class ProtocolTests(unittest.TestCase):
    def test_candidate_schedule_extends_without_padding(self) -> None:
        for layers in (12, 20, 24, 32):
            schedule = candidate_bits(layers)
            self.assertEqual(len(schedule), layers)
            self.assertEqual(schedule[0], 9)
            self.assertEqual(schedule[layers // 3], 9)
            self.assertTrue(all(bits == 8 for index, bits in enumerate(schedule) if index not in {0, layers // 3}))
            self.assertEqual(candidate_configuration(layers)["bitsByLayer"], schedule)

    def test_candidate_schedule_rejects_too_few_layers(self) -> None:
        with self.assertRaises(ValueError):
            candidate_bits(2)

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            load_json_strict_bytes(b'{"a":1,"a":2}', label="duplicate fixture")

    def test_strict_json_rejects_lone_surrogates_and_overflow(self) -> None:
        surrogate = '{"value":"\\ud800"}'.encode("ascii")
        with self.assertRaisesRegex(ValueError, "lone surrogate"):
            load_json_strict_bytes(surrogate, label="surrogate fixture")
        with self.assertRaisesRegex(ValueError, "non-finite JSON number"):
            load_json_strict_bytes(b'{"value":1e999}', label="overflow fixture")

    def test_output_value_requires_exact_hex_length(self) -> None:
        self.assertEqual(len(decode_output_value("00" * 64)), 64)
        for invalid in ("00" * 63, "00" * 65, "zz" * 64):
            with self.assertRaises(ValueError):
                decode_output_value(invalid)

    def test_draw_is_deterministic(self) -> None:
        snapshot = b'{"fixture":true}'
        output = bytes(range(64))
        first = unbiased_draw(snapshot, output, draw_index=7, population_size=19)
        second = unbiased_draw(snapshot, output, draw_index=7, population_size=19)
        self.assertEqual(first, second)
        self.assertLess(first["selectedPosition"], 19)

    def test_rejection_sampling_increments_counter(self) -> None:
        class FakeDigest:
            def __init__(self, value: bytes) -> None:
                self.value = value

            def digest(self) -> bytes:
                return self.value

        values = iter((b"\xff" * 64, b"\x00" * 64))
        with patch(
            "v3.protocol.hashlib.sha512",
            side_effect=lambda _: FakeDigest(next(values)),
        ):
            draw = unbiased_draw(
                b'{"fixture":true}',
                bytes(64),
                draw_index=0,
                population_size=3,
            )
        self.assertEqual(draw["counter"], 1)
        self.assertEqual(draw["selectedPosition"], 0)

    def test_ledger_requires_canonical_order(self) -> None:
        records = [
            {"timestamp": "2026-08-16T00:00:02Z", "pageid": 2, "revid": 2},
            {"timestamp": "2026-08-16T00:00:01Z", "pageid": 1, "revid": 1},
        ] * 8
        with self.assertRaises(ValueError):
            validate_ledger("example.invalid", records)

    def test_ledger_rejects_duplicate_revision_or_page(self) -> None:
        vector = json.loads(
            (V3_ROOT / "test-vectors" / "selection-v1.json").read_text()
        )
        records = copy.deepcopy(vector["ledgers"]["de.wikipedia.org"])
        records[-1]["revid"] = records[0]["revid"]
        with self.assertRaisesRegex(ValueError, "duplicate revision"):
            validate_ledger("de.wikipedia.org", records)
        records = copy.deepcopy(vector["ledgers"]["de.wikipedia.org"])
        records[-1]["pageid"] = records[0]["pageid"]
        with self.assertRaisesRegex(ValueError, "two revisions for one page"):
            validate_ledger("de.wikipedia.org", records)

    def test_normative_ledger_size_and_time_window_are_enforced(self) -> None:
        vector = json.loads(
            (V3_ROOT / "test-vectors" / "selection-v1.json").read_text()
        )
        records = vector["ledgers"]["de.wikipedia.org"]
        with self.assertRaisesRegex(ValueError, "at least 64 records"):
            validate_ledger(
                "de.wikipedia.org",
                records,
                minimum_records=64,
                timestamp_start=datetime(2026, 8, 16, tzinfo=timezone.utc),
                timestamp_end=datetime(2026, 8, 30, tzinfo=timezone.utc),
            )
        expanded = [
            {
                "timestamp": f"2026-08-16T00:{index // 60:02d}:{index % 60:02d}Z",
                "pageid": index + 1,
                "revid": index + 1,
            }
            for index in range(64)
        ]
        expanded[-1]["timestamp"] = "2026-08-30T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "outside the corpus interval"):
            validate_ledger(
                "de.wikipedia.org",
                expanded,
                minimum_records=64,
                timestamp_start=datetime(2026, 8, 16, tzinfo=timezone.utc),
                timestamp_end=datetime(2026, 8, 30, tzinfo=timezone.utc),
            )

    def test_known_answer_selection(self) -> None:
        vector = json.loads(
            (V3_ROOT / "test-vectors" / "selection-v1.json").read_text()
        )
        snapshot = canonical_json_bytes(vector["snapshotRegistration"])
        selection = resolve_selection(
            snapshot,
            vector["nistOutputValue"],
            projects=vector["projects"],
            models=vector["models"],
            ledgers=vector["ledgers"],
            allow_fixture=True,
        )
        self.assertEqual(
            sha256_bytes(canonical_json_bytes(selection)),
            vector["expectedSelectionSHA256"],
        )
        self.assertEqual(selection["draws"][0], vector["expectedFirstDraw"])
        self.assertEqual(selection["draws"][-1], vector["expectedLastDraw"])
        self.assertEqual(len(selection["selectedCorpora"]), 2)
        self.assertEqual(len(selection["modelExecutionOrder"]), 3)
        self.assertEqual(len(selection["draws"]), 36)
        self.assertEqual(
            len({tuple(item.values()) for pages in selection["selectedPages"].values() for item in pages}),
            32,
        )

    def test_snapshot_fixture_is_denied_by_normative_default(self) -> None:
        vector = json.loads(
            (V3_ROOT / "test-vectors" / "selection-v1.json").read_text()
        )
        with self.assertRaisesRegex(ValueError, "fixture is forbidden"):
            resolve_selection(
                canonical_json_bytes(vector["snapshotRegistration"]),
                vector["nistOutputValue"],
                projects=vector["projects"],
                models=vector["models"],
                ledgers=vector["ledgers"],
            )

    def test_normative_snapshot_binds_caller_projects_and_models(self) -> None:
        vector = json.loads(
            (V3_ROOT / "test-vectors" / "selection-v1.json").read_text()
        )
        snapshot = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-snapshot-registration-v1",
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
            "status": "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION",
            "designPublicationReceiptSHA256": "3" * 64,
            "snapshotReleasePlan": {
                "tag": "corelm-crossmodel-livewiki-v3-snapshot",
                "publishNoLaterThan": "2026-09-01T18:00:00Z",
                "serverTimestampRequired": True,
                "immutableReleaseRequired": True,
                "signedAnnotatedTagRequired": True,
            },
            "projects": vector["projects"],
            "models": vector["models"],
            "ledgers": {project: "4" * 64 for project in vector["projects"]},
            "modelAssetSourceManifestSHA256": "5" * 64,
            "fullAssetReceiptSHA256": "7" * 64,
            "corpusManifestSHA256": "6" * 64,
            "createdAt": "2026-08-31T06:30:00Z",
        }
        validate_snapshot_registration(snapshot, allow_fixture=False)
        invalid_receipt = copy.deepcopy(snapshot)
        invalid_receipt["designPublicationReceiptSHA256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "invalid digest"):
            validate_snapshot_registration(invalid_receipt, allow_fixture=False)
        before_second_crawl = copy.deepcopy(snapshot)
        before_second_crawl["createdAt"] = "2026-08-31T05:59:59Z"
        with self.assertRaisesRegex(
            ValueError, "before the second registered crawl"
        ):
            validate_snapshot_registration(before_second_crawl, allow_fixture=False)
        after_release_deadline = copy.deepcopy(snapshot)
        after_release_deadline["createdAt"] = "2026-09-01T18:00:01Z"
        with self.assertRaisesRegex(
            ValueError, "after its registered release deadline"
        ):
            validate_snapshot_registration(after_release_deadline, allow_fixture=False)
        snapshot_bytes = canonical_json_bytes(snapshot)
        with self.assertRaisesRegex(ValueError, "caller projects differ"):
            resolve_selection(
                snapshot_bytes,
                vector["nistOutputValue"],
                projects=["x.example", "y.example", "z.example"],
                models=vector["models"],
                ledgers=vector["ledgers"],
            )
        with self.assertRaisesRegex(ValueError, "caller models differ"):
            resolve_selection(
                snapshot_bytes,
                vector["nistOutputValue"],
                projects=vector["projects"],
                models=["model-a", "model-b", "model-c"],
                ledgers=vector["ledgers"],
            )

    def test_normative_snapshot_rejects_old_self_referential_release_form(self) -> None:
        def release(tag: str, published_at: str) -> dict[str, str]:
            return {
                "tag": tag,
                "commit": "1" * 40,
                "tree": "2" * 40,
                "publishedAt": published_at,
                "freezeManifestSHA256": "3" * 64,
            }

        old_snapshot = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-snapshot-registration-v1",
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
            "status": "PUBLIC_SNAPSHOT_FROZEN",
            "designRelease": release(
                "corelm-crossmodel-livewiki-v3-design", "2026-08-14T12:00:00Z"
            ),
            "snapshotRelease": release(
                "corelm-crossmodel-livewiki-v3-snapshot", "2026-08-31T07:00:00Z"
            ),
            "projects": [
                "de.wikipedia.org",
                "en.wikipedia.org",
                "fr.wikipedia.org",
            ],
            "models": [
                "gpt-neo-125m",
                "smollm2-360m",
                "tiny-starcoder-py",
            ],
            "ledgers": {
                "de.wikipedia.org": "4" * 64,
                "en.wikipedia.org": "4" * 64,
                "fr.wikipedia.org": "4" * 64,
            },
            "modelAssetManifestSHA256": "5" * 64,
            "corpusManifestSHA256": "6" * 64,
            "createdAt": "2026-08-31T06:30:00Z",
        }
        with self.assertRaisesRegex(ValueError, "registration fields differ"):
            validate_snapshot_registration(old_snapshot, allow_fixture=False)

    def test_normative_selection_authenticates_exact_ledger_bytes(self) -> None:
        projects = [
            "de.wikipedia.org",
            "en.wikipedia.org",
            "fr.wikipedia.org",
        ]
        models = ["gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py"]
        ledger_bytes: dict[str, bytes] = {}
        for project_index, project in enumerate(projects):
            records = [
                {
                    "timestamp": f"2026-08-16T00:{index // 60:02d}:{index % 60:02d}Z",
                    "pageid": 100000 * (project_index + 1) + index + 1,
                    "revid": 200000 * (project_index + 1) + index + 1,
                }
                for index in range(64)
            ]
            ledger_bytes[project] = canonical_json_bytes(records)

        snapshot = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-snapshot-registration-v1",
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
            "status": "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION",
            "designPublicationReceiptSHA256": "3" * 64,
            "snapshotReleasePlan": {
                "tag": "corelm-crossmodel-livewiki-v3-snapshot",
                "publishNoLaterThan": "2026-09-01T18:00:00Z",
                "serverTimestampRequired": True,
                "immutableReleaseRequired": True,
                "signedAnnotatedTagRequired": True,
            },
            "projects": projects,
            "models": models,
            "ledgers": {
                project: sha256_bytes(value) for project, value in ledger_bytes.items()
            },
            "modelAssetSourceManifestSHA256": "5" * 64,
            "fullAssetReceiptSHA256": "7" * 64,
            "corpusManifestSHA256": "6" * 64,
            "createdAt": "2026-08-31T06:30:00Z",
        }
        snapshot_bytes = canonical_json_bytes(snapshot)
        selection = resolve_selection(
            snapshot_bytes,
            "00" * 64,
            projects=projects,
            models=models,
            ledgers=ledger_bytes,
        )
        self.assertEqual(len(selection["draws"]), 36)

        substituted = dict(ledger_bytes)
        parsed = json.loads(substituted[projects[0]])
        parsed[-1]["pageid"] += 1
        substituted[projects[0]] = canonical_json_bytes(parsed)
        with self.assertRaisesRegex(ValueError, "ledger commitment mismatch"):
            resolve_selection(
                snapshot_bytes,
                "00" * 64,
                projects=projects,
                models=models,
                ledgers=substituted,
            )
        with self.assertRaisesRegex(ValueError, "must be supplied as exact bytes"):
            resolve_selection(
                snapshot_bytes,
                "00" * 64,
                projects=projects,
                models=models,
                ledgers={
                    project: json.loads(value)
                    for project, value in ledger_bytes.items()
                },
                allow_fixture=True,
            )

    def test_model_aggregate_gates_are_executable(self) -> None:
        passing = evaluate_model_aggregate([0.0] * 32, [128] * 32)
        self.assertTrue(passing["pass"])
        self.assertLessEqual(passing["deltaUpper"], 0.01)
        self.assertGreaterEqual(passing["wilsonLower"], 0.99)
        failing = evaluate_model_aggregate([0.02] * 32, [126] * 32)
        self.assertFalse(failing["pass"])

    def test_freeze_status_cannot_be_enabled_by_deleting_blocker_strings(self) -> None:
        registration = json.loads(
            (V3_ROOT / "design-registration.draft.json").read_text()
        )
        registration["status"] = "FREEZE_CANDIDATE_NOT_PUBLISHED"
        registration["readyToFreeze"] = True
        registration["freezeBlockers"] = []
        with self.assertRaisesRegex(ValueError, "fail-closed"):
            validate_design_registration(registration)

    def test_design_remains_explicitly_not_freezable(self) -> None:
        registration = json.loads(
            (V3_ROOT / "design-registration.draft.json").read_text()
        )
        blockers = validate_design_registration(registration)
        self.assertFalse(registration["readyToFreeze"])
        self.assertFalse(registration["countsTowardScientificVerdict"])
        self.assertGreaterEqual(len(blockers), 1)
        self.assertTrue(
            any(
                "UD English PUD" in blocker
                and "CC BY-SA 3.0" in blocker
                for blocker in blockers
            )
        )

    def test_frozen_design_lifecycle_reuses_every_normative_body_check(self) -> None:
        frozen = json.loads(
            (V3_ROOT / "design-registration.draft.json").read_text()
        )
        frozen.update(
            schemaVersion="corelm-crossmodel-livewiki-v3-design-v1",
            status="PUBLIC_DESIGN_FROZEN",
            readyToFreeze=True,
            freezeBlockers=[],
        )
        frozen["labSource"].update(
            status="FROZEN_BOUND",
            commit="1" * 40,
            tree="2" * 40,
            freezeManifestSHA256="3" * 64,
        )
        frozen["runtime"].update(
            status="FROZEN_BOUND", runtimeManifestSHA256="4" * 64
        )
        frozen["developmentControls"]["realDataE2EFreezeGate"].update(
            status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
            executionId="development-execution-20260814T100000Z-0123456789abcdef",
            archiveReceiptSHA256="7" * 64,
            archivePublishedAt="2026-08-14T10:05:00Z",
            archiveAttestedAt="2026-08-14T10:05:01Z",
            releaseAttestationBundleSHA256="b" * 64,
            releaseAttestationOutputSHA256="c" * 64,
            reportSHA256="8" * 64,
            artifactSetSHA256="9" * 64,
            controlConfigurationSHA256="a" * 64,
            completedAt="2026-08-14T10:00:00Z",
        )
        frozen["beacon"].update(
            transportCABundleSHA256="5" * 64,
            offlineTrustBundleSHA256="6" * 64,
        )
        self.assertEqual(validate_frozen_design_registration(frozen), [])
        self.assertEqual(validate_design_registration_lifecycle(frozen), [])
        mutated = copy.deepcopy(frozen)
        mutated["candidate"]["groupSize"] = 64
        with self.assertRaisesRegex(ValueError, "candidate boundary"):
            validate_frozen_design_registration(mutated)
        mutated = copy.deepcopy(frozen)
        mutated["runtime"]["runtimeManifestSHA256"] = None
        with self.assertRaisesRegex(ValueError, "runtime manifest"):
            validate_frozen_design_registration(mutated)
        mutated = copy.deepcopy(frozen)
        mutated["developmentControls"]["realDataE2EFreezeGate"][
            "archiveAttestedAt"
        ] = "2026-08-15T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "archive timing"):
            validate_frozen_design_registration(mutated)

    def test_design_validator_binds_normative_fields(self) -> None:
        original = json.loads(
            (V3_ROOT / "design-registration.draft.json").read_text()
        )
        mutations = (
            ("", "claim", "transfers to all language models"),
            ("cellGates", "minimumTop1Agreement", 0.5),
            ("execution", "device", "cuda"),
            ("beacon", "targetUnixMilliseconds", 0),
            ("candidate", "groupSize", 64),
            ("selection", "allModelsRequired", False),
            ("snapshotRelease", "sourcePolicy", "ALLOW_LATER_COMMIT"),
            ("modelAggregateGates", "minimumWilsonLower", 0.5),
            ("continuousIntegration", "workflowFileSHA256", "0" * 64),
            ("developmentControls", "syntheticInputsForbidden", False),
        )
        for section, field, value in mutations:
            registration = copy.deepcopy(original)
            if section:
                registration[section][field] = value
            else:
                registration[field] = value
            with self.assertRaises(ValueError):
                validate_design_registration(registration)
        registration = copy.deepcopy(original)
        registration["execution"]["independentModelReplay"][
            "fixtureBackendScientificUse"
        ] = "allowed"
        with self.assertRaisesRegex(ValueError, "execution boundary"):
            validate_design_registration(registration)
        registration = copy.deepcopy(original)
        registration["futureCorpus"]["prospectiveHoldout"][
            "operatorBlindnessClaimed"
        ] = True
        with self.assertRaisesRegex(ValueError, "future corpus boundary"):
            validate_design_registration(registration)

    def test_model_asset_manifest_matches_design(self) -> None:
        registration = json.loads(
            (V3_ROOT / "design-registration.draft.json").read_text()
        )
        manifest = json.loads((V3_ROOT / "model-assets.draft.json").read_text())
        summary = validate_model_asset_manifest(manifest, registration)
        self.assertEqual(summary["models"], 3)
        self.assertEqual(summary["runtimeFiles"], 24)
        self.assertEqual(summary["smallFilesContentHashed"], 21)
        self.assertFalse(summary["fullSafetensorsBytesLocallyVerified"])


@unittest.skipIf(np is None, "locked benchmark runtime with NumPy is unavailable")
class CacheAdapterTests(unittest.TestCase):
    CONFIGS = {
        "gpt-neo-125m": {
            "model_type": "gpt_neo",
            "num_layers": 12,
            "num_heads": 12,
            "hidden_size": 768,
        },
        "smollm2-360m": {
            "model_type": "llama",
            "num_hidden_layers": 32,
            "num_attention_heads": 15,
            "num_key_value_heads": 5,
            "hidden_size": 960,
        },
        "tiny-starcoder-py": {
            "model_type": "gpt_bigcode",
            "n_layer": 20,
            "n_head": 12,
            "n_embd": 768,
            "multi_query": True,
        },
    }

    def test_registered_geometries(self) -> None:
        expected = {
            "gpt-neo-125m": (12, 12, 64, 1536),
            "smollm2-360m": (32, 5, 64, 640),
            "tiny-starcoder-py": (20, 1, 64, 128),
        }
        for key, config in self.CONFIGS.items():
            geometry = geometry_from_config(config)
            self.assertEqual(
                (
                    geometry["layers"],
                    geometry["kvHeads"],
                    geometry["headDimension"],
                    geometry["trajectoryWidth"],
                ),
                expected[key],
            )

    def test_layout_round_trip_for_every_registered_architecture(self) -> None:
        tokens = 7
        for config in self.CONFIGS.values():
            geometry = geometry_from_config(config)
            shape = (
                1,
                int(geometry["kvHeads"]),
                tokens,
                int(geometry["headDimension"]),
            )
            keys = np.arange(np.prod(shape), dtype=np.float32).reshape(shape)
            values = keys + np.float32(0.25)
            trajectory = flatten_kv_numpy(keys, values, geometry, tokens=tokens)
            rebuilt_keys, rebuilt_values = rebuild_kv_numpy(
                trajectory, geometry, tokens=tokens
            )
            np.testing.assert_array_equal(rebuilt_keys, keys)
            np.testing.assert_array_equal(rebuilt_values, values)

    def test_variable_layer_count_is_enforced(self) -> None:
        geometry = geometry_from_config(self.CONFIGS["gpt-neo-125m"])
        layer = np.zeros((3, int(geometry["trajectoryWidth"])), dtype=np.float32)
        validate_trajectory_layers([layer.copy() for _ in range(12)], geometry, tokens=3)
        with self.assertRaisesRegex(ValueError, "layer count mismatch"):
            validate_trajectory_layers([layer.copy() for _ in range(11)], geometry, tokens=3)

    def test_gpt_bigcode_mqa_is_not_misclassified_as_mha(self) -> None:
        geometry = geometry_from_config(self.CONFIGS["tiny-starcoder-py"])
        self.assertEqual(geometry["attentionHeads"], 12)
        self.assertEqual(geometry["kvHeads"], 1)
        self.assertEqual(geometry["attentionLayout"], "multi-query")

    @unittest.skipIf(torch is None, "locked Torch/Transformers runtime is unavailable")
    def test_transformers_dynamic_cache_accepts_every_layer_geometry(self) -> None:
        configs = (
            GPTNeoConfig(
                num_layers=12,
                num_heads=12,
                hidden_size=768,
                attention_types=[[['global', 'local'], 6]],
            ),
            LlamaConfig(
                num_hidden_layers=32,
                num_attention_heads=15,
                num_key_value_heads=5,
                hidden_size=960,
            ),
            GPTBigCodeConfig(
                n_layer=20,
                n_head=12,
                n_embd=768,
                multi_query=True,
            ),
        )
        for mapping, config in zip(self.CONFIGS.values(), configs):
            geometry = geometry_from_config(mapping)
            layers = [
                np.zeros((3, int(geometry["trajectoryWidth"])), dtype=np.float32)
                for _ in range(int(geometry["layers"]))
            ]
            cache = build_dynamic_cache(
                layers,
                geometry,
                model_config=config,
                device="cpu",
                torch_module=torch,
                tokens=3,
            )
            self.assertEqual(len(cache.layers), int(geometry["layers"]))
            self.assertEqual(int(cache.get_seq_length()), 3)


if __name__ == "__main__":
    unittest.main()
