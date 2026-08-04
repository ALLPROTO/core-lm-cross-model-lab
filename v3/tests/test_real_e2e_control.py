from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from v3 import development_corpus as records
from v3 import development_model_replay as independent
from v3 import model_worker
from v3 import run_real_e2e_control as control
from v3 import runner as scientific_runner
from v3.protocol import EXPECTED_DEVELOPMENT_CONTROLS, canonical_json_bytes


FALSE_BOUNDARY_FIELDS = (
    "countsTowardScientificVerdict",
    "usedForCandidateSelectionOrTuning",
    "scientificAttemptStateCreated",
    "nistUsed",
    "futureCorpusUsed",
)
HEX_A = "1" * 64
TEMPORARY_PARENT = Path(tempfile.gettempdir()).resolve(strict=True)


def _digest_record() -> dict[str, object]:
    return {"bytes": 1, "sha256": HEX_A}


def _digest_bytes(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _model_bindings() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    models: list[dict[str, object]] = []
    inventory: list[dict[str, object]] = []
    for model_key in independent.MODELS:
        identity = independent.EXPECTED_MODEL_IDENTITIES[model_key]
        files: dict[str, dict[str, object]] = {}
        for filename in independent.MODEL_FILES:
            path = f"models/{model_key}/{filename}"
            expected_bytes, expected_sha256 = model_worker.DEVELOPMENT_MODEL_BINDINGS[
                model_key
            ]["files"][filename]
            commitment = {"bytes": expected_bytes, "sha256": expected_sha256}
            specification = {"path": path, **commitment}
            files[filename] = specification
            inventory.append({**specification, "role": "model-asset"})
        layers = identity["layers"]
        models.append(
            {
                "key": model_key,
                "repository": identity["repository"],
                "revision": identity["revision"],
                "layers": layers,
                "vocabSize": identity["vocabSize"],
                "candidateBitsByLayer": [
                    9 if index in {0, layers // 3} else 8
                    for index in range(layers)
                ],
                "files": files,
            }
        )
    return models, inventory


def _execution() -> dict[str, object]:
    value = dict(independent.EXPECTED_EXECUTION)
    del value["modelsSequential"]
    return value


def _input_bindings() -> dict[str, object]:
    archival = _archival_inputs()
    return {
        "designRegistration": _digest_bytes(archival["design-registration.draft.json"]),
        "modelAssetManifest": _digest_bytes(archival["model-assets.draft.json"]),
        "fullAssetReceipt": _digest_bytes(
            archival["model-assets.full-rehash.json"]
        ),
        "developmentCorpusManifest": _digest_bytes(
            archival["development-corpus.draft.json"]
        ),
        "licenseSourceEvidence": _digest_bytes(
            archival["LICENSES/source-evidence.json"]
        ),
        "assetLicenseMatrix": _digest_bytes(
            archival["LICENSES/ASSET_LICENSES.md"]
        ),
        "udEnglishPudReadme": _digest_bytes(
            archival["LICENSES/upstream/ud-english-pud-r2.18-README.md"]
        ),
        "udEnglishPudLicense": _digest_bytes(
            archival["LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"]
        ),
        "udEnglishPudAttribution": _digest_bytes(
            archival["LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"]
        ),
        "developmentDataset": {
            "bytes": independent.DATASET_BYTES,
            "sha256": independent.DATASET_SHA256,
        },
        "runtimeManifest": _digest_bytes(archival["runtime-manifest.json"]),
        "labSource": {
            "repository": "https://github.com/ALLPROTO/core-lm-cross-model-lab.git",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "worktreeClean": True,
        },
        "joinedCorpusText": {
            "bytes": independent.JOINED_DATASET_BYTES,
            "sha256": independent.JOINED_DATASET_SHA256,
        },
        "conlluDecode": {
            "parser": "strict-stdlib-conllu-text-v1",
            "sentences": independent.DATASET_ROWS,
            "sourceConlluSHA256": independent.DATASET_SHA256,
        },
        "codecSource": copy.deepcopy(independent.EXPECTED_CODEC_SOURCE),
        "controlSources": [
            {"path": path, **_digest_record()}
            for path in independent.CONTROL_SOURCE_PATHS
        ],
        "adapter": dict(control.ADAPTER),
    }


def _archival_inputs() -> dict[str, bytes]:
    return {
        "design-registration.draft.json": (
            control.V3_ROOT / "design-registration.draft.json"
        ).read_bytes(),
        "model-assets.draft.json": (
            control.V3_ROOT / "model-assets.draft.json"
        ).read_bytes(),
        "model-assets.full-rehash.json": (
            control.V3_ROOT / "manifests" / "model-assets.full-rehash.json"
        ).read_bytes(),
        "development-corpus.draft.json": (
            control.V3_ROOT / "development-corpus.draft.json"
        ).read_bytes(),
        "LICENSES/source-evidence.json": (
            control.PROJECT_ROOT / "LICENSES" / "source-evidence.json"
        ).read_bytes(),
        "LICENSES/ASSET_LICENSES.md": (
            control.PROJECT_ROOT / "LICENSES" / "ASSET_LICENSES.md"
        ).read_bytes(),
        "LICENSES/upstream/ud-english-pud-r2.18-README.md": (
            control.PROJECT_ROOT
            / "LICENSES"
            / "upstream"
            / "ud-english-pud-r2.18-README.md"
        ).read_bytes(),
        "LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt": (
            control.PROJECT_ROOT
            / "LICENSES"
            / "upstream"
            / "ud-english-pud-r2.18-LICENSE.txt"
        ).read_bytes(),
        "LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md": (
            control.PROJECT_ROOT
            / "LICENSES"
            / "UD_ENGLISH_PUD_ATTRIBUTION.md"
        ).read_bytes(),
        "runtime-manifest.json": b"{\"unitFixture\":true}\n",
    }


def _rehash_plan(plan: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(plan)
    value.pop("contentSHA256", None)
    return control._with_content_digest(value)


def _fixture_sentences() -> list[str]:
    return [
        f"real PUD-format source sentence {index:04d}"
        for index in range(independent.DATASET_ROWS)
    ]


def _build_lightweight_plan(
    private_root: Path,
) -> tuple[dict[str, object], dict[str, bytes]]:
    models, inventory = _model_bindings()
    with mock.patch.object(
        control,
        "_link_model_assets",
        return_value=(models, inventory),
    ):
        return control.build_plan(
            design={"execution": _execution()},
            receipt={},
            asset_root=private_root / "unused-assets",
            private_root=private_root,
            sentences=_fixture_sentences(),
            input_bindings=_input_bindings(),
        )


class RealE2EDevelopmentBoundaryTests(unittest.TestCase):
    def test_model_assets_are_streamed_under_their_exact_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            root = Path(temporary)
            asset_root = root / "assets"
            private_root = root / "private"
            model_root = asset_root / "fixture-model"
            model_root.mkdir(parents=True)
            private_root.mkdir()
            raw = b"exact model bytes"
            (model_root / "model.safetensors").write_bytes(raw)
            commitment = _digest_bytes(raw)
            design = {
                "models": [
                    {
                        "key": "fixture-model",
                        "repository": "fixture/repository",
                        "revision": "1" * 40,
                        "layers": 1,
                        "vocabSize": 8,
                        "candidateBitsByLayer": [9],
                    }
                ]
            }
            receipt = {
                "models": {
                    "fixture-model": {
                        "files": {"model.safetensors": commitment}
                    }
                }
            }
            with mock.patch.object(
                control, "MODEL_FILES", ("model.safetensors",)
            ), mock.patch.object(
                control,
                "_read_regular",
                side_effect=AssertionError("model asset must be streamed"),
            ):
                models, inventory = control._link_model_assets(
                    private_root=private_root,
                    asset_root=asset_root,
                    receipt=receipt,
                    design=design,
                )
            expected = {
                "path": "models/fixture-model/model.safetensors",
                **commitment,
            }
            self.assertEqual(models[0]["files"]["model.safetensors"], expected)
            self.assertEqual(inventory, [{**expected, "role": "model-asset"}])

            oversized_private_root = root / "oversized-private"
            oversized_private_root.mkdir()
            oversized_receipt = copy.deepcopy(receipt)
            oversized_receipt["models"]["fixture-model"]["files"][
                "model.safetensors"
            ]["bytes"] -= 1
            with mock.patch.object(
                control, "MODEL_FILES", ("model.safetensors",)
            ), self.assertRaisesRegex(
                control.DevelopmentControlError, "exact byte bound"
            ):
                control._link_model_assets(
                    private_root=oversized_private_root,
                    asset_root=asset_root,
                    receipt=oversized_receipt,
                    design=design,
                )

    def test_exact_real_dataset_identity_is_consistent_everywhere(self) -> None:
        expected = {
            "datasetId": "UniversalDependencies/UD_English-PUD:r2.18:test",
            "repository": "UniversalDependencies/UD_English-PUD",
            "revision": "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
            "tree": "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde",
            "releaseTag": "r2.18",
            "split": "test",
            "splitPurpose": (
                "upstream test split reused only as a non-scientific development "
                "control; it is not a blind scientific test result"
            ),
            "file": "en_pud-ud-test.conllu",
            "format": "CoNLL-U",
            "bytes": 1_386_858,
            "sha256": (
                "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa"
            ),
            "rows": 1_000,
            "rowExtraction": (
                "exactly one '# text = ' value from each LF-delimited CoNLL-U "
                "sentence block; prefix removed; text otherwise unchanged"
            ),
            "joinedTextBytes": 112_419,
            "joinedTextSHA256": (
                "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea"
            ),
            "license": "CC-BY-SA-3.0",
            "manifestPath": "v3/development-corpus.draft.json",
            "manifestBytes": 1_985,
            "manifestSHA256": (
                "b18149b73be0bb2510759c8ca567c4ab0a9f04f7960eb4c6a44b6eedfbda9634"
            ),
        }
        self.assertEqual(EXPECTED_DEVELOPMENT_CONTROLS["dataset"], expected)
        self.assertEqual(records.DATASET_ID, expected["datasetId"])
        self.assertEqual(records.REPOSITORY, expected["repository"])
        self.assertEqual(records.REVISION, expected["revision"])
        self.assertEqual(records.TREE, expected["tree"])
        self.assertEqual(records.RELEASE_TAG, expected["releaseTag"])
        self.assertEqual(records.SPLIT, expected["split"])
        self.assertEqual(records.FILE, expected["file"])
        self.assertEqual(records.FORMAT, expected["format"])
        self.assertEqual(records.SOURCE_BYTES, expected["bytes"])
        self.assertEqual(records.SOURCE_SHA256, expected["sha256"])
        self.assertEqual(records.SENTENCE_COUNT, expected["rows"])
        self.assertEqual(records.JOINED_TEXT_BYTES, expected["joinedTextBytes"])
        self.assertEqual(
            records.JOINED_TEXT_SHA256, expected["joinedTextSHA256"]
        )
        self.assertEqual(independent.DATASET_ID, expected["datasetId"])
        self.assertEqual(model_worker.DEVELOPMENT_DATASET_ID, expected["datasetId"])
        self.assertEqual(independent.CORPORA, (expected["datasetId"],))
        self.assertEqual(
            control.ADAPTER,
            {
                "source": "pinned-ud-english-pud-r2.18-test-conllu",
                "sentenceText": "exact-single-#-text-comment-per-block",
                "join": "two-LF-between-sentence-texts-within-each-slice",
                "partition": "all-source-sentences-equal-floor-boundaries-32",
                "partitions": 32,
                "records": 32,
                "contentSynthetic": False,
                "metadataEnvelopeScientificUse": "forbidden",
            },
        )
        self.assertEqual(len(_archival_inputs()), 10)
        self.assertEqual(len(_input_bindings()), 17)

    def test_pud_rights_evidence_is_exact_and_tamper_evident(self) -> None:
        archival = _archival_inputs()
        source_evidence = json.loads(
            archival["LICENSES/source-evidence.json"].decode("utf-8")
        )
        readme = archival[
            "LICENSES/upstream/ud-english-pud-r2.18-README.md"
        ]
        license_raw = archival[
            "LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
        ]
        attribution = archival[
            "LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"
        ]

        self.assertEqual(
            records.verify_rights_evidence(
                source_evidence, readme, license_raw, attribution
            ),
            records.RIGHTS_STATUS,
        )
        matrix = archival["LICENSES/ASSET_LICENSES.md"].decode(
            "utf-8", errors="strict"
        )
        self.assertIn("UD English PUD", matrix)
        self.assertIn("CC BY-SA 3.0", matrix)
        self.assertIn("without added restrictions", matrix)

        forged_source = copy.deepcopy(source_evidence)
        pud_source = next(
            item
            for item in forged_source["sources"]
            if item.get("component") == records.README_COMPONENT
        )
        pud_source["sha256"] = "0" * 64
        for label, evidence, readme_raw, license_value, attribution_raw in (
            (
                "source commitment",
                forged_source,
                readme,
                license_raw,
                attribution,
            ),
            (
                "upstream README",
                source_evidence,
                readme + b"A",
                license_raw,
                attribution,
            ),
            (
                "upstream license",
                source_evidence,
                readme,
                license_raw + b"A",
                attribution,
            ),
            (
                "attribution",
                source_evidence,
                readme,
                license_raw,
                attribution + b"A",
            ),
        ):
            with self.subTest(label=label), self.assertRaises(
                records.DevelopmentCorpusError
            ):
                records.verify_rights_evidence(
                    evidence, readme_raw, license_value, attribution_raw
                )

    def test_real_sentences_strict_fixture_parser_without_models(self) -> None:
        blocks = []
        expected_sentences = []
        for index in range(records.SENTENCE_COUNT):
            sentence = f"PUD-format fixture sentence {index:04d}."
            expected_sentences.append(sentence)
            blocks.append(
                (
                    f"# sent_id = fixture-{index:04d}\n"
                    f"# text = {sentence}\n"
                    "1\tFixture\t_\tNOUN\t_\t_\t0\troot\t_\t_"
                ).encode("utf-8")
            )
        raw = b"\n\n".join(blocks) + b"\n\n"
        joined = "\n\n".join(expected_sentences).encode("utf-8")
        with mock.patch.multiple(
            records,
            SOURCE_BYTES=len(raw),
            SOURCE_SHA256=hashlib.sha256(raw).hexdigest(),
            JOINED_TEXT_BYTES=len(joined),
            JOINED_TEXT_SHA256=hashlib.sha256(joined).hexdigest(),
        ):
            sentences, evidence = control._real_sentences(raw)
            self.assertEqual(sentences, expected_sentences)
            self.assertEqual(
                evidence,
                {
                    **_digest_bytes(joined),
                    "parser": "strict-stdlib-conllu-text-v1",
                    "sentences": records.SENTENCE_COUNT,
                    "sourceConlluSHA256": hashlib.sha256(raw).hexdigest(),
                },
            )
            with self.assertRaises(control.DevelopmentControlError):
                control._real_sentences(raw + b"\n")

    def test_record_building_and_parsing_preserve_sentence_ranges(self) -> None:
        sentences = _fixture_sentences()
        with tempfile.TemporaryDirectory(
            dir=TEMPORARY_PARENT
        ) as first, tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as second:
            first_pages, first_inventory = control._write_private_records(
                Path(first), sentences
            )
            second_pages, second_inventory = control._write_private_records(
                Path(second), sentences
            )

            self.assertEqual(first_pages, second_pages)
            self.assertEqual(first_inventory, second_inventory)
            pages = first_pages[records.DATASET_ID]
            self.assertEqual(len(pages), control.PARTITIONS)
            self.assertEqual(pages[0]["sentenceStart"], 0)
            self.assertEqual(pages[-1]["sentenceEnd"], len(sentences))
            for index, page in enumerate(pages):
                with self.subTest(index=index):
                    self.assertEqual(
                        page["recordPath"],
                        f"records/ud-english-pud/slice-{index:02d}.bin",
                    )
                    raw = (Path(first) / page["recordPath"]).read_bytes()
                    duplicate = (Path(second) / page["recordPath"]).read_bytes()
                    parsed = records.parse_record(raw)
                    self.assertEqual(raw, duplicate)
                    self.assertEqual(parsed["datasetId"], records.DATASET_ID)
                    self.assertEqual(
                        parsed["sentenceStart"], page["sentenceStart"]
                    )
                    self.assertEqual(parsed["sentenceEnd"], page["sentenceEnd"])
                    self.assertEqual(
                        parsed["content"],
                        "\n\n".join(
                            sentences[
                                page["sentenceStart"] : page["sentenceEnd"]
                            ]
                        ),
                    )
                    if index:
                        self.assertEqual(
                            page["sentenceStart"],
                            pages[index - 1]["sentenceEnd"],
                        )
            self.assertTrue(
                all(
                    item["role"] == "development-corpus-record"
                    for item in first_inventory
                )
            )

        canonical = records.serialize_record(
            sentence_start=10,
            sentence_end=20,
            content="real-format sentence slice",
        )
        self.assertEqual(
            canonical,
            records.serialize_record(
                sentence_start=10,
                sentence_end=20,
                content="real-format sentence slice",
            ),
        )
        with self.assertRaises(records.DevelopmentCorpusError):
            records.parse_record(canonical + b"x")

    def test_plan_jobs_and_run_id_are_deterministic_and_non_scientific(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=TEMPORARY_PARENT
        ) as first, tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as second:
            first_plan, first_jobs = _build_lightweight_plan(Path(first))
            second_plan, second_jobs = _build_lightweight_plan(Path(second))

        self.assertEqual(first_plan, second_plan)
        self.assertEqual(first_jobs, second_jobs)
        self.assertEqual(first_plan["schemaVersion"], independent.PLAN_SCHEMA)
        self.assertEqual(first_plan["suiteId"], independent.SUITE_ID)
        self.assertEqual(
            first_plan["runId"],
            "development-e2e-" + first_plan["controlConfigurationSHA256"],
        )
        self.assertNotIn("attemptId", first_plan)
        for field in (*FALSE_BOUNDARY_FIELDS, "thresholdsApplied"):
            self.assertIs(first_plan[field], False)
        self.assertEqual(len(first_plan["inputBindings"]), 17)
        source_entry = next(
            item
            for item in first_plan["privateFiles"]
            if item["role"] == "development-corpus-source"
        )
        self.assertEqual(
            source_entry,
            {
                "path": independent.DATASET_EVIDENCE_PATH,
                "bytes": independent.DATASET_BYTES,
                "sha256": independent.DATASET_SHA256,
                "role": "development-corpus-source",
            },
        )
        record_entries = [
            item
            for item in first_plan["privateFiles"]
            if item["role"] == "development-corpus-record"
        ]
        self.assertEqual(len(record_entries), control.PARTITIONS)
        self.assertEqual(
            [item["path"] for item in record_entries],
            [
                f"records/ud-english-pud/slice-{index:02d}.bin"
                for index in range(control.PARTITIONS)
            ],
        )
        for model_key, raw in first_jobs.items():
            with self.subTest(model=model_key):
                self.assertTrue(raw.endswith(b"\n"))
                job = json.loads(raw)
                self.assertEqual(job["schemaVersion"], model_worker.DEVELOPMENT_JOB_SCHEMA)
                self.assertEqual(job["suiteId"], model_worker.DEVELOPMENT_SUITE_ID)
                self.assertEqual(job["runId"], first_plan["runId"])
                self.assertEqual(
                    job["runId"],
                    "development-e2e-" + job["controlConfigurationSHA256"],
                )
                self.assertNotIn("attemptId", job)
                for field in FALSE_BOUNDARY_FIELDS:
                    self.assertIs(job[field], False)
                model_worker.validate_job(job)

    def test_worker_rejects_scientific_future_nist_synthetic_and_fake_namespace(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            plan, jobs = _build_lightweight_plan(Path(temporary))
        job = json.loads(jobs[independent.MODELS[0]])

        contaminations: list[tuple[str, dict[str, object]]] = []
        for field in FALSE_BOUNDARY_FIELDS:
            forged = copy.deepcopy(job)
            forged[field] = True
            contaminations.append((field, forged))
        forged = copy.deepcopy(job)
        forged["attemptId"] = "attempt-" + HEX_A
        contaminations.append(("scientific-attempt-id", forged))
        forged = copy.deepcopy(job)
        forged["suiteId"] = model_worker.SCIENTIFIC_SUITE_ID
        contaminations.append(("scientific-suite", forged))
        forged = copy.deepcopy(job)
        forged["synthetic"] = True
        contaminations.append(("synthetic-input-marker", forged))
        forged = copy.deepcopy(job)
        forged["selectedCorpora"] = ["fixture://fake-corpus"]
        contaminations.append(("fake-corpus-namespace", forged))
        forged = copy.deepcopy(job)
        forged["runId"] = "development-e2e-" + "2" * 64
        contaminations.append(("run-id-configuration-mismatch", forged))
        forged = copy.deepcopy(job)
        forged["sourceDataset"]["sha256"] = "2" * 64
        contaminations.append(("unregistered-source-dataset", forged))
        forged = copy.deepcopy(job)
        forged["model"]["key"] = "unregistered-model"
        contaminations.append(("unregistered-model", forged))
        forged = copy.deepcopy(job)
        forged["model"]["files"]["tokenizer.json"]["sha256"] = "2" * 64
        contaminations.append(("unregistered-tokenizer", forged))
        forged = copy.deepcopy(job)
        forged["model"]["candidateBitsByLayer"][1] = 9
        contaminations.append(("tuned-layer-schedule", forged))
        forged = copy.deepcopy(job)
        forged["pages"][independent.DATASET_ID][0]["sentenceEnd"] += 1
        contaminations.append(("noncanonical-sentence-range", forged))

        for label, forged in contaminations:
            with self.subTest(contamination=label), self.assertRaises(model_worker.WorkerError):
                model_worker.validate_job(forged)

        self.assertEqual(job["runId"], plan["runId"])

    def test_plan_rejects_scientific_future_nist_synthetic_and_fake_namespace(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            plan, _jobs = _build_lightweight_plan(Path(temporary))

        contaminations: list[tuple[str, dict[str, object]]] = []
        for field in (*FALSE_BOUNDARY_FIELDS, "thresholdsApplied"):
            forged = copy.deepcopy(plan)
            forged[field] = True
            contaminations.append((field, _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["attemptId"] = "attempt-" + HEX_A
        contaminations.append(("scientific-attempt-id", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["suiteId"] = model_worker.SCIENTIFIC_SUITE_ID
        contaminations.append(("scientific-suite", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["selectedCorpora"] = ["fixture://fake-corpus"]
        contaminations.append(("fake-corpus-namespace", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["inputBindings"]["adapter"]["contentSynthetic"] = True
        contaminations.append(("synthetic-adapter", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["runId"] = "development-e2e-" + "2" * 64
        contaminations.append(("run-id-configuration-mismatch", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["inputBindings"]["conlluDecode"]["sentences"] -= 1
        contaminations.append(("wrong-real-sentence-count", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["inputBindings"]["labSource"]["worktreeClean"] = False
        contaminations.append(("dirty-lab-source", _rehash_plan(forged)))
        forged = copy.deepcopy(plan)
        forged["inputBindings"]["codecSource"]["commit"] = "2" * 40
        contaminations.append(("wrong-codec-source", _rehash_plan(forged)))

        for label, forged in contaminations:
            with self.subTest(contamination=label), self.assertRaises(
                independent.DevelopmentReplayError
            ):
                independent.validate_plan(forged)

    def test_output_is_forbidden_under_scientific_results_and_repository(self) -> None:
        forbidden = control.V3_ROOT / "results" / "development-e2e-forbidden"
        with self.assertRaisesRegex(
            control.DevelopmentControlError,
            "outside the repository and v3/results",
        ):
            control._external_output_path(forbidden)
        with self.assertRaises(control.DevelopmentControlError):
            control._external_output_path(
                control.PROJECT_ROOT / "development-e2e-forbidden"
            )
        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            scientific_root = Path(temporary) / "private.one-shot-result"
            scientific_root.mkdir()
            nested = scientific_root / "development"
            with self.assertRaises(control.DevelopmentControlError):
                control._external_output_path(nested)
            with self.assertRaises(model_worker.WorkerError):
                model_worker._guard_development_output_root(nested)
            nested.mkdir()
            with self.assertRaises(independent.DevelopmentReplayError):
                independent._guard_development_evidence_root(nested)

    def test_scientific_worker_contract_remains_distinct_and_valid(self) -> None:
        design = json.loads(
            (control.V3_ROOT / "design-registration.draft.json").read_bytes()
        )
        model_key = independent.MODELS[0]
        model = next(item for item in design["models"] if item["key"] == model_key)
        files = []
        for filename, (size, digest) in model_worker.DEVELOPMENT_MODEL_BINDINGS[
            model_key
        ]["files"].items():
            files.append(
                {
                    "path": f"models/{model_key}/{filename}",
                    "bytes": size,
                    "sha256": digest,
                }
            )
        corpora = ["de.wikipedia.org", "en.wikipedia.org"]
        selected_pages: dict[str, list[dict[str, int]]] = {}
        for corpus_index, corpus in enumerate(corpora):
            selected_pages[corpus] = []
            for index in range(16):
                revision = 1000 + corpus_index * 100 + index
                selected_pages[corpus].append({"revid": revision})
                files.append(
                    {
                        "path": f"records/{corpus}/{revision}.bin",
                        "bytes": 1,
                        "sha256": HEX_A,
                    }
                )
        job = scientific_runner._worker_job(
            design=design,
            selection={
                "selectedCorpora": corpora,
                "selectedPages": selected_pages,
            },
            private_manifest={"files": files},
            model_key=model_key,
            attempt="20260903T180000Z-" + "a" * 16,
        )
        self.assertEqual(job["schemaVersion"], model_worker.SCIENTIFIC_JOB_SCHEMA)
        self.assertNotIn("runId", job)
        self.assertNotIn("sourceDataset", job)
        model_worker.validate_job(job)

        contaminations = []
        forged = copy.deepcopy(job)
        forged["sourceDataset"] = {
            "path": model_worker.DEVELOPMENT_DATASET_PATH,
            "bytes": model_worker.DEVELOPMENT_DATASET_BYTES,
            "sha256": model_worker.DEVELOPMENT_DATASET_SHA256,
        }
        contaminations.append(forged)
        forged = copy.deepcopy(job)
        forged["countsTowardScientificVerdict"] = False
        contaminations.append(forged)
        forged = copy.deepcopy(job)
        forged["schemaVersion"] = model_worker.DEVELOPMENT_JOB_SCHEMA
        contaminations.append(forged)
        forged = copy.deepcopy(job)
        forged["selectedCorpora"] = [independent.DATASET_ID]
        forged["pages"] = {independent.DATASET_ID: []}
        contaminations.append(forged)
        for forged in contaminations:
            with self.assertRaises(model_worker.WorkerError):
                model_worker.validate_job(forged)

    def test_mocked_control_orchestration_never_loads_a_model(self) -> None:
        models, inventory = _model_bindings()
        sentences = _fixture_sentences()
        bindings = _input_bindings()
        archival_inputs = _archival_inputs()
        design = {"execution": _execution()}

        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            temporary_root = Path(temporary)
            output = temporary_root / "control-output"
            asset_root = temporary_root / "assets-not-read"
            codec_root = temporary_root / "codec-not-read"
            asset_root.mkdir()
            codec_root.mkdir()
            arguments = argparse.Namespace(
                asset_root=asset_root,
                dataset=temporary_root / "en_pud-ud-test.conllu",
                codec_root=codec_root,
                runtime_manifest=temporary_root / "runtime-manifest.json",
                output=output,
            )

            def supervise(
                _command: list[str],
                *,
                cwd: Path,
                environment: dict[str, str],
                log_path: Path,
                maximum_rss_bytes: int,
                poll_milliseconds: int,
                subject: str,
            ) -> dict[str, object]:
                del cwd, environment, maximum_rss_bytes, poll_milliseconds
                root = log_path.parents[1]
                plan = json.loads((root / "development-plan.json").read_bytes())
                if subject.startswith("producer:"):
                    model_key = subject.split(":", 1)[1]
                    worker_root = root / "workers" / model_key
                    worker_root.mkdir(parents=True, exist_ok=True)
                    evidence: dict[str, dict[str, object]] = {}
                    for field, filename in (
                        ("rawTokenEvidence", "raw-token-evidence.jsonl"),
                        ("containerEvidence", "container-evidence.jsonl"),
                        ("pageTokenEvidence", "page-token-evidence.jsonl"),
                    ):
                        raw = b"{}\n"
                        (worker_root / filename).write_bytes(raw)
                        evidence[field] = {"path": filename, **_digest_bytes(raw)}
                    model = next(
                        item for item in plan["models"] if item["key"] == model_key
                    )
                    summary = {
                        "schemaVersion": control.WORKER_SUMMARY_SCHEMA,
                        "suiteId": independent.SUITE_ID,
                        "runId": plan["runId"],
                        "modelKey": model_key,
                        "geometry": {"layers": model["layers"]},
                        "pages": [
                            {
                                "datasetId": independent.DATASET_ID,
                                "pageSelectionIndex": index,
                                "sourceSliceIndex": index,
                                "denseBF16Bytes": 1024,
                                "containerBytes": 512,
                                "compressionRatioVsBF16": 2.0,
                                "deltaNLLNatPerToken": 0.0,
                                "top1ExactMatches": 128,
                            }
                            for index in range(32)
                        ],
                        **evidence,
                        "durationNanoseconds": 1,
                        "networkUsed": False,
                        "modelLoad": "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained",
                        "countsTowardScientificVerdict": False,
                        "usedForCandidateSelectionOrTuning": False,
                        "scientificAttemptStateCreated": False,
                        "nistUsed": False,
                        "futureCorpusUsed": False,
                        "controlConfigurationSHA256": plan[
                            "controlConfigurationSHA256"
                        ],
                    }
                    destination = root / "workers" / model_key / "worker-summary.json"
                else:
                    model_summaries = []
                    for model in plan["models"]:
                        model_summaries.append(
                            {
                                "modelKey": model["key"],
                                "modelFileSetSHA256": HEX_A,
                                "weightSHA256": model["files"]["model.safetensors"]["sha256"],
                                "tokenizerSHA256": model["files"]["tokenizer.json"]["sha256"],
                                "corpusRecordSetSHA256": HEX_A,
                                "rawTokenEvidenceSHA256": HEX_A,
                                "pageTokenEvidenceSHA256": HEX_A,
                                "containerEvidenceSHA256": HEX_A,
                                "containerByteSetSHA256": HEX_A,
                                "pageReplaySHA256": HEX_A,
                                "replayedPages": 32,
                                "replayedPredictions": 4096,
                                "replayedContainers": 32 * model["layers"],
                                "exactTokenIds": True,
                                "exactLossFloat32Bits": True,
                                "exactTop1TokenIds": True,
                                "allContainerInputsBoundToBaselineCache": True,
                            }
                        )
                    summary = control._with_content_digest(
                        {
                            "schemaVersion": control.REPLAY_SUMMARY_SCHEMA,
                            "suiteId": independent.SUITE_ID,
                            "runId": plan["runId"],
                            "status": "NON_SCIENTIFIC_DEVELOPMENT_REPLAY_PASS",
                            "countsTowardScientificVerdict": False,
                            "usedForCandidateSelectionOrTuning": False,
                            "scientificAttemptStateCreated": False,
                            "nistUsed": False,
                            "futureCorpusUsed": False,
                            "thresholdsApplied": False,
                            "controlConfigurationSHA256": plan[
                                "controlConfigurationSHA256"
                            ],
                            "modelOrder": list(independent.MODELS),
                            "selectedCorpora": list(independent.CORPORA),
                            "execution": {
                                "device": "cpu",
                                "modelDtype": "float32",
                                "baselineCache": "bfloat16-roundtrip-to-float32",
                                "deterministicAlgorithms": True,
                                "intraOpThreads": 2,
                                "interOpThreads": 1,
                                "modelsSequential": True,
                                "networkUsed": False,
                                "fixtureBackendUsed": False,
                            },
                            "runtime": {
                                "numpy": "2.5.1",
                                "safetensors": "0.8.0",
                                "tokenizers": "0.22.2",
                                "torch": "2.13.0",
                                "transformers": "5.14.1",
                            },
                            "models": model_summaries,
                            "totalReplayedPages": 96,
                            "totalReplayedPredictions": 12288,
                            "totalReplayedContainers": 2048,
                            "exactTokenIds": True,
                            "exactLossFloat32Bits": True,
                            "exactTop1TokenIds": True,
                            "allContainerInputsBoundToBaselineCache": True,
                            "replayComplete": True,
                        }
                    )
                    destination = root / "independent-development-replay.json"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(canonical_json_bytes(summary) + b"\n")
                return {
                    "schemaVersion": control.SUPERVISOR_SCHEMA,
                    "subject": subject,
                    "exitCode": 0,
                    "countsTowardScientificVerdict": False,
                    "usedForCandidateSelectionOrTuning": False,
                }

            with (
                mock.patch.object(
                    control,
                    "_load_fixed_inputs",
                    return_value=(
                        design,
                        {},
                        b"pinned-real-conllu",
                        copy.deepcopy(EXPECTED_DEVELOPMENT_CONTROLS["dataset"]),
                        bindings,
                        archival_inputs,
                    ),
                ),
                mock.patch.object(
                    control,
                    "closed_environment",
                    return_value={"PATH": "/usr/bin:/bin"},
                ),
                mock.patch.object(control, "verify_active_python_startup"),
                mock.patch.object(control, "verify_development_lifecycle"),
                mock.patch.object(control, "validate_development_control_report"),
                mock.patch.object(
                    control,
                    "verify_primary_host_safety",
                    return_value={"system": "Darwin", "machine": "arm64"},
                ),
                mock.patch.object(
                    control,
                    "verify_python_subprocess",
                    return_value={"runtimeProbe": "mocked-no-model-load"},
                ),
                mock.patch.object(
                    control,
                    "_real_sentences",
                    return_value=(
                        sentences,
                        {
                            "bytes": independent.JOINED_DATASET_BYTES,
                            "sha256": independent.JOINED_DATASET_SHA256,
                            "parser": "strict-stdlib-conllu-text-v1",
                            "sentences": len(sentences),
                            "sourceConlluSHA256": independent.DATASET_SHA256,
                        },
                    ),
                ),
                mock.patch.object(
                    control,
                    "_link_model_assets",
                    return_value=(models, inventory),
                ),
                mock.patch.object(
                    control,
                    "_tracked_sources",
                    return_value=bindings["controlSources"],
                ),
                mock.patch.object(
                    control,
                    "verify_codec",
                    return_value=bindings["codecSource"],
                ),
                mock.patch.object(
                    control,
                    "_development_child_command",
                    return_value=(["mocked-development-child"], "mock-networkless"),
                ),
                mock.patch.object(
                    control,
                    "_supervise_development_child",
                    side_effect=supervise,
                ) as supervisor,
                mock.patch.object(control, "consolidate_worker_evidence"),
                mock.patch.object(
                    model_worker,
                    "load_model_and_tokenizer",
                    side_effect=AssertionError("unit test must not load a model"),
                ) as model_loader,
            ):
                report = control.run_control(arguments)

            self.assertEqual(report["schemaVersion"], control.REPORT_SCHEMA)
            self.assertEqual(
                report["status"], "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_PASS"
            )
            self.assertEqual(
                report["runId"],
                "development-e2e-" + report["controlConfigurationSHA256"],
            )
            for field in (*FALSE_BOUNDARY_FIELDS, "thresholdsApplied"):
                self.assertIs(report[field], False)
            self.assertEqual(supervisor.call_count, len(independent.MODELS) + 1)
            model_loader.assert_not_called()
            self.assertTrue((output / "development-control-report.json").is_file())
            receipt_path = (
                output / "inputs" / control.FULL_ASSET_RECEIPT_ARCHIVE_NAME
            )
            self.assertEqual(
                receipt_path.read_bytes(),
                archival_inputs[control.FULL_ASSET_RECEIPT_ARCHIVE_NAME],
            )
            self.assertFalse((output / "inputs/full-asset-receipt.json").exists())
            self.assertFalse((control.V3_ROOT / "results" / output.name).exists())

    def test_failure_after_output_claim_is_durable_and_never_pass(self) -> None:
        sentences = _fixture_sentences()
        bindings = _input_bindings()
        archival_inputs = _archival_inputs()
        design = {"execution": _execution()}
        with tempfile.TemporaryDirectory(dir=TEMPORARY_PARENT) as temporary:
            root = Path(temporary)
            output = root / "failed-control"
            arguments = argparse.Namespace(
                asset_root=root,
                dataset=root / "en_pud-ud-test.conllu",
                codec_root=root,
                runtime_manifest=root / "runtime.json",
                output=output,
            )
            with (
                mock.patch.object(
                    control,
                    "_load_fixed_inputs",
                    return_value=(
                        design,
                        {},
                        b"pinned-real-conllu",
                        copy.deepcopy(EXPECTED_DEVELOPMENT_CONTROLS["dataset"]),
                        bindings,
                        archival_inputs,
                    ),
                ),
                mock.patch.object(control, "verify_development_lifecycle"),
                mock.patch.object(
                    control,
                    "closed_environment",
                    return_value={"PATH": "/usr/bin:/bin"},
                ),
                mock.patch.object(control, "verify_active_python_startup"),
                mock.patch.object(
                    control,
                    "verify_python_subprocess",
                    return_value={"runtimeProbe": "fixture"},
                ),
                mock.patch.object(
                    control,
                    "_real_sentences",
                    return_value=(
                        sentences,
                        {
                            "bytes": independent.JOINED_DATASET_BYTES,
                            "sha256": independent.JOINED_DATASET_SHA256,
                            "parser": "strict-stdlib-conllu-text-v1",
                            "sentences": independent.DATASET_ROWS,
                            "sourceConlluSHA256": independent.DATASET_SHA256,
                        },
                    ),
                ),
                mock.patch.object(
                    control,
                    "verify_primary_host_safety",
                    return_value={"system": "Darwin", "machine": "arm64"},
                ),
                mock.patch.object(
                    control,
                    "_link_model_assets",
                    side_effect=control.DevelopmentControlError(
                        "intentional unit control failure"
                    ),
                ),
            ):
                with self.assertRaises(control.DevelopmentControlError):
                    control.run_control(arguments)

            failure_path = output / "development-control-failure.json"
            self.assertTrue(failure_path.is_file())
            self.assertTrue((output / "development-control-start.json").is_file())
            self.assertFalse((output / "development-control-report.json").exists())
            failure = json.loads(failure_path.read_bytes())
            control.verify_content_digest(failure)
            self.assertEqual(
                failure["status"], "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_FAIL"
            )
            for field in (*FALSE_BOUNDARY_FIELDS, "thresholdsApplied"):
                self.assertIs(failure[field], False)
            self.assertEqual(failure["scientificClaim"], "forbidden")
            self.assertEqual(failure["failureType"], "DevelopmentControlError")
            self.assertRegex(
                failure["executionId"],
                r"development-execution-\d{8}T\d{6}Z-[0-9a-f]{16}\Z",
            )

    def test_development_lifecycle_is_draft_only_and_cutoff_bound(self) -> None:
        design = json.loads(
            (control.V3_ROOT / "design-registration.draft.json").read_bytes()
        )
        control.verify_development_lifecycle(
            design,
            now=datetime(2026, 8, 14, 23, 59, 59, tzinfo=timezone.utc),
        )
        with self.assertRaises(control.DevelopmentControlError):
            control.verify_development_lifecycle(
                design,
                now=datetime(2026, 8, 15, 0, 0, 0, tzinfo=timezone.utc),
            )
        bound = copy.deepcopy(design)
        bound["developmentControls"]["realDataE2EFreezeGate"]["status"] = (
            "BOUND_ARCHIVED_PASS"
        )
        with self.assertRaises(control.DevelopmentControlError):
            control.verify_development_lifecycle(
                bound,
                now=datetime(2026, 8, 14, 0, 0, 0, tzinfo=timezone.utc),
            )

    def test_registered_boundary_and_cli_expose_no_tuning_controls(self) -> None:
        self.assertTrue(EXPECTED_DEVELOPMENT_CONTROLS["syntheticInputsForbidden"])
        self.assertFalse(EXPECTED_DEVELOPMENT_CONTROLS["nistUsed"])
        self.assertFalse(EXPECTED_DEVELOPMENT_CONTROLS["scientificAttemptStateCreated"])
        self.assertFalse(EXPECTED_DEVELOPMENT_CONTROLS["scientificResultRootUsed"])
        self.assertFalse(EXPECTED_DEVELOPMENT_CONTROLS["countsTowardScientificVerdict"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            control.parse_arguments(
                [
                    "--asset-root",
                    "assets",
                    "--dataset",
                    "dataset",
                    "--codec-root",
                    "codec",
                    "--output",
                    "output",
                    "--pages",
                    "1",
                ]
            )


if __name__ == "__main__":
    unittest.main()
