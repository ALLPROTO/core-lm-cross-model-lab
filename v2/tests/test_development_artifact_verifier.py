from __future__ import annotations

import copy
import hashlib
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from v2 import development_artifact_verifier as subject


def canonical(value: object) -> bytes:
    return subject._canonical_json_bytes(value)


def line(value: object) -> bytes:
    return canonical(value) + b"\n"


def jsonl(values: list[dict[str, object]]) -> bytes:
    return b"".join(line(value) for value in values)


def digest(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def f32(value: float) -> str:
    return struct.pack(">f", value).hex()


class TinySemanticArchive:
    model_key = "unit-model"

    def __init__(self) -> None:
        self.text = "one real sentence"
        self.dataset = (
            "# sent_id = unit-1\n"
            f"# text = {self.text}\n"
            "1\tone\tone\tNOUN\t_\t_\t0\troot\t_\t_\n\n"
        ).encode("utf-8")
        self.dataset_sha = hashlib.sha256(self.dataset).hexdigest()
        self.joined = self.text.encode("utf-8")
        self.readme = (
            "License: CC BY-SA 3.0\n"
            "Includes text: yes\n"
            "GOOGLE MAKES THEM AVAILABLE TO YOU under CC-BY-SA 3.0\n"
        ).encode("utf-8")
        self.license = (
            "Creative Commons Attribution-ShareAlike 3.0\n"
            "https://creativecommons.org/licenses/by-sa/3.0/\n"
        ).encode("utf-8")
        self.attribution = (
            f"r2.18\n{subject.DATASET_REVISION}\n{subject.DATASET_TREE}\n"
            f"{self.dataset_sha}\nNo endorsement\n"
        ).encode("utf-8")
        self.matrix = (
            b"UD English PUD | CC BY-SA 3.0 | without added restrictions\n"
        )
        self.files: dict[str, bytes] = {}
        self._build()

    def patches(self):
        return mock.patch.multiple(
            subject,
            MODEL_KEYS=(self.model_key,),
            MODEL_FILES=("config.json", "model.safetensors", "tokenizer.json"),
            MODEL_IDENTITIES={
                self.model_key: {
                    "repository": "unit/model",
                    "revision": "1" * 40,
                    "layers": 1,
                    "vocabSize": 16,
                }
            },
            MODEL_GEOMETRIES={
                self.model_key: {
                    "modelType": "unit",
                    "attentionLayout": "unit",
                    "layers": 1,
                    "attentionHeads": 1,
                    "kvHeads": 1,
                    "headDimension": 64,
                    "hiddenSize": 64,
                    "trajectoryWidth": 128,
                }
            },
            DATASET_BYTES=len(self.dataset),
            DATASET_SHA256=self.dataset_sha,
            DATASET_SENTENCES=1,
            JOINED_TEXT_BYTES=len(self.joined),
            JOINED_TEXT_SHA256=hashlib.sha256(self.joined).hexdigest(),
            PUD_README_BYTES=len(self.readme),
            PUD_README_SHA256=hashlib.sha256(self.readme).hexdigest(),
            PUD_LICENSE_BYTES=len(self.license),
            PUD_LICENSE_SHA256=hashlib.sha256(self.license).hexdigest(),
            PUD_ATTRIBUTION_BYTES=len(self.attribution),
            PUD_ATTRIBUTION_SHA256=hashlib.sha256(self.attribution).hexdigest(),
            PAGES_PER_MODEL=1,
            PAGE_TOKENS=3,
            PREFILL_TOKENS=1,
            PREDICTIONS_PER_PAGE=1,
        )

    def _build(self) -> None:
        with self.patches():
            key = self.model_key
            model_files: dict[str, dict[str, object]] = {}
            receipt_files: dict[str, dict[str, object]] = {}
            private: list[dict[str, object]] = []
            for index, filename in enumerate(subject.MODEL_FILES, start=1):
                commitment = {
                    "bytes": index,
                    "sha256": f"{index:x}" * 64,
                }
                receipt_files[filename] = commitment
                path = f"models/{key}/{filename}"
                model_files[filename] = {"path": path, **commitment}
                private.append({"path": path, **commitment, "role": "model-asset"})

            receipt = {
                "schemaVersion": subject.ASSET_RECEIPT_SCHEMA,
                "status": "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED",
                "countsTowardScientificVerdict": False,
                "networkUsed": False,
                "modelInferenceUsed": False,
                "assetLayout": "<asset-root>/<model-key>/<manifest-relative-file>",
                "fileCount": len(subject.MODEL_FILES),
                "fullSafetensorsBytesLocallyVerified": True,
                "models": {
                    key: {
                        "repository": "unit/model",
                        "revision": "1" * 40,
                        "files": receipt_files,
                    }
                },
            }
            self.files["inputs/full-asset-receipt.json"] = line(receipt)
            corpus_manifest = {
                "schemaVersion": "corelm-crossmodel-livewiki-v2-development-corpus-v1",
                "status": "PINNED_REAL_CORPUS_WITH_EXPLICIT_REDISTRIBUTION_LICENSE",
                "queriedAtUTC": "2026-08-03T23:02:05Z",
                "datasetId": subject.DATASET_ID,
                "repository": subject.DATASET_REPOSITORY,
                "revision": subject.DATASET_REVISION,
                "tree": subject.DATASET_TREE,
                "releaseTag": subject.DATASET_RELEASE_TAG,
                "split": subject.DATASET_SPLIT,
                "splitPurpose": (
                    "upstream test split reused only as a non-scientific "
                    "development control; it is not a blind scientific test result"
                ),
                "file": subject.DATASET_FILE,
                "format": "CoNLL-U",
                "bytes": len(self.dataset),
                "sha256": self.dataset_sha,
                "sourceURL": (
                    "https://raw.githubusercontent.com/UniversalDependencies/"
                    f"UD_English-PUD/{subject.DATASET_REVISION}/"
                    f"{subject.DATASET_FILE}"
                ),
                "rows": 1,
                "rowExtraction": (
                    "exactly one '# text = ' value from each LF-delimited "
                    "CoNLL-U sentence block; prefix removed; text otherwise unchanged"
                ),
                "joinedTextBytes": len(self.joined),
                "joinedTextSHA256": hashlib.sha256(self.joined).hexdigest(),
                "contentSynthetic": False,
                "license": "CC-BY-SA-3.0",
                "licenseFile": {
                    "path": "LICENSE.txt",
                    **digest(self.license),
                    "url": (
                        "https://raw.githubusercontent.com/UniversalDependencies/"
                        f"UD_English-PUD/{subject.DATASET_REVISION}/LICENSE.txt"
                    ),
                },
                "readme": {
                    "path": "README.md",
                    **digest(self.readme),
                    "url": (
                        "https://raw.githubusercontent.com/UniversalDependencies/"
                        f"UD_English-PUD/{subject.DATASET_REVISION}/README.md"
                    ),
                },
                "redistributionObligations": {
                    "attributionRequired": True,
                    "shareAlikeRequired": True,
                    "licenseNoticeRequired": True,
                    "upstreamWarranty": "none",
                },
            }
            self.files[subject.CORPUS_MANIFEST_PATH] = line(corpus_manifest)
            source_evidence = {
                "schemaVersion": (
                    "corelm-crossmodel-livewiki-v2-license-source-evidence-v1"
                ),
                "status": "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED",
                "retrievedAt": "2026-08-03T23:10:15Z",
                "sources": [
                    {
                        "component": "UD English PUD development corpus README",
                        "repository": subject.DATASET_REPOSITORY,
                        "revision": subject.DATASET_REVISION,
                        "relativePath": "README.md",
                        "archivedPath": (
                            "upstream/ud-english-pud-r2.18-README.md"
                        ),
                        "archivedEncoding": "identity",
                        "url": (
                            "https://raw.githubusercontent.com/UniversalDependencies/"
                            f"UD_English-PUD/{subject.DATASET_REVISION}/README.md"
                        ),
                        **digest(self.readme),
                        "declaredLicense": "CC-BY-SA-3.0",
                    },
                    {
                        "component": "UD English PUD development corpus license",
                        "repository": subject.DATASET_REPOSITORY,
                        "revision": subject.DATASET_REVISION,
                        "relativePath": "LICENSE.txt",
                        "archivedPath": (
                            "upstream/ud-english-pud-r2.18-LICENSE.txt"
                        ),
                        "archivedEncoding": "identity",
                        "url": (
                            "https://raw.githubusercontent.com/UniversalDependencies/"
                            f"UD_English-PUD/{subject.DATASET_REVISION}/LICENSE.txt"
                        ),
                        **digest(self.license),
                        "declaredLicense": "CC-BY-SA-3.0",
                    },
                ],
            }
            self.files[subject.LICENSE_SOURCE_PATH] = line(source_evidence)
            self.files[subject.LICENSE_MATRIX_PATH] = self.matrix
            self.files[subject.PUD_README_PATH] = self.readme
            self.files[subject.PUD_LICENSE_PATH] = self.license
            self.files[subject.PUD_ATTRIBUTION_PATH] = self.attribution
            self.files[subject.DATASET_PATH] = self.dataset

            content = self.text
            content_raw = content.encode()
            record_raw = subject._serialize_record(
                sentence_start=0, sentence_end=1, content=content
            )
            record_path = "records/ud-english-pud/slice-00.bin"
            page = {
                "pageSelectionIndex": 0,
                "sourceSliceIndex": 0,
                "sentenceStart": 0,
                "sentenceEnd": 1,
                "recordPath": record_path,
                "recordBytes": len(record_raw),
                "recordSHA256": hashlib.sha256(record_raw).hexdigest(),
                "inputTextBytes": len(content_raw),
                "inputTextSHA256": hashlib.sha256(content_raw).hexdigest(),
            }
            private.extend(
                (
                    {
                        "path": record_path,
                        "bytes": len(record_raw),
                        "sha256": hashlib.sha256(record_raw).hexdigest(),
                        "role": "development-corpus-record",
                    },
                    {
                        "path": subject.DATASET_PATH,
                        "bytes": len(self.dataset),
                        "sha256": self.dataset_sha,
                        "role": "development-corpus-source",
                    },
                )
            )
            bindings = {
                "developmentCorpusManifest": digest(
                    self.files[subject.CORPUS_MANIFEST_PATH]
                ),
                "licenseSourceEvidence": digest(
                    self.files[subject.LICENSE_SOURCE_PATH]
                ),
                "assetLicenseMatrix": digest(self.matrix),
                "udEnglishPudReadme": digest(self.readme),
                "udEnglishPudLicense": digest(self.license),
                "udEnglishPudAttribution": digest(self.attribution),
                "developmentDataset": digest(self.dataset),
                "conlluDecode": {
                    "parser": "strict-stdlib-conllu-text-v1",
                    "sentences": 1,
                    "sourceConlluSHA256": self.dataset_sha,
                },
                "joinedCorpusText": {
                    "bytes": len(content_raw),
                    "sha256": hashlib.sha256(content_raw).hexdigest(),
                },
            }
            model = {
                "key": key,
                "repository": "unit/model",
                "revision": "1" * 40,
                "layers": 1,
                "vocabSize": 16,
                "candidateBitsByLayer": [9],
                "files": model_files,
            }
            self.plan: dict[str, object] = {
                "suiteId": subject.SUITE_ID,
                "runId": "development-e2e-" + "a" * 64,
                "controlConfigurationSHA256": "a" * 64,
                "modelExecutionOrder": [key],
                "selectedCorpora": [subject.DATASET_ID],
                "candidate": dict(subject.CANDIDATE),
                "models": [model],
                "pages": {subject.DATASET_ID: [page]},
                "privateFiles": private,
                "inputBindings": bindings,
                "jobs": {},
            }
            expected_job = subject._expected_job(self.plan, key)
            job_raw = line(expected_job)
            job_path = f"jobs/{key}.json"
            self.files[job_path] = job_raw
            self.plan["jobs"] = {key: {"path": job_path, **digest(job_raw)}}

            page_token = {
                "schemaVersion": subject.PAGE_TOKEN_SCHEMA,
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "modelKey": key,
                "datasetId": subject.DATASET_ID,
                "sourceSliceIndex": 0,
                "pageSelectionIndex": 0,
                "vocabSize": 16,
                "first512TokenIds": [1, 2, 3],
                "first512StreamSHA256": hashlib.sha256(
                    subject._token_stream([1, 2, 3])
                ).hexdigest(),
            }
            raw_token = {
                "schemaVersion": subject.RAW_TOKEN_SCHEMA,
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "modelKey": key,
                "datasetId": subject.DATASET_ID,
                "sourceSliceIndex": 0,
                "pageSelectionIndex": 0,
                "predictionIndex": 0,
                "targetTokenId": 3,
                "baselineLossF32Bits": f32(1.0),
                "candidateLossF32Bits": f32(1.5),
                "baselineTop1TokenId": 4,
                "candidateTop1TokenId": 4,
            }
            container_raw, metadata = self._container()
            relative = (
                f"containers/{key}/{subject.DATASET_ID}/slice-00/layer-00.vtl5"
            )
            container_record = {
                "schemaVersion": subject.CONTAINER_SCHEMA,
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "modelKey": key,
                "datasetId": subject.DATASET_ID,
                "sourceSliceIndex": 0,
                "pageSelectionIndex": 0,
                "layerIndex": 0,
                "denseBF16Bytes": 256,
                "containerBytes": len(container_raw),
                "containerSHA256": hashlib.sha256(container_raw).hexdigest(),
                "relativePath": relative,
                "structuralReplay": True,
            }
            raw_bytes = jsonl([raw_token])
            page_bytes = jsonl([page_token])
            container_bytes = jsonl([container_record])
            prefix = f"workers/{key}"
            self.files[f"{prefix}/raw-token-evidence.jsonl"] = raw_bytes
            self.files[f"{prefix}/page-token-evidence.jsonl"] = page_bytes
            self.files[f"{prefix}/container-evidence.jsonl"] = container_bytes
            self.files[relative] = container_raw
            worker_summary = {
                "schemaVersion": subject.WORKER_SUMMARY_SCHEMA,
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "modelKey": key,
                "geometry": subject.MODEL_GEOMETRIES[key],
                "pages": [
                    {
                        "datasetId": subject.DATASET_ID,
                        "pageSelectionIndex": 0,
                        "sourceSliceIndex": 0,
                        "denseBF16Bytes": 256,
                        "containerBytes": len(container_raw),
                        "compressionRatioVsBF16": 256 / len(container_raw),
                        "deltaNLLNatPerToken": 0.5,
                        "top1ExactMatches": 1,
                    }
                ],
                "rawTokenEvidence": {
                    "path": "raw-token-evidence.jsonl",
                    **digest(raw_bytes),
                },
                "containerEvidence": {
                    "path": "container-evidence.jsonl",
                    **digest(container_bytes),
                },
                "pageTokenEvidence": {
                    "path": "page-token-evidence.jsonl",
                    **digest(page_bytes),
                },
                "durationNanoseconds": 1,
                "networkUsed": False,
                "modelLoad": "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained",
                "countsTowardScientificVerdict": False,
                "usedForCandidateSelectionOrTuning": False,
                "scientificAttemptStateCreated": False,
                "nistUsed": False,
                "futureCorpusUsed": False,
                "controlConfigurationSHA256": self.plan[
                    "controlConfigurationSHA256"
                ],
            }
            self.files[f"{prefix}/worker-summary.json"] = line(worker_summary)
            self.files["raw-token-evidence.jsonl"] = raw_bytes
            self.files["container-evidence.jsonl"] = container_bytes
            self.files["page-token-evidence.jsonl"] = page_bytes

            record_commitments = [
                {
                    "datasetId": subject.DATASET_ID,
                    "sourceSliceIndex": 0,
                    "sentenceStart": 0,
                    "sentenceEnd": 1,
                    "bytes": len(record_raw),
                    "sha256": hashlib.sha256(record_raw).hexdigest(),
                }
            ]
            container_commitments = [
                {
                    "layerIndex": 0,
                    "relativePath": relative,
                    "containerBytes": len(container_raw),
                    "containerSHA256": hashlib.sha256(container_raw).hexdigest(),
                    "inputSHA256": metadata["inputSha256"],
                    "reconstructionSHA256": metadata["reconstructionSha256"],
                }
            ]
            page_summaries = [
                {
                    "datasetId": subject.DATASET_ID,
                    "sourceSliceIndex": 0,
                    "sentenceStart": 0,
                    "sentenceEnd": 1,
                    "predictions": 1,
                    "containers": 1,
                    "tokenStreamSHA256": page_token["first512StreamSHA256"],
                    "containerCommitmentsSHA256": hashlib.sha256(
                        canonical(container_commitments)
                    ).hexdigest(),
                }
            ]
            byte_set = [
                {
                    "relativePath": relative,
                    "bytes": len(container_raw),
                    "sha256": hashlib.sha256(container_raw).hexdigest(),
                }
            ]
            replay_model = {
                "modelKey": key,
                "modelFileSetSHA256": subject._model_file_digest(model),
                "weightSHA256": model_files["model.safetensors"]["sha256"],
                "tokenizerSHA256": model_files["tokenizer.json"]["sha256"],
                "corpusRecordSetSHA256": hashlib.sha256(
                    canonical(record_commitments)
                ).hexdigest(),
                "rawTokenEvidenceSHA256": hashlib.sha256(raw_bytes).hexdigest(),
                "pageTokenEvidenceSHA256": hashlib.sha256(page_bytes).hexdigest(),
                "containerEvidenceSHA256": hashlib.sha256(
                    container_bytes
                ).hexdigest(),
                "containerByteSetSHA256": hashlib.sha256(
                    canonical(byte_set)
                ).hexdigest(),
                "pageReplaySHA256": hashlib.sha256(
                    canonical(page_summaries)
                ).hexdigest(),
                "replayedPages": 1,
                "replayedPredictions": 1,
                "replayedContainers": 1,
                "exactTokenIds": True,
                "exactLossFloat32Bits": True,
                "exactTop1TokenIds": True,
                "allContainerInputsBoundToBaselineCache": True,
            }
            replay = {
                "schemaVersion": "corelm-crossmodel-v2-real-e2e-development-model-replay-v1",
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "status": "NON_SCIENTIFIC_DEVELOPMENT_REPLAY_PASS",
                "countsTowardScientificVerdict": False,
                "usedForCandidateSelectionOrTuning": False,
                "scientificAttemptStateCreated": False,
                "nistUsed": False,
                "futureCorpusUsed": False,
                "thresholdsApplied": False,
                "controlConfigurationSHA256": self.plan[
                    "controlConfigurationSHA256"
                ],
                "modelOrder": [key],
                "selectedCorpora": [subject.DATASET_ID],
                "execution": {},
                "runtime": {},
                "models": [replay_model],
                "totalReplayedPages": 1,
                "totalReplayedPredictions": 1,
                "totalReplayedContainers": 1,
                "exactTokenIds": True,
                "exactLossFloat32Bits": True,
                "exactTop1TokenIds": True,
                "allContainerInputsBoundToBaselineCache": True,
                "replayComplete": True,
            }
            replay["contentSHA256"] = hashlib.sha256(canonical(replay)).hexdigest()
            self.report: dict[str, object] = {
                "suiteId": subject.SUITE_ID,
                "runId": self.plan["runId"],
                "controlConfigurationSHA256": self.plan[
                    "controlConfigurationSHA256"
                ],
                "inputs": bindings,
                "independentReplay": replay,
            }

    @staticmethod
    def _container() -> tuple[bytes, dict[str, object]]:
        scales = b"\0\0"
        codes = b"\0" * 144
        stored_scales = zlib.compress(scales, level=9)
        stored_codes = zlib.compress(codes, level=9)
        payload = stored_scales + stored_codes
        metadata: dict[str, object] = {
            "bits": 9,
            "codeCompression": "zlib-9",
            "codeCount": 128,
            "codeMapping": "zigzag-symmetric-v1",
            "dtype": "float32",
            "format": "voidtoken-rotated-entropy-v5",
            "groupSize": 128,
            "groupsPerRow": 1,
            "inputSha256": "1" * 64,
            "layerIndex": 0,
            "packedBytes": 144,
            "packing": "byte-low-plus-lsb-high-fields-v1",
            "payloadBytes": len(payload),
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
            "quantization": "symmetric-max-abs-v1",
            "reconstructionSha256": hashlib.sha256(b"\0" * 128 * 4).hexdigest(),
            "scaleBytes": 2,
            "scaleCompression": "zlib-9",
            "scaleCount": 1,
            "scaleDtype": "float16-le",
            "shape": [1, 128],
            "signDerivation": "shake256-layer-column-v1",
            "signMode": "none",
            "storedCodeBytes": len(stored_codes),
            "storedScaleBytes": len(stored_scales),
            "transform": "normalized-walsh-hadamard-v1",
            "transformBlockSize": 128,
        }
        metadata_raw = canonical(metadata)
        return struct.pack("<4sI", b"VTL5", len(metadata_raw)) + metadata_raw + payload, metadata

    def inventory(self) -> dict[str, dict[str, object]]:
        return {path: {"path": path, **digest(raw)} for path, raw in self.files.items()}

    def reader(self, relative: str, maximum_bytes: int) -> bytes:
        raw = self.files[relative]
        if len(raw) > maximum_bytes:
            raise AssertionError("fixture exceeded verifier bound")
        return raw

    def refresh_replay_digest(self) -> None:
        replay = self.report["independentReplay"]
        assert isinstance(replay, dict)
        replay.pop("contentSHA256", None)
        replay["contentSHA256"] = hashlib.sha256(canonical(replay)).hexdigest()

    def replace_bound_input(self, binding: str, path: str, raw: bytes) -> None:
        self.files[path] = raw
        commitment = digest(raw)
        bindings = self.plan["inputBindings"]
        report_bindings = self.report["inputs"]
        assert isinstance(bindings, dict)
        assert isinstance(report_bindings, dict)
        bindings[binding] = commitment
        report_bindings[binding] = commitment


class DevelopmentArtifactVerifierTests(unittest.TestCase):
    def verify(self, fixture: TinySemanticArchive) -> dict[str, object]:
        with fixture.patches():
            return subject.verify_artifact_semantics(
                Path("/unused-with-callback"),
                fixture.plan,
                fixture.report,
                fixture.inventory(),
                fixture.reader,
            )

    def test_recomputes_complete_semantic_chain(self) -> None:
        fixture = TinySemanticArchive()
        result = self.verify(fixture)
        self.assertEqual(result["status"], "VERIFIED_DEVELOPMENT_ARTIFACT_SEMANTICS")
        self.assertEqual(result["datasetSentences"], 1)
        self.assertEqual(result["totalPages"], 1)
        self.assertEqual(result["totalPredictions"], 1)
        self.assertEqual(result["totalContainers"], 1)
        self.assertEqual(tuple(result["models"]), (fixture.model_key,))

    def test_self_contained_reader_rejects_symlink_substitution(self) -> None:
        fixture = TinySemanticArchive()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, raw in fixture.files.items():
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            with fixture.patches():
                result = subject.verify_artifact_semantics(
                    root,
                    fixture.plan,
                    fixture.report,
                    fixture.inventory(),
                )
            self.assertEqual(
                result["status"], "VERIFIED_DEVELOPMENT_ARTIFACT_SEMANTICS"
            )
            target = root / "raw-token-evidence.jsonl"
            target.unlink()
            os.symlink(
                root
                / "workers"
                / fixture.model_key
                / "raw-token-evidence.jsonl",
                target,
            )
            with fixture.patches(), self.assertRaises(
                subject.DevelopmentArtifactVerificationError
            ):
                subject.verify_artifact_semantics(
                    root,
                    fixture.plan,
                    fixture.report,
                    fixture.inventory(),
                )

    def test_rejects_self_consistent_asset_job_record_and_replay_tampering(self) -> None:
        mutations = []

        asset = TinySemanticArchive()
        asset.plan["models"][0]["files"]["tokenizer.json"]["sha256"] = "9" * 64
        mutations.append(asset)

        job = TinySemanticArchive()
        path = f"jobs/{job.model_key}.json"
        job_value = subject._canonical_line(job.files[path], label="fixture job")
        job_value["seed"] = 1
        job.files[path] = line(job_value)
        job.plan["jobs"][job.model_key] = {"path": path, **digest(job.files[path])}
        mutations.append(job)

        record = TinySemanticArchive()
        record.plan["pages"][subject.DATASET_ID][0]["recordSHA256"] = "8" * 64
        mutations.append(record)

        replay = TinySemanticArchive()
        replay.report["independentReplay"]["models"][0][
            "pageReplaySHA256"
        ] = "7" * 64
        replay.refresh_replay_digest()
        mutations.append(replay)

        for fixture in mutations:
            with self.subTest(mutation=mutations.index(fixture)):
                with self.assertRaises(subject.DevelopmentArtifactVerificationError):
                    self.verify(fixture)

    def test_rejects_pud_manifest_rights_and_record_tampering(self) -> None:
        manifest = TinySemanticArchive()
        manifest_value = subject._strict_json(
            manifest.files[subject.CORPUS_MANIFEST_PATH],
            label="fixture corpus manifest",
        )
        manifest_value["license"] = "MIT"
        manifest.replace_bound_input(
            "developmentCorpusManifest",
            subject.CORPUS_MANIFEST_PATH,
            line(manifest_value),
        )

        readme = TinySemanticArchive()
        readme.replace_bound_input(
            "udEnglishPudReadme",
            subject.PUD_README_PATH,
            readme.readme.replace(b"Includes text: yes", b"Includes text: no"),
        )

        license_text = TinySemanticArchive()
        license_text.replace_bound_input(
            "udEnglishPudLicense",
            subject.PUD_LICENSE_PATH,
            license_text.license.replace(b"Attribution-ShareAlike", b"Attribution"),
        )

        attribution = TinySemanticArchive()
        attribution.replace_bound_input(
            "udEnglishPudAttribution",
            subject.PUD_ATTRIBUTION_PATH,
            attribution.attribution.replace(b"No endorsement", b"Endorsement"),
        )

        record = TinySemanticArchive()
        tampered_content = "different source sentence"
        with record.patches():
            tampered_record = subject._serialize_record(
                sentence_start=0,
                sentence_end=1,
                content=tampered_content,
            )
        tampered_record_digest = digest(tampered_record)
        page = record.plan["pages"][subject.DATASET_ID][0]
        page.update(
            {
                "recordBytes": tampered_record_digest["bytes"],
                "recordSHA256": tampered_record_digest["sha256"],
                "inputTextBytes": len(tampered_content.encode("utf-8")),
                "inputTextSHA256": hashlib.sha256(
                    tampered_content.encode("utf-8")
                ).hexdigest(),
            }
        )
        record_path = page["recordPath"]
        private_record = next(
            item
            for item in record.plan["privateFiles"]
            if item["path"] == record_path
        )
        private_record.update(tampered_record_digest)
        record_commitment = {
            "datasetId": subject.DATASET_ID,
            "sourceSliceIndex": 0,
            "sentenceStart": 0,
            "sentenceEnd": 1,
            **tampered_record_digest,
        }
        record.report["independentReplay"]["models"][0][
            "corpusRecordSetSHA256"
        ] = hashlib.sha256(canonical([record_commitment])).hexdigest()
        record.refresh_replay_digest()

        cases = {
            "corpus-manifest": manifest,
            "README": readme,
            "LICENSE": license_text,
            "attribution": attribution,
            "PUD-record": record,
        }
        for label, fixture in cases.items():
            with self.subTest(label=label), self.assertRaises(
                subject.DevelopmentArtifactVerificationError
            ):
                self.verify(fixture)

    def test_rejects_token_metric_container_and_consolidation_tampering(self) -> None:
        raw = TinySemanticArchive()
        worker_raw_path = f"workers/{raw.model_key}/raw-token-evidence.jsonl"
        records = subject._canonical_jsonl(raw.files[worker_raw_path], label="fixture")
        records[0]["targetTokenId"] = 2
        changed_raw = jsonl(records)
        raw.files[worker_raw_path] = changed_raw
        raw.files["raw-token-evidence.jsonl"] = changed_raw
        summary_path = f"workers/{raw.model_key}/worker-summary.json"
        summary = subject._canonical_line(raw.files[summary_path], label="fixture")
        summary["rawTokenEvidence"] = {
            "path": "raw-token-evidence.jsonl",
            **digest(changed_raw),
        }
        raw.files[summary_path] = line(summary)
        raw.report["independentReplay"]["models"][0][
            "rawTokenEvidenceSHA256"
        ] = hashlib.sha256(changed_raw).hexdigest()
        raw.refresh_replay_digest()

        metric = TinySemanticArchive()
        summary_path = f"workers/{metric.model_key}/worker-summary.json"
        summary = subject._canonical_line(metric.files[summary_path], label="fixture")
        summary["pages"][0]["deltaNLLNatPerToken"] = 0.25
        metric.files[summary_path] = line(summary)

        container = TinySemanticArchive()
        relative = next(path for path in container.files if path.endswith(".vtl5"))
        value = bytearray(container.files[relative])
        value[-1] ^= 1
        container.files[relative] = bytes(value)
        evidence_path = f"workers/{container.model_key}/container-evidence.jsonl"
        evidence = subject._canonical_jsonl(container.files[evidence_path], label="fixture")
        evidence[0]["containerSHA256"] = hashlib.sha256(value).hexdigest()
        evidence[0]["containerBytes"] = len(value)
        changed_evidence = jsonl(evidence)
        container.files[evidence_path] = changed_evidence
        container.files["container-evidence.jsonl"] = changed_evidence
        summary_path = f"workers/{container.model_key}/worker-summary.json"
        summary = subject._canonical_line(container.files[summary_path], label="fixture")
        summary["containerEvidence"] = {
            "path": "container-evidence.jsonl",
            **digest(changed_evidence),
        }
        container.files[summary_path] = line(summary)
        container.report["independentReplay"]["models"][0][
            "containerEvidenceSHA256"
        ] = hashlib.sha256(changed_evidence).hexdigest()
        container.refresh_replay_digest()

        combined = TinySemanticArchive()
        combined.files["raw-token-evidence.jsonl"] += b"{}\n"

        for fixture in (raw, metric, container, combined):
            with self.subTest(kind=id(fixture)):
                with self.assertRaises(subject.DevelopmentArtifactVerificationError):
                    self.verify(fixture)

    def test_canonical_jsonl_rejects_duplicate_nonfinite_and_blank_records(self) -> None:
        for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b"{}\n\n"):
            with self.subTest(raw=raw), self.assertRaises(
                subject.DevelopmentArtifactVerificationError
            ):
                subject._canonical_jsonl(raw, label="unit")


if __name__ == "__main__":
    unittest.main()
