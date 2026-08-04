#!/usr/bin/env python3
"""Independent real-model replay for the non-scientific development E2E control.

This entry point accepts only a sealed development plan produced by
``run_real_e2e_control.py``.  Its identity and output schemas are deliberately
incompatible with the scientific one-shot.  It imports the independently
implemented model/VTL5 replay module and never imports the producer worker,
runner, state machine, NIST client, or scientific verifier.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3 import independent_model_replay as replay  # noqa: E402
from v3.development_corpus import verify_rights_evidence  # noqa: E402


PLAN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-plan-v1"
JOB_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-worker-job-v1"
SUMMARY_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-model-replay-v1"
SUITE_ID = "corelm-voidtoken-crossmodel-v3-author-verified-development-e2e"
RUN_ID = re.compile(r"development-e2e-[0-9a-f]{64}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
MODELS = ("gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py")
DATASET_ID = "UniversalDependencies/UD_English-PUD:r2.18:test"
DATASET_REPOSITORY = "UniversalDependencies/UD_English-PUD"
DATASET_RELEASE_TAG = "r2.18"
DATASET_REVISION = "e173a1be1b442faf34e7d5a502189ad5d9d1e197"
DATASET_TREE = "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde"
DATASET_SPLIT = "test"
DATASET_FILE = "en_pud-ud-test.conllu"
DATASET_BYTES = 1_386_858
DATASET_SHA256 = "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa"
DATASET_ROWS = 1_000
DATASET_EVIDENCE_PATH = "inputs/corpus/en_pud-ud-test.conllu"
FULL_ASSET_RECEIPT_PATH = "inputs/model-assets.full-rehash.json"
JOINED_DATASET_BYTES = 112_419
JOINED_DATASET_SHA256 = (
    "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea"
)
CORPUS_MANIFEST_BYTES = 1_985
CORPUS_MANIFEST_SHA256 = (
    "b18149b73be0bb2510759c8ca567c4ab0a9f04f7960eb4c6a44b6eedfbda9634"
)
CORPORA = (DATASET_ID,)
MODEL_FILES = (
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
)
CANDIDATE = {
    "backend": "voidtoken-v5",
    "groupSize": 128,
    "transformBlockSize": 128,
    "codeCompression": "zlib-9",
    "scaleCompression": "zlib-9",
    "signMode": "none",
}
RAW_TOKEN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-raw-token-v1"
PAGE_TOKEN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-page-token-v1"
CONTAINER_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-container-v1"
RECORD_MAGIC = b"CORELM-UD-ENGLISH-PUD-R2.18-DEVELOPMENT-RECORD\0"
CONLLU_TOKEN_ID = re.compile(
    r"[1-9][0-9]*(?:-[1-9][0-9]*|\.[1-9][0-9]*)?\Z"
)
CONTROL_SOURCE_PATHS = (
    "v3/run_real_e2e_control.py",
    "v3/development_model_replay.py",
    "v3/development_corpus.py",
    "v3/development_runtime.py",
    "v3/development_artifact_verifier.py",
    "v3/freeze_manifest.py",
    "v3/model_worker.py",
    "v3/independent_model_replay.py",
    "v3/cache_adapter.py",
    "v3/evidence.py",
    "v3/mediawiki_snapshot.py",
    "v3/protocol.py",
    "v3/reproducibility.py",
    "v3/create_asset_receipt.py",
    "v3/preflight.py",
    "v3/fetch_assets.py",
)
EXPECTED_EXECUTION = {
    "device": "cpu",
    "intraOpThreads": 2,
    "interOpThreads": 1,
    "modelDtype": "float32",
    "cacheBaseline": "float32-to-bfloat16-to-float32",
    "attentionImplementation": "eager",
    "prefillTokens": 383,
    "predictionTokensPerPage": 128,
    "maximumWorkerRSSBytes": 4294967296,
    "watchdogPollMilliseconds": 250,
    "deterministicAlgorithms": "fail-closed",
    "modelsSequential": True,
}
EXPECTED_MODEL_IDENTITIES = {
    "gpt-neo-125m": {
        "repository": "EleutherAI/gpt-neo-125m",
        "revision": "21def0189f5705e2521767faed922f1f15e7d7db",
        "layers": 12,
        "vocabSize": 50257,
        "weightBytes": 525979192,
        "weightSHA256": "52738cbfb54e25a232598242f60ef19ee193d36090b98fe649b10c02724b3521",
    },
    "smollm2-360m": {
        "repository": "HuggingFaceTB/SmolLM2-360M",
        "revision": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
        "layers": 32,
        "vocabSize": 49152,
        "weightBytes": 723674912,
        "weightSHA256": "7aaff6661428bed033abba9522bec81938678642cca3181fe752b6ca9e1e540f",
    },
    "tiny-starcoder-py": {
        "repository": "bigcode/tiny_starcoder_py",
        "revision": "8547527bef0bc927268c1653cce6948c5c242dd1",
        "layers": 20,
        "vocabSize": 49152,
        "weightBytes": 656601304,
        "weightSHA256": "15fa942f055b618d5ca6283f5c27278a475ff12e53dc704b9658ffd5160d4021",
    },
}
EXPECTED_CODEC_SOURCE = {
    "repository": "https://github.com/ALLPROTO/core-lm-benchmark.git",
    "commit": "2e8d3b1591ee4a1ed822310f330317936871ff2b",
    "tree": "c0bb15784d252cd5036757bc64765c773a5f16e8",
    "requiredFiles": {
        "RealLLM/app_proof_core.py": {
            "bytes": 43127,
            "sha256": "16940683af7b182a588404a493d54e17e029288f4947f2e7e9ab6a4f1c106bd4",
        },
        "RealLLM/benchmark_real_llm.py": {
            "bytes": 67362,
            "sha256": "b5e7b301222501e148d54cda3f0d04997e6a061051cedc6393d1a87b638522d0",
        },
        "RealLLM/codecs.py": {
            "bytes": 23987,
            "sha256": "fe5763b7cb0b2e775436c7414a1af48704095518e0428fe4a7965b84f0ce7a05",
        },
        "RealLLM/requirements.lock": {
            "bytes": 55781,
            "sha256": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
        },
        "RealLLM/voidtoken_v5.py": {
            "bytes": 35374,
            "sha256": "80ed51aa2a201dbdaae36434709a50a8a679fa84d29b08ad7b083c14cec33758",
        },
    },
}
EXPECTED_CONTROL_DATASET = {
    "datasetId": DATASET_ID,
    "repository": DATASET_REPOSITORY,
    "revision": DATASET_REVISION,
    "tree": DATASET_TREE,
    "releaseTag": DATASET_RELEASE_TAG,
    "split": DATASET_SPLIT,
    "splitPurpose": (
        "upstream test split reused only as a non-scientific development "
        "control; it is not a blind scientific test result"
    ),
    "file": DATASET_FILE,
    "format": "CoNLL-U",
    "bytes": DATASET_BYTES,
    "sha256": DATASET_SHA256,
    "rows": DATASET_ROWS,
    "rowExtraction": (
        "exactly one '# text = ' value from each LF-delimited CoNLL-U "
        "sentence block; prefix removed; text otherwise unchanged"
    ),
    "joinedTextBytes": JOINED_DATASET_BYTES,
    "joinedTextSHA256": JOINED_DATASET_SHA256,
    "license": "CC-BY-SA-3.0",
    "manifestPath": "v3/development-corpus.draft.json",
    "manifestBytes": CORPUS_MANIFEST_BYTES,
    "manifestSHA256": CORPUS_MANIFEST_SHA256,
}
EXPECTED_CORPUS_MANIFEST = {
    "schemaVersion": "corelm-crossmodel-livewiki-v3-development-corpus-v1",
    "status": "PINNED_REAL_CORPUS_WITH_EXPLICIT_REDISTRIBUTION_LICENSE",
    "queriedAtUTC": "2026-08-03T23:02:05Z",
    **{
        key: EXPECTED_CONTROL_DATASET[key]
        for key in (
            "datasetId",
            "repository",
            "revision",
            "tree",
            "releaseTag",
            "split",
            "splitPurpose",
            "file",
            "format",
            "bytes",
            "sha256",
        )
    },
    "sourceURL": (
        "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/"
        f"{DATASET_REVISION}/{DATASET_FILE}"
    ),
    "rows": DATASET_ROWS,
    "rowExtraction": EXPECTED_CONTROL_DATASET["rowExtraction"],
    "joinedTextBytes": JOINED_DATASET_BYTES,
    "joinedTextSHA256": JOINED_DATASET_SHA256,
    "contentSynthetic": False,
    "license": "CC-BY-SA-3.0",
    "licenseFile": {
        "path": "LICENSE.txt",
        "bytes": 19_556,
        "sha256": (
            "b278eb53fe50b8bb7fa0d90fb8536c35fdcaa80f9d63812cb51db539555d2a89"
        ),
        "url": (
            "https://raw.githubusercontent.com/UniversalDependencies/"
            f"UD_English-PUD/{DATASET_REVISION}/LICENSE.txt"
        ),
    },
    "readme": {
        "path": "README.md",
        "bytes": 6_986,
        "sha256": (
            "9558eb70a6565a40e2ecf06d0f38c9f6117de0f0f8bc5021805bdce51ee0d67f"
        ),
        "url": (
            "https://raw.githubusercontent.com/UniversalDependencies/"
            f"UD_English-PUD/{DATASET_REVISION}/README.md"
        ),
    },
    "redistributionObligations": {
        "attributionRequired": True,
        "shareAlikeRequired": True,
        "licenseNoticeRequired": True,
        "upstreamWarranty": "none",
    },
}
EXPECTED_ADAPTER = {
    "source": "pinned-ud-english-pud-r2.18-test-conllu",
    "sentenceText": "exact-single-#-text-comment-per-block",
    "join": "two-LF-between-sentence-texts-within-each-slice",
    "partition": "all-source-sentences-equal-floor-boundaries-32",
    "partitions": 32,
    "records": 32,
    "contentSynthetic": False,
    "metadataEnvelopeScientificUse": "forbidden",
}


class DevelopmentReplayError(RuntimeError):
    """Raised when development evidence escapes or differs from its plan."""


def _guard_development_evidence_root(path: Path) -> Path:
    try:
        root = path.resolve(strict=True)
        project = PROJECT_ROOT.resolve(strict=True)
    except OSError as error:
        raise DevelopmentReplayError(
            "development evidence root cannot be resolved"
        ) from error
    if root.is_symlink() or not root.is_dir():
        raise DevelopmentReplayError("development evidence root is not a real directory")
    if root == project or root.is_relative_to(project):
        raise DevelopmentReplayError(
            "development evidence root must be outside the repository"
        )
    if any(part.endswith(".one-shot-result") for part in root.parts):
        raise DevelopmentReplayError(
            "development evidence root must not occupy a scientific result namespace"
        )
    return root


def _digest_record(value: Any, *, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"bytes", "sha256"}
        or type(value.get("bytes")) is not int
        or value["bytes"] < 1
        or not isinstance(value.get("sha256"), str)
        or HEX_64.fullmatch(value["sha256"]) is None
    ):
        raise DevelopmentReplayError(f"{label} commitment is invalid")


def _verify_content_digest(value: dict[str, Any], *, label: str) -> None:
    digest = value.get("contentSHA256")
    if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
        raise DevelopmentReplayError(f"{label} content digest is invalid")
    payload = dict(value)
    del payload["contentSHA256"]
    if replay.sha256_bytes(replay.canonical_json_bytes(payload)) != digest:
        raise DevelopmentReplayError(f"{label} content digest differs")


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DevelopmentReplayError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise DevelopmentReplayError(f"{label} contains a non-finite number: {value}")

    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DevelopmentReplayError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise DevelopmentReplayError(f"{label} must contain a JSON object")
    return value


def _load_archived_inputs(
    evidence_root: Path, plan: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    paths = {
        "designRegistration": "inputs/design-registration.draft.json",
        "modelAssetManifest": "inputs/model-assets.draft.json",
        "fullAssetReceipt": FULL_ASSET_RECEIPT_PATH,
        "developmentCorpusManifest": "inputs/development-corpus.draft.json",
        "licenseSourceEvidence": "inputs/LICENSES/source-evidence.json",
        "runtimeManifest": "inputs/runtime-manifest.json",
    }
    documents: dict[str, dict[str, Any]] = {}
    for binding, relative in paths.items():
        commitment = plan["inputBindings"][binding]
        raw = replay.read_beneath(
            evidence_root,
            relative,
            maximum_bytes=32 * 1024 * 1024,
            expected_bytes=commitment["bytes"],
            expected_sha256=commitment["sha256"],
        )
        documents[binding] = _strict_json_object(raw, label=relative)

    rights_raw: dict[str, bytes] = {}
    for binding, relative in {
        "assetLicenseMatrix": "inputs/LICENSES/ASSET_LICENSES.md",
        "udEnglishPudReadme": (
            "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md"
        ),
        "udEnglishPudLicense": (
            "inputs/LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
        ),
        "udEnglishPudAttribution": (
            "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"
        ),
    }.items():
        commitment = plan["inputBindings"][binding]
        rights_raw[binding] = replay.read_beneath(
            evidence_root,
            relative,
            maximum_bytes=4 * 1024 * 1024,
            expected_bytes=commitment["bytes"],
            expected_sha256=commitment["sha256"],
        )
    try:
        verify_rights_evidence(
            documents["licenseSourceEvidence"],
            rights_raw["udEnglishPudReadme"],
            rights_raw["udEnglishPudLicense"],
            rights_raw["udEnglishPudAttribution"],
        )
    except ValueError as error:
        raise DevelopmentReplayError(
            "archived UD English PUD rights evidence differs"
        ) from error
    try:
        asset_license_matrix = rights_raw["assetLicenseMatrix"].decode(
            "utf-8", errors="strict"
        )
    except UnicodeDecodeError as error:
        raise DevelopmentReplayError(
            "archived asset license matrix is not UTF-8"
        ) from error
    if (
        "UD English PUD" not in asset_license_matrix
        or "CC BY-SA 3.0" not in asset_license_matrix
        or "without added restrictions" not in asset_license_matrix
    ):
        raise DevelopmentReplayError(
            "archived asset license matrix omits PUD obligations"
        )

    corpus_manifest = documents["developmentCorpusManifest"]
    if corpus_manifest != EXPECTED_CORPUS_MANIFEST:
        raise DevelopmentReplayError("archived development corpus manifest differs")

    design = documents["designRegistration"]
    if design.get("codecSource") != EXPECTED_CODEC_SOURCE:
        raise DevelopmentReplayError("archived design codec binding differs")
    candidate = design.get("candidate")
    if not isinstance(candidate, dict) or {
        key: candidate.get(key) for key in CANDIDATE
    } != CANDIDATE:
        raise DevelopmentReplayError("archived design candidate differs")
    controls = design.get("developmentControls")
    control_dataset = controls.get("dataset") if isinstance(controls, dict) else None
    if (
        not isinstance(controls, dict)
        or not isinstance(control_dataset, dict)
        or controls.get("syntheticInputsForbidden") is not True
        or controls.get("futureCorpusUsed") is not False
        or controls.get("nistUsed") is not False
        or controls.get("countsTowardScientificVerdict") is not False
        or controls.get("usedForCandidateSelectionOrTuning") is not False
        or control_dataset != EXPECTED_CONTROL_DATASET
    ):
        raise DevelopmentReplayError("archived development control boundary differs")
    design_models = design.get("models")
    if not isinstance(design_models, list) or [
        item.get("key") for item in design_models if isinstance(item, dict)
    ] != list(MODELS):
        raise DevelopmentReplayError("archived design model order differs")
    for plan_model, design_model in zip(plan["models"], design_models, strict=True):
        for field in (
            "key",
            "repository",
            "revision",
            "layers",
            "vocabSize",
            "candidateBitsByLayer",
        ):
            if design_model.get(field) != plan_model[field]:
                raise DevelopmentReplayError(
                    f"archived design model binding differs: {plan_model['key']}/{field}"
                )

    manifest = documents["modelAssetManifest"]
    receipt = documents["fullAssetReceipt"]
    _verify_content_digest(receipt, label="archived full asset receipt")
    manifest_models = manifest.get("models")
    receipt_models = receipt.get("models")
    if not isinstance(manifest_models, dict) or not isinstance(receipt_models, dict):
        raise DevelopmentReplayError("archived model inventories are invalid")
    for model in plan["models"]:
        key = model["key"]
        manifest_model = manifest_models.get(key)
        receipt_model = receipt_models.get(key)
        if not isinstance(manifest_model, dict) or not isinstance(receipt_model, dict):
            raise DevelopmentReplayError(f"archived model receipt is absent: {key}")
        for field in ("repository", "revision"):
            if (
                manifest_model.get(field) != model[field]
                or receipt_model.get(field) != model[field]
            ):
                raise DevelopmentReplayError(
                    f"archived model identity differs: {key}/{field}"
                )
        manifest_files = manifest_model.get("files")
        receipt_files = receipt_model.get("files")
        if (
            not isinstance(manifest_files, dict)
            or not isinstance(receipt_files, dict)
            or set(manifest_files) != set(MODEL_FILES)
            or set(receipt_files) != set(MODEL_FILES)
        ):
            raise DevelopmentReplayError(f"archived model file set differs: {key}")
        for filename in MODEL_FILES:
            expected = {
                "bytes": model["files"][filename]["bytes"],
                "sha256": model["files"][filename]["sha256"],
            }
            manifest_file = manifest_files[filename]
            if (
                not isinstance(manifest_file, dict)
                or {field: manifest_file.get(field) for field in expected} != expected
                or receipt_files[filename] != expected
            ):
                raise DevelopmentReplayError(
                    f"archived model asset differs: {key}/{filename}"
                )

    runtime = documents["runtimeManifest"]
    _verify_content_digest(runtime, label="archived runtime manifest")
    runtime_host = runtime.get("host")
    if (
        runtime.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v3-runtime-manifest-v1"
        or runtime.get("status") != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY"
        or not isinstance(runtime_host, dict)
        or runtime_host.get("system") != "Darwin"
        or runtime_host.get("machine") != "arm64"
    ):
        raise DevelopmentReplayError("archived runtime host boundary differs")
    lab = plan["inputBindings"]["labSource"]
    runtime_lab = runtime.get("labSource")
    runtime_codec = runtime.get("codecSource")
    if (
        not isinstance(runtime_lab, dict)
        or runtime_lab.get("commit") != lab["commit"]
        or runtime_lab.get("tree") != lab["tree"]
        or runtime_lab.get("worktreeClean") is not True
        or not isinstance(runtime_codec, dict)
        or runtime_codec.get("commit") != EXPECTED_CODEC_SOURCE["commit"]
        or runtime_codec.get("tree") != EXPECTED_CODEC_SOURCE["tree"]
        or runtime_codec.get("worktreeClean") is not True
    ):
        raise DevelopmentReplayError("archived runtime source identity differs")
    distributions = runtime.get("installedDistributions")
    if not isinstance(distributions, list):
        raise DevelopmentReplayError("archived runtime distribution inventory differs")
    installed = {
        item.get("normalizedName"): item.get("version")
        for item in distributions
        if isinstance(item, dict)
    }
    expected_versions = {
        "jsonschema": "4.25.1",
        "numpy": "2.5.1",
        "pyarrow": "23.0.1",
        "safetensors": "0.8.0",
        "tokenizers": "0.22.2",
        "torch": "2.13.0",
        "transformers": "5.14.1",
    }
    if {name: installed.get(name) for name in expected_versions} != expected_versions:
        raise DevelopmentReplayError("archived runtime dependency versions differ")
    return documents


def _verify_live_lab_source(plan: dict[str, Any]) -> None:
    expected = plan["inputBindings"]["labSource"]
    commands = {
        "commit": ["rev-parse", "HEAD"],
        "tree": ["rev-parse", "HEAD^{tree}"],
        "repository": ["remote", "get-url", "origin"],
        "status": ["status", "--porcelain=v1", "--untracked-files=all"],
    }
    observed: dict[str, str] = {}
    for label, arguments in commands.items():
        try:
            completed = subprocess.run(
                ["/usr/bin/git", *arguments],
                cwd=PROJECT_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DevelopmentReplayError("live lab source cannot be inspected") from error
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 1024 * 1024:
            raise DevelopmentReplayError(f"live lab source query failed: {label}")
        try:
            observed[label] = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise DevelopmentReplayError("live lab source output is not UTF-8") from error
    if (
        observed["commit"] != expected["commit"]
        or observed["tree"] != expected["tree"]
        or observed["repository"].rstrip("/").removesuffix(".git")
        != expected["repository"].rstrip("/").removesuffix(".git")
        or observed["status"]
    ):
        raise DevelopmentReplayError("live lab source differs or is dirty")


def _private_entries(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = plan["privateFiles"]
    if not isinstance(values, list) or not values:
        raise DevelopmentReplayError("development private file inventory is absent")
    result: dict[str, dict[str, Any]] = {}
    for entry in values:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "bytes", "sha256", "role"}
            or not isinstance(entry.get("path"), str)
            or entry["path"] in result
            or type(entry.get("bytes")) is not int
            or entry["bytes"] < 1
            or not isinstance(entry.get("sha256"), str)
            or HEX_64.fullmatch(entry["sha256"]) is None
            or entry.get("role")
            not in {
                "model-asset",
                "development-corpus-record",
                "development-corpus-source",
            }
        ):
            raise DevelopmentReplayError(
                "development private file inventory contains an invalid entry"
            )
        replay._safe_relative(entry["path"], label="development private file")
        result[entry["path"]] = entry
    return result


def validate_plan(plan: Any) -> None:
    expected = {
        "schemaVersion",
        "suiteId",
        "runId",
        "status",
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
        "modelExecutionOrder",
        "selectedCorpora",
        "candidate",
        "models",
        "pages",
        "privateFiles",
        "jobs",
        "inputBindings",
        "execution",
        "controlConfigurationSHA256",
        "contentSHA256",
    }
    if not isinstance(plan, dict) or set(plan) != expected:
        raise DevelopmentReplayError("development plan fields differ")
    _verify_content_digest(plan, label="development plan")
    if (
        plan["schemaVersion"] != PLAN_SCHEMA
        or plan["suiteId"] != SUITE_ID
        or plan["status"] != "SEALED_NON_SCIENTIFIC_DEVELOPMENT_INPUT"
        or plan["countsTowardScientificVerdict"] is not False
        or plan["usedForCandidateSelectionOrTuning"] is not False
        or plan["scientificAttemptStateCreated"] is not False
        or plan["nistUsed"] is not False
        or plan["futureCorpusUsed"] is not False
        or plan["thresholdsApplied"] is not False
    ):
        raise DevelopmentReplayError("development plan boundary differs")
    if not isinstance(plan["runId"], str) or RUN_ID.fullmatch(plan["runId"]) is None:
        raise DevelopmentReplayError("development run identity differs")
    if (
        not isinstance(plan["controlConfigurationSHA256"], str)
        or HEX_64.fullmatch(plan["controlConfigurationSHA256"]) is None
        or plan["runId"]
        != "development-e2e-" + plan["controlConfigurationSHA256"]
    ):
        raise DevelopmentReplayError("development configuration identity differs")
    if tuple(plan["modelExecutionOrder"]) != MODELS:
        raise DevelopmentReplayError("development model order differs")
    if tuple(plan["selectedCorpora"]) != CORPORA:
        raise DevelopmentReplayError("development corpus namespaces differ")
    if plan["candidate"] != CANDIDATE:
        raise DevelopmentReplayError("development candidate differs")
    bindings = plan["inputBindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "designRegistration",
        "modelAssetManifest",
        "fullAssetReceipt",
        "developmentCorpusManifest",
        "licenseSourceEvidence",
        "assetLicenseMatrix",
        "udEnglishPudReadme",
        "udEnglishPudLicense",
        "udEnglishPudAttribution",
        "developmentDataset",
        "runtimeManifest",
        "labSource",
        "joinedCorpusText",
        "conlluDecode",
        "codecSource",
        "controlSources",
        "adapter",
    }:
        raise DevelopmentReplayError("development input bindings differ")
    for key in (
        "designRegistration",
        "modelAssetManifest",
        "fullAssetReceipt",
        "developmentCorpusManifest",
        "licenseSourceEvidence",
        "assetLicenseMatrix",
        "udEnglishPudReadme",
        "udEnglishPudLicense",
        "udEnglishPudAttribution",
        "developmentDataset",
        "runtimeManifest",
        "joinedCorpusText",
    ):
        _digest_record(bindings[key], label=f"development {key}")
    if bindings["developmentDataset"] != {
        "bytes": DATASET_BYTES,
        "sha256": DATASET_SHA256,
    }:
        raise DevelopmentReplayError("development dataset bytes are not the pin")
    if bindings["developmentCorpusManifest"] != {
        "bytes": CORPUS_MANIFEST_BYTES,
        "sha256": CORPUS_MANIFEST_SHA256,
    }:
        raise DevelopmentReplayError("development corpus manifest differs")
    if bindings["joinedCorpusText"] != {
        "bytes": JOINED_DATASET_BYTES,
        "sha256": JOINED_DATASET_SHA256,
    }:
        raise DevelopmentReplayError("development joined corpus text differs")
    if bindings["conlluDecode"] != {
        "parser": "strict-stdlib-conllu-text-v1",
        "sentences": DATASET_ROWS,
        "sourceConlluSHA256": DATASET_SHA256,
    }:
        raise DevelopmentReplayError("development CoNLL-U decoder binding differs")
    if bindings["modelAssetManifest"] != {
        "bytes": 6381,
        "sha256": "eef95202c08c5a44ef85197f7519b36c3336f4ff4b04e786bd415b06b8b18eb9",
    }:
        raise DevelopmentReplayError("development model manifest differs")
    if bindings["fullAssetReceipt"] != {
        "bytes": 4272,
        "sha256": "a576fd188afd9ace4368c2bc30fd0bbf90492741efa342a847a5805147333d2b",
    }:
        raise DevelopmentReplayError("development full asset receipt differs")
    lab_source = bindings["labSource"]
    if (
        not isinstance(lab_source, dict)
        or set(lab_source) != {"repository", "commit", "tree", "worktreeClean"}
        or lab_source["repository"]
        != "https://github.com/ALLPROTO/core-lm-cross-model-lab.git"
        or not isinstance(lab_source["commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", lab_source["commit"]) is None
        or not isinstance(lab_source["tree"], str)
        or re.fullmatch(r"[0-9a-f]{40}", lab_source["tree"]) is None
        or lab_source["worktreeClean"] is not True
    ):
        raise DevelopmentReplayError("development lab source binding is invalid")
    if bindings["codecSource"] != EXPECTED_CODEC_SOURCE:
        raise DevelopmentReplayError("development codec binding differs")
    if not isinstance(bindings["controlSources"], list) or not bindings["controlSources"]:
        raise DevelopmentReplayError("development control source bindings are absent")
    for source in bindings["controlSources"]:
        if not isinstance(source, dict) or set(source) != {"path", "bytes", "sha256"}:
            raise DevelopmentReplayError("development control source binding is invalid")
        _digest_record(
            {"bytes": source["bytes"], "sha256": source["sha256"]},
            label="development control source",
        )
    if tuple(source["path"] for source in bindings["controlSources"]) != CONTROL_SOURCE_PATHS:
        raise DevelopmentReplayError("development control source paths differ")
    adapter = bindings["adapter"]
    if adapter != EXPECTED_ADAPTER:
        raise DevelopmentReplayError("development corpus adapter differs")

    models = plan["models"]
    if not isinstance(models, list) or [item.get("key") for item in models] != list(MODELS):
        raise DevelopmentReplayError("development model bindings differ")
    entries = _private_entries(plan)
    expected_private: set[str] = set()
    source_dataset_entry = {
        "path": DATASET_EVIDENCE_PATH,
        "bytes": DATASET_BYTES,
        "sha256": DATASET_SHA256,
        "role": "development-corpus-source",
    }
    if entries.get(DATASET_EVIDENCE_PATH) != source_dataset_entry:
        raise DevelopmentReplayError("development private dataset binding differs")
    expected_private.add(DATASET_EVIDENCE_PATH)
    for model in models:
        if not isinstance(model, dict) or set(model) != {
            "key",
            "repository",
            "revision",
            "layers",
            "vocabSize",
            "candidateBitsByLayer",
            "files",
        }:
            raise DevelopmentReplayError("development model fields differ")
        key = model["key"]
        identity = EXPECTED_MODEL_IDENTITIES[key]
        if (
            not isinstance(model["repository"], str)
            or not isinstance(model["revision"], str)
            or type(model["layers"]) is not int
            or model["layers"] < 3
            or type(model["vocabSize"]) is not int
            or model["vocabSize"] < 1
            or not isinstance(model["candidateBitsByLayer"], list)
            or len(model["candidateBitsByLayer"]) != model["layers"]
            or any(type(bits) is not int or bits not in {8, 9} for bits in model["candidateBitsByLayer"])
            or not isinstance(model["files"], dict)
            or set(model["files"]) != set(MODEL_FILES)
        ):
            raise DevelopmentReplayError(f"development model binding is invalid: {key}")
        if any(model[field] != identity[field] for field in (
            "repository", "revision", "layers", "vocabSize"
        )):
            raise DevelopmentReplayError(f"development model identity differs: {key}")
        expected_bits = [
            9 if index in {0, identity["layers"] // 3} else 8
            for index in range(identity["layers"])
        ]
        if model["candidateBitsByLayer"] != expected_bits:
            raise DevelopmentReplayError(f"development candidate schedule differs: {key}")
        for filename in MODEL_FILES:
            specification = model["files"][filename]
            if not isinstance(specification, dict) or set(specification) != {
                "path",
                "bytes",
                "sha256",
            }:
                raise DevelopmentReplayError("development model asset fields differ")
            path = f"models/{key}/{filename}"
            if specification["path"] != path:
                raise DevelopmentReplayError("development model asset path differs")
            _digest_record(
                {"bytes": specification["bytes"], "sha256": specification["sha256"]},
                label="development model asset",
            )
            if entries.get(path) != {**specification, "role": "model-asset"}:
                raise DevelopmentReplayError("development private model binding differs")
            expected_private.add(path)
        weight = model["files"]["model.safetensors"]
        if (
            weight["bytes"] != identity["weightBytes"]
            or weight["sha256"] != identity["weightSHA256"]
        ):
            raise DevelopmentReplayError(f"development model weight differs: {key}")

    pages = plan["pages"]
    if not isinstance(pages, dict) or tuple(pages) != CORPORA:
        raise DevelopmentReplayError("development dataset page binding differs")
    for corpus in CORPORA:
        previous_end = 0
        records = pages[corpus]
        if not isinstance(records, list) or len(records) != 32:
            raise DevelopmentReplayError("development page count differs")
        for index, page in enumerate(records):
            if not isinstance(page, dict) or set(page) != {
                "pageSelectionIndex",
                "sourceSliceIndex",
                "sentenceStart",
                "sentenceEnd",
                "recordPath",
                "recordBytes",
                "recordSHA256",
                "inputTextBytes",
                "inputTextSHA256",
            }:
                raise DevelopmentReplayError("development page fields differ")
            path = f"records/ud-english-pud/slice-{index:02d}.bin"
            if (
                page["pageSelectionIndex"] != index
                or page["sourceSliceIndex"] != index
                or page["sentenceStart"] != DATASET_ROWS * index // 32
                or page["sentenceEnd"] != DATASET_ROWS * (index + 1) // 32
                or page["sentenceStart"] != previous_end
                or type(page["sentenceEnd"]) is not int
                or page["sentenceEnd"] <= page["sentenceStart"]
                or page["recordPath"] != path
            ):
                raise DevelopmentReplayError(
                    "development deterministic sentence mapping differs"
                )
            previous_end = page["sentenceEnd"]
            for prefix in ("record", "inputText"):
                _digest_record(
                    {
                        "bytes": page[f"{prefix}Bytes"],
                        "sha256": page[f"{prefix}SHA256"],
                    },
                    label=f"development page {prefix}",
                )
            entry = entries.get(path)
            if entry != {
                "path": path,
                "bytes": page["recordBytes"],
                "sha256": page["recordSHA256"],
                "role": "development-corpus-record",
            }:
                raise DevelopmentReplayError("development private record binding differs")
            expected_private.add(path)
        if previous_end != DATASET_ROWS:
            raise DevelopmentReplayError("development dataset coverage differs")
    if set(entries) != expected_private:
        raise DevelopmentReplayError("development private inventory has extra files")

    jobs = plan["jobs"]
    if not isinstance(jobs, dict) or tuple(jobs) != MODELS:
        raise DevelopmentReplayError("development job commitments differ")
    for key in MODELS:
        commitment = jobs[key]
        if not isinstance(commitment, dict) or set(commitment) != {"path", "bytes", "sha256"}:
            raise DevelopmentReplayError("development job commitment fields differ")
        if commitment["path"] != f"jobs/{key}.json":
            raise DevelopmentReplayError("development job path differs")
        _digest_record(
            {"bytes": commitment["bytes"], "sha256": commitment["sha256"]},
            label="development job",
        )
    if plan["execution"] != EXPECTED_EXECUTION:
        raise DevelopmentReplayError("development execution boundary differs")
    configuration = {
        "schemaVersion": "corelm-crossmodel-v3-real-e2e-development-configuration-v1",
        "suiteId": SUITE_ID,
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "modelExecutionOrder": list(MODELS),
        "selectedCorpora": list(CORPORA),
        "candidate": dict(CANDIDATE),
        "models": plan["models"],
        "pages": plan["pages"],
        "execution": plan["execution"],
        "inputBindings": plan["inputBindings"],
    }
    if replay.sha256_bytes(replay.canonical_json_bytes(configuration)) != plan[
        "controlConfigurationSHA256"
    ]:
        raise DevelopmentReplayError("development configuration digest differs")


def expected_job(plan: dict[str, Any], model_key: str) -> dict[str, Any]:
    model = next(item for item in plan["models"] if item["key"] == model_key)
    pages: dict[str, list[dict[str, Any]]] = {}
    for corpus in CORPORA:
        pages[corpus] = [
            {
                "pageSelectionIndex": page["pageSelectionIndex"],
                "sourceSliceIndex": page["sourceSliceIndex"],
                "sentenceStart": page["sentenceStart"],
                "sentenceEnd": page["sentenceEnd"],
                "recordPath": page["recordPath"],
                "recordBytes": page["recordBytes"],
                "recordSHA256": page["recordSHA256"],
            }
            for page in plan["pages"][corpus]
        ]
    return {
        "schemaVersion": JOB_SCHEMA,
        "suiteId": SUITE_ID,
        "runId": plan["runId"],
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "controlConfigurationSHA256": plan["controlConfigurationSHA256"],
        "sourceDataset": {
            "path": DATASET_EVIDENCE_PATH,
            "bytes": DATASET_BYTES,
            "sha256": DATASET_SHA256,
        },
        "model": {
            "key": model_key,
            "files": model["files"],
            "layers": model["layers"],
            "vocabSize": model["vocabSize"],
            "candidateBitsByLayer": model["candidateBitsByLayer"],
        },
        "selectedCorpora": list(CORPORA),
        "pages": pages,
        "candidate": dict(CANDIDATE),
        "seed": 0,
    }


def _group_one(
    records: list[dict[str, Any]], *, dataset_id: str, slice_index: int
) -> list[dict[str, Any]]:
    return [
        item
        for item in records
        if item.get("datasetId") == dataset_id
        and item.get("sourceSliceIndex") == slice_index
    ]


def _parse_conllu_source(raw: bytes) -> tuple[str, ...]:
    """Independently parse the exact PUD source with the standard library."""

    if type(raw) is not bytes:
        raise DevelopmentReplayError("development CoNLL-U source is not bytes")
    if len(raw) != DATASET_BYTES or hashlib.sha256(raw).hexdigest() != DATASET_SHA256:
        raise DevelopmentReplayError("development CoNLL-U source identity differs")
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or b"\x00" in raw:
        raise DevelopmentReplayError("development CoNLL-U encoding markers differ")
    if not raw.endswith(b"\n\n") or raw.endswith(b"\n\n\n"):
        raise DevelopmentReplayError(
            "development CoNLL-U must end in exactly two LF bytes"
        )
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentReplayError(
            "development CoNLL-U source is not strict UTF-8"
        ) from error
    if source.encode("utf-8", errors="strict") != raw:
        raise DevelopmentReplayError("development CoNLL-U UTF-8 is non-canonical")
    blocks = source.split("\n\n")
    if len(blocks) != DATASET_ROWS + 1 or blocks[-1] != "":
        raise DevelopmentReplayError("development CoNLL-U block count differs")

    texts: list[str] = []
    sent_ids: set[str] = set()
    for block_index, block in enumerate(blocks[:-1]):
        lines = block.split("\n")
        if not lines or any(not line for line in lines):
            raise DevelopmentReplayError(
                f"development CoNLL-U block is malformed: {block_index}"
            )
        sentence_ids: list[str] = []
        sentence_texts: list[str] = []
        token_seen = False
        syntactic_tokens = 0
        for line in lines:
            if line.startswith("#"):
                if token_seen or not line.startswith("# "):
                    raise DevelopmentReplayError(
                        f"development CoNLL-U metadata is misplaced: {block_index}"
                    )
                if line.startswith("# sent_id"):
                    if not line.startswith("# sent_id = "):
                        raise DevelopmentReplayError(
                            "development CoNLL-U sent_id metadata is malformed"
                        )
                    sentence_ids.append(line.removeprefix("# sent_id = "))
                if line.startswith("# text"):
                    if not line.startswith("# text = "):
                        raise DevelopmentReplayError(
                            "development CoNLL-U text metadata is malformed"
                        )
                    sentence_texts.append(line.removeprefix("# text = "))
                continue
            token_seen = True
            fields = line.split("\t")
            if len(fields) != 10 or CONLLU_TOKEN_ID.fullmatch(fields[0]) is None:
                raise DevelopmentReplayError(
                    f"development CoNLL-U row is malformed: {block_index}"
                )
            if "-" not in fields[0] and "." not in fields[0]:
                syntactic_tokens += 1
        if (
            len(sentence_ids) != 1
            or len(sentence_texts) != 1
            or not sentence_ids[0]
            or sentence_ids[0].strip() != sentence_ids[0]
            or not sentence_texts[0]
            or syntactic_tokens == 0
        ):
            raise DevelopmentReplayError(
                f"development CoNLL-U block metadata differs: {block_index}"
            )
        if sentence_ids[0] in sent_ids:
            raise DevelopmentReplayError("development CoNLL-U sent_id is duplicated")
        sent_ids.add(sentence_ids[0])
        texts.append(sentence_texts[0])

    joined = "\n\n".join(texts).encode("utf-8", errors="strict")
    if (
        len(joined) != JOINED_DATASET_BYTES
        or hashlib.sha256(joined).hexdigest() != JOINED_DATASET_SHA256
    ):
        raise DevelopmentReplayError("development joined PUD text differs")
    return tuple(texts)


def _record_field(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise DevelopmentReplayError(f"development record {label} is not text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise DevelopmentReplayError(
            f"development record {label} is not strict UTF-8"
        ) from error
    return len(encoded).to_bytes(8, "big") + encoded


def _serialize_development_record(
    *, sentence_start: int, sentence_end: int, content: str
) -> bytes:
    if (
        type(sentence_start) is not int
        or type(sentence_end) is not int
        or sentence_start < 0
        or sentence_end <= sentence_start
        or sentence_end > DATASET_ROWS
        or not isinstance(content, str)
        or not content
    ):
        raise DevelopmentReplayError("development record sentence range differs")
    return b"".join(
        (
            RECORD_MAGIC,
            _record_field(DATASET_ID, label="dataset ID"),
            _record_field(DATASET_REPOSITORY, label="repository"),
            _record_field(DATASET_RELEASE_TAG, label="release tag"),
            _record_field(DATASET_REVISION, label="revision"),
            _record_field(DATASET_TREE, label="tree"),
            _record_field(DATASET_SPLIT, label="split"),
            _record_field(DATASET_FILE, label="file"),
            _record_field(DATASET_SHA256, label="source SHA-256"),
            _record_field(JOINED_DATASET_SHA256, label="joined-text SHA-256"),
            sentence_start.to_bytes(8, "big"),
            sentence_end.to_bytes(8, "big"),
            _record_field(content, label="content"),
        )
    )


def _parse_development_record(raw: bytes) -> dict[str, Any]:
    """Independently parse and reconstruct the PUD development envelope."""

    if type(raw) is not bytes or not raw.startswith(RECORD_MAGIC):
        raise DevelopmentReplayError("development PUD record magic differs")
    offset = len(RECORD_MAGIC)

    def take(size: int, label: str) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(raw):
            raise DevelopmentReplayError(f"development record is truncated: {label}")
        value = raw[offset : offset + size]
        offset += size
        return value

    def number(label: str) -> int:
        return int.from_bytes(take(8, label), "big")

    def text(label: str) -> str:
        encoded = take(number(f"{label} length"), label)
        try:
            value = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise DevelopmentReplayError(
                f"development record is not UTF-8: {label}"
            ) from error
        if value.encode("utf-8", errors="strict") != encoded:
            raise DevelopmentReplayError(
                f"development record is non-canonical: {label}"
            )
        return value

    value = {
        "datasetId": text("dataset ID"),
        "repository": text("repository"),
        "releaseTag": text("release tag"),
        "revision": text("revision"),
        "tree": text("tree"),
        "split": text("split"),
        "file": text("file"),
        "sourceSHA256": text("source SHA-256"),
        "joinedTextSHA256": text("joined-text SHA-256"),
        "sentenceStart": number("sentence start"),
        "sentenceEnd": number("sentence end"),
        "content": text("content"),
    }
    if offset != len(raw):
        raise DevelopmentReplayError("development record has trailing bytes")
    expected_identity = {
        "datasetId": DATASET_ID,
        "repository": DATASET_REPOSITORY,
        "releaseTag": DATASET_RELEASE_TAG,
        "revision": DATASET_REVISION,
        "tree": DATASET_TREE,
        "split": DATASET_SPLIT,
        "file": DATASET_FILE,
        "sourceSHA256": DATASET_SHA256,
        "joinedTextSHA256": JOINED_DATASET_SHA256,
    }
    if any(value[key] != expected for key, expected in expected_identity.items()):
        raise DevelopmentReplayError("development record provenance differs")
    if (
        value["sentenceStart"] < 0
        or value["sentenceEnd"] <= value["sentenceStart"]
        or value["sentenceEnd"] > DATASET_ROWS
        or not value["content"]
    ):
        raise DevelopmentReplayError("development record sentence range differs")
    rebuilt = _serialize_development_record(
        sentence_start=value["sentenceStart"],
        sentence_end=value["sentenceEnd"],
        content=value["content"],
    )
    if rebuilt != raw:
        raise DevelopmentReplayError("development record reconstruction differs")
    return value


def replay_development_page(
    *,
    backend: replay.PageReplayBackend,
    run_id: str,
    model_key: str,
    slice_index: int,
    sentence_start: int,
    sentence_end: int,
    expected_content: str,
    record_raw: bytes,
    page_evidence: dict[str, Any],
    raw_evidence: list[dict[str, Any]],
    container_evidence: list[dict[str, Any]],
    candidate: dict[str, Any],
    bits_by_layer: list[int],
    container_reader: Any,
) -> dict[str, Any]:
    """Replay one real PUD sentence slice with independent model/VTL5 code."""

    import numpy as np

    parsed = _parse_development_record(record_raw)
    if (
        parsed["sentenceStart"] != sentence_start
        or parsed["sentenceEnd"] != sentence_end
        or parsed["content"] != expected_content
    ):
        raise DevelopmentReplayError("development record sentence binding differs")
    token_ids = backend.tokenize(parsed["content"])
    if len(token_ids) < replay.PAGE_TOKENS:
        raise DevelopmentReplayError("development row slice has fewer than 512 tokens")
    token_ids = token_ids[: replay.PAGE_TOKENS]
    identity = {
        "suiteId": SUITE_ID,
        "runId": run_id,
        "modelKey": model_key,
        "datasetId": DATASET_ID,
        "sourceSliceIndex": slice_index,
        "pageSelectionIndex": slice_index,
    }
    page_fields = set(identity) | {
        "schemaVersion", "vocabSize", "first512TokenIds", "first512StreamSHA256"
    }
    if (
        set(page_evidence) != page_fields
        or page_evidence.get("schemaVersion") != PAGE_TOKEN_SCHEMA
        or any(page_evidence.get(key) != value for key, value in identity.items())
        or page_evidence.get("vocabSize") != backend.vocab_size
        or page_evidence.get("first512TokenIds") != token_ids
        or page_evidence.get("first512StreamSHA256")
        != replay.sha256_bytes(replay.token_id_stream(token_ids))
    ):
        raise DevelopmentReplayError("development token evidence differs")
    prefix = token_ids[: replay.PREFILL_TOKENS]
    continuation = token_ids[replay.PREFILL_TOKENS : -1]
    targets = token_ids[replay.PREFILL_TOKENS + 1 :]
    baseline = backend.baseline_cache(prefix)
    if len(baseline) != backend.layers or len(bits_by_layer) != backend.layers:
        raise DevelopmentReplayError("development cache layer count differs")
    shape = (replay.PREFILL_TOKENS, backend.trajectory_width)
    candidates: list[Any] = []
    container_commitments: list[dict[str, Any]] = []
    container_fields = set(identity) | {
        "schemaVersion", "layerIndex", "denseBF16Bytes", "containerBytes",
        "containerSHA256", "relativePath", "structuralReplay",
    }
    ordered_containers = sorted(container_evidence, key=lambda item: item.get("layerIndex", -1))
    if len(ordered_containers) != backend.layers:
        raise DevelopmentReplayError("development container coverage differs")
    for layer_index, record in enumerate(ordered_containers):
        layer = np.asarray(baseline[layer_index])
        expected_path = (
            f"containers/{model_key}/{DATASET_ID}/slice-{slice_index:02d}/"
            f"layer-{layer_index:02d}.vtl5"
        )
        if (
            layer.shape != shape
            or layer.dtype != np.float32
            or not np.isfinite(layer).all()
            or set(record) != container_fields
            or record.get("schemaVersion") != CONTAINER_SCHEMA
            or any(record.get(key) != value for key, value in identity.items())
            or record.get("layerIndex") != layer_index
            or record.get("denseBF16Bytes") != int(layer.size) * 2
            or record.get("relativePath") != expected_path
            or record.get("structuralReplay") is not True
        ):
            raise DevelopmentReplayError("development container identity differs")
        raw = container_reader(record)
        if len(raw) != record["containerBytes"] or replay.sha256_bytes(raw) != record["containerSHA256"]:
            raise DevelopmentReplayError("development container bytes differ")
        decoded, metadata = replay.decode_vtl5_container(
            raw,
            expected_layer=layer_index,
            expected_bits=bits_by_layer[layer_index],
            expected_rows=replay.PREFILL_TOKENS,
            expected_columns=backend.trajectory_width,
            expected_group_size=candidate["groupSize"],
            expected_transform_block_size=candidate["transformBlockSize"],
            expected_sign_mode=candidate["signMode"],
            expected_input_sha256=replay._float32_sha256(layer),
        )
        candidates.append(np.ascontiguousarray(decoded, dtype=np.float32))
        container_commitments.append({
            "layerIndex": layer_index,
            "relativePath": expected_path,
            "containerBytes": len(raw),
            "containerSHA256": replay.sha256_bytes(raw),
            "inputSHA256": metadata["inputSha256"],
            "reconstructionSHA256": metadata["reconstructionSha256"],
        })
    computed = backend.evaluate(continuation, targets, baseline, candidates)
    metric_fields = {
        "targetTokenId", "baselineLossF32Bits", "candidateLossF32Bits",
        "baselineTop1TokenId", "candidateTop1TokenId",
    }
    raw_fields = set(identity) | {"schemaVersion", "predictionIndex"} | metric_fields
    ordered_raw = sorted(raw_evidence, key=lambda item: item.get("predictionIndex", -1))
    if len(ordered_raw) != replay.PREDICTION_TOKENS or len(computed) != replay.PREDICTION_TOKENS:
        raise DevelopmentReplayError("development raw-token coverage differs")
    for index, (record, expected) in enumerate(zip(ordered_raw, computed, strict=True)):
        if (
            set(record) != raw_fields
            or record.get("schemaVersion") != RAW_TOKEN_SCHEMA
            or any(record.get(key) != value for key, value in identity.items())
            or record.get("predictionIndex") != index
            or set(expected) != metric_fields
            or any(record[field] != expected[field] for field in metric_fields)
        ):
            raise DevelopmentReplayError(f"development prediction differs: {index}")
    return {
        "datasetId": DATASET_ID,
        "sourceSliceIndex": slice_index,
        "sentenceStart": sentence_start,
        "sentenceEnd": sentence_end,
        "predictions": replay.PREDICTION_TOKENS,
        "containers": backend.layers,
        "tokenStreamSHA256": page_evidence["first512StreamSHA256"],
        "containerCommitmentsSHA256": replay.sha256_bytes(
            replay.canonical_json_bytes(container_commitments)
        ),
    }


def run_development_replay(*, evidence_root: Path, private_root: Path) -> dict[str, Any]:
    evidence_root = _guard_development_evidence_root(evidence_root)
    plan_raw = replay.read_beneath(
        evidence_root, "development-plan.json", maximum_bytes=16 * 1024 * 1024
    )
    plan = replay.load_canonical_line(plan_raw, label="development plan")
    validate_plan(plan)
    _load_archived_inputs(evidence_root, plan)
    _verify_live_lab_source(plan)
    replay.install_network_denial()
    replay._configure_deterministic_cpu()
    dataset_raw = replay.read_beneath(
        evidence_root,
        DATASET_EVIDENCE_PATH,
        maximum_bytes=16 * 1024 * 1024,
        expected_bytes=DATASET_BYTES,
        expected_sha256=DATASET_SHA256,
    )
    private_dataset_raw = replay.read_beneath(
        private_root,
        DATASET_EVIDENCE_PATH,
        maximum_bytes=16 * 1024 * 1024,
        expected_bytes=DATASET_BYTES,
        expected_sha256=DATASET_SHA256,
    )
    if private_dataset_raw != dataset_raw:
        raise DevelopmentReplayError(
            "archived and private development corpus sources differ"
        )
    dataset_rows = _parse_conllu_source(dataset_raw)
    if plan["inputBindings"]["conlluDecode"] != {
        "parser": "strict-stdlib-conllu-text-v1",
        "sentences": len(dataset_rows),
        "sourceConlluSHA256": hashlib.sha256(dataset_raw).hexdigest(),
    }:
        raise DevelopmentReplayError("development CoNLL-U decode binding differs")
    joined_raw = "\n\n".join(dataset_rows).encode("utf-8", errors="strict")
    if plan["inputBindings"]["joinedCorpusText"] != {
        "bytes": len(joined_raw),
        "sha256": hashlib.sha256(joined_raw).hexdigest(),
    }:
        raise DevelopmentReplayError("joined PUD corpus commitment differs")
    for index, page in enumerate(plan["pages"][DATASET_ID]):
        start = len(dataset_rows) * index // 32
        end = len(dataset_rows) * (index + 1) // 32
        content_raw = "\n\n".join(dataset_rows[start:end]).encode(
            "utf-8", errors="strict"
        )
        if (
            page["sentenceStart"] != start
            or page["sentenceEnd"] != end
            or page["inputTextBytes"] != len(content_raw)
            or page["inputTextSHA256"] != replay.sha256_bytes(content_raw)
        ):
            raise DevelopmentReplayError(
                "development slices do not reconstruct the pinned PUD sentences"
            )
    model_summaries: list[dict[str, Any]] = []
    observed_runtime: dict[str, str] | None = None
    total_pages = 0
    total_predictions = 0
    total_containers = 0

    for model_key in MODELS:
        commitment = plan["jobs"][model_key]
        job_raw = replay.read_beneath(
            evidence_root,
            commitment["path"],
            maximum_bytes=16 * 1024 * 1024,
            expected_bytes=commitment["bytes"],
            expected_sha256=commitment["sha256"],
        )
        job = replay.load_canonical_line(job_raw, label=f"development job {model_key}")
        if job != expected_job(plan, model_key):
            raise DevelopmentReplayError(
                f"development job differs from sealed plan: {model_key}"
            )
        model_bytes: dict[str, bytes] = {}
        model_file_commitments: list[dict[str, Any]] = []
        for filename in MODEL_FILES:
            specification = job["model"]["files"][filename]
            raw = replay.read_beneath(
                private_root,
                specification["path"],
                maximum_bytes=(
                    2 * 1024 * 1024 * 1024
                    if filename == "model.safetensors"
                    else 32 * 1024 * 1024
                ),
                expected_bytes=specification["bytes"],
                expected_sha256=specification["sha256"],
            )
            model_bytes[filename] = raw
            model_file_commitments.append(
                {"filename": filename, "bytes": len(raw), "sha256": replay.sha256_bytes(raw)}
            )
        raw_relative = f"workers/{model_key}/raw-token-evidence.jsonl"
        container_relative = f"workers/{model_key}/container-evidence.jsonl"
        page_relative = f"workers/{model_key}/page-token-evidence.jsonl"
        raw_bytes = replay.read_beneath(evidence_root, raw_relative, maximum_bytes=128 * 1024 * 1024)
        container_bytes = replay.read_beneath(evidence_root, container_relative, maximum_bytes=64 * 1024 * 1024)
        page_bytes = replay.read_beneath(evidence_root, page_relative, maximum_bytes=16 * 1024 * 1024)
        raw_records = replay.load_canonical_jsonl(raw_bytes, label=raw_relative)
        container_records = replay.load_canonical_jsonl(container_bytes, label=container_relative)
        page_records = replay.load_canonical_jsonl(page_bytes, label=page_relative)
        expected_pages = 32
        expected_layers = job["model"]["layers"]
        if (
            len(raw_records) != expected_pages * replay.PREDICTION_TOKENS
            or len(container_records) != expected_pages * expected_layers
            or len(page_records) != expected_pages
        ):
            raise DevelopmentReplayError(
                f"development evidence record counts differ: {model_key}"
            )
        try:
            backend = replay.RealModelReplayBackend(
                model_bytes,
                expected_vocab_size=job["model"]["vocabSize"],
                expected_layers=expected_layers,
            )
        finally:
            model_bytes.clear()
            gc.collect()
        if observed_runtime is None:
            observed_runtime = dict(backend.runtime)
        elif observed_runtime != backend.runtime:
            raise DevelopmentReplayError(
                "dependency versions changed between development replay models"
            )
        page_summaries: list[dict[str, Any]] = []
        record_commitments: list[dict[str, Any]] = []
        container_commitments: list[dict[str, Any]] = []
        try:
            for corpus in CORPORA:
                for page in job["pages"][corpus]:
                    page_index = page["pageSelectionIndex"]
                    slice_index = page["sourceSliceIndex"]
                    record_raw = replay.read_beneath(
                        private_root,
                        page["recordPath"],
                        maximum_bytes=64 * 1024 * 1024,
                        expected_bytes=page["recordBytes"],
                        expected_sha256=page["recordSHA256"],
                    )
                    matching_pages = _group_one(
                        page_records, dataset_id=corpus, slice_index=slice_index
                    )
                    matching_raw = _group_one(
                        raw_records, dataset_id=corpus, slice_index=slice_index
                    )
                    matching_containers = _group_one(
                        container_records, dataset_id=corpus, slice_index=slice_index
                    )
                    if len(matching_pages) != 1:
                        raise DevelopmentReplayError(
                            "development page-token evidence is duplicated or missing"
                        )

                    def container_reader(record: dict[str, Any]) -> bytes:
                        return replay.read_beneath(
                            evidence_root,
                            record["relativePath"],
                            maximum_bytes=256 * 1024 * 1024,
                            expected_bytes=record["containerBytes"],
                            expected_sha256=record["containerSHA256"],
                        )

                    page_summary = replay_development_page(
                        backend=backend,
                        run_id=plan["runId"],
                        model_key=model_key,
                        slice_index=slice_index,
                        sentence_start=page["sentenceStart"],
                        sentence_end=page["sentenceEnd"],
                        expected_content="\n\n".join(
                            dataset_rows[
                                page["sentenceStart"] : page["sentenceEnd"]
                            ]
                        ),
                        record_raw=record_raw,
                        page_evidence=matching_pages[0],
                        raw_evidence=matching_raw,
                        container_evidence=matching_containers,
                        candidate=job["candidate"],
                        bits_by_layer=job["model"]["candidateBitsByLayer"],
                        container_reader=container_reader,
                    )
                    page_summaries.append(page_summary)
                    record_commitments.append(
                        {
                            "datasetId": corpus,
                            "sourceSliceIndex": slice_index,
                            "sentenceStart": page["sentenceStart"],
                            "sentenceEnd": page["sentenceEnd"],
                            "bytes": len(record_raw),
                            "sha256": replay.sha256_bytes(record_raw),
                        }
                    )
                    for item in sorted(matching_containers, key=lambda value: value["layerIndex"]):
                        container_commitments.append(
                            {
                                "relativePath": item["relativePath"],
                                "bytes": item["containerBytes"],
                                "sha256": item["containerSHA256"],
                            }
                        )
        finally:
            backend.close()
            del backend
            gc.collect()
        model_summary = {
            "modelKey": model_key,
            "modelFileSetSHA256": replay.sha256_bytes(replay.canonical_json_bytes(model_file_commitments)),
            "weightSHA256": job["model"]["files"]["model.safetensors"]["sha256"],
            "tokenizerSHA256": job["model"]["files"]["tokenizer.json"]["sha256"],
            "corpusRecordSetSHA256": replay.sha256_bytes(replay.canonical_json_bytes(record_commitments)),
            "rawTokenEvidenceSHA256": replay.sha256_bytes(raw_bytes),
            "pageTokenEvidenceSHA256": replay.sha256_bytes(page_bytes),
            "containerEvidenceSHA256": replay.sha256_bytes(container_bytes),
            "containerByteSetSHA256": replay.sha256_bytes(replay.canonical_json_bytes(container_commitments)),
            "pageReplaySHA256": replay.sha256_bytes(replay.canonical_json_bytes(page_summaries)),
            "replayedPages": len(page_summaries),
            "replayedPredictions": len(page_summaries) * replay.PREDICTION_TOKENS,
            "replayedContainers": len(container_commitments),
            "exactTokenIds": True,
            "exactLossFloat32Bits": True,
            "exactTop1TokenIds": True,
            "allContainerInputsBoundToBaselineCache": True,
        }
        model_summaries.append(model_summary)
        total_pages += model_summary["replayedPages"]
        total_predictions += model_summary["replayedPredictions"]
        total_containers += model_summary["replayedContainers"]
    if observed_runtime is None:
        raise DevelopmentReplayError("no development model was replayed")
    summary: dict[str, Any] = {
        "schemaVersion": SUMMARY_SCHEMA,
        "suiteId": SUITE_ID,
        "runId": plan["runId"],
        "status": "NON_SCIENTIFIC_DEVELOPMENT_REPLAY_PASS",
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "controlConfigurationSHA256": plan["controlConfigurationSHA256"],
        "modelOrder": list(MODELS),
        "selectedCorpora": list(CORPORA),
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
        "runtime": observed_runtime,
        "models": model_summaries,
        "totalReplayedPages": total_pages,
        "totalReplayedPredictions": total_predictions,
        "totalReplayedContainers": total_containers,
        "exactTokenIds": True,
        "exactLossFloat32Bits": True,
        "exactTop1TokenIds": True,
        "allContainerInputsBoundToBaselineCache": True,
        "replayComplete": True,
    }
    summary["contentSHA256"] = replay.sha256_bytes(replay.canonical_json_bytes(summary))
    return summary


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    return parser.parse_args(argv)


def main() -> int:
    arguments = parse_arguments()
    try:
        summary = run_development_replay(
            evidence_root=arguments.evidence_root,
            private_root=arguments.private_root,
        )
        output = arguments.evidence_root / "independent-development-replay.json"
        with output.open("xb") as handle:
            handle.write(replay.canonical_json_bytes(summary) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError, KeyError, DevelopmentReplayError, replay.IndependentModelReplayError) as error:
        print(f"DEVELOPMENT REPLAY FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": summary["status"],
        "runId": summary["runId"],
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "contentSHA256": summary["contentSHA256"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
