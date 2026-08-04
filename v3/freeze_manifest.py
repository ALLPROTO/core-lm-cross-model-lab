#!/usr/bin/env python3
"""Create and verify the non-self-referential author-verified v3 freeze manifest.

The author-verified exact implementation commit is stage one.  This canonical manifest is
then generated outside that Git tree.  Stage two publishes a frozen design
whose ``labSource.freezeManifestSHA256`` is the SHA-256 of the exact manifest
file bytes.  The manifest therefore never attempts to contain its own file
hash; its ``contentSHA256`` is a conventional digest of the payload with that
single field omitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.mediawiki_snapshot import PROJECTS, PinnedHTTPSClient  # noqa: E402
from v3.development_artifact_verifier import (  # noqa: E402
    DevelopmentArtifactVerificationError,
    verify_artifact_semantics,
)
from v3.development_corpus import (  # noqa: E402
    ATTRIBUTION_ARCHIVED_PATH,
    DATASET_ID as DEVELOPMENT_DATASET_ID,
    FILE as DEVELOPMENT_DATASET_FILE,
    JOINED_TEXT_BYTES as DEVELOPMENT_JOINED_TEXT_BYTES,
    JOINED_TEXT_SHA256 as DEVELOPMENT_JOINED_TEXT_SHA256,
    LICENSE_ARCHIVED_PATH,
    LICENSE_ID as DEVELOPMENT_CORPUS_LICENSE,
    PARTITIONS as DEVELOPMENT_PAGES_PER_MODEL,
    README_ARCHIVED_PATH,
    REPOSITORY as DEVELOPMENT_CORPUS_REPOSITORY,
    REVISION as DEVELOPMENT_CORPUS_REVISION,
    RIGHTS_SCOPE as DEVELOPMENT_RIGHTS_SCOPE,
    RIGHTS_STATUS as DEVELOPMENT_RIGHTS_STATUS,
    SENTENCE_COUNT as DEVELOPMENT_DATASET_SENTENCES,
    SOURCE_BYTES as DEVELOPMENT_DATASET_BYTES,
    SOURCE_SHA256 as DEVELOPMENT_DATASET_SHA256,
    partition_bounds,
    verify_rights_evidence,
)
from v3.github_gate_receipt import (  # noqa: E402
    EVIDENCE_BOUNDARY as GITHUB_GATE_EVIDENCE_BOUNDARY,
    MAXIMUM_CAPTURE_SPAN_SECONDS as GITHUB_GATE_MAXIMUM_CAPTURE_SPAN_SECONDS,
    MAXIMUM_RECEIPT_BYTES as MAX_GITHUB_GATE_RECEIPT_BYTES,
    GitHubGateReceiptError,
    REQUIRED_WORKFLOW_NAME,
    REQUIRED_WORKFLOW_PATH,
    VerifiedGitHubGateReceipt,
    canonical_ci_artifact_commitments,
    verify_github_gate_receipt,
)
from v3.nist_beacon import (  # noqa: E402
    NIST_TRUST_ROOT_DER_SHA256,
    load_offline_trust_bundle,
)
from v3.protocol import (  # noqa: E402
    load_json_strict_bytes,
    validate_frozen_design_registration,
)
from v3.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    verify_content_digest,
    verify_runtime_manifest_integrity,
    with_content_digest,
    write_new_bytes,
)
from v3.release_receipt import (  # noqa: E402
    ReleaseAttestationCryptographicVerifier,
    ReleaseReceiptError,
    verify_release_receipt,
)
from v3.release_attestation_crypto import (  # noqa: E402
    PinnedCosignReleaseAttestationVerifier,
)


SCHEMA_VERSION = "corelm-crossmodel-livewiki-v3-freeze-manifest-v1"
STATUS = "IMPLEMENTATION_FREEZE_READY_FOR_DESIGN_BINDING"
SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
RUNTIME_SCHEMA = "corelm-crossmodel-livewiki-v3-runtime-manifest-v1"
ASSET_RECEIPT_SCHEMA = "corelm-crossmodel-livewiki-v3-asset-receipt-v1"
TRUST_SCHEMA = "corelm-crossmodel-livewiki-v3-nist-trust-bundle-v1"
PULSE_TIME = datetime(2026, 9, 2, 18, 0, 0, tzinfo=timezone.utc)
DECISION_CHECKPOINT = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
DESIGN_PUBLISH_DEADLINE = datetime(2026, 8, 15, 0, 0, 0, tzinfo=timezone.utc)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
GITHUB_LOGIN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z"
)
MAX_RUNTIME_MANIFEST_BYTES = 512 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_TRUST_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CA_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_FREEZE_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_DESIGN_BYTES = 4 * 1024 * 1024
MAX_DEVELOPMENT_REPORT_BYTES = 16 * 1024 * 1024
MAX_DEVELOPMENT_PLAN_BYTES = 16 * 1024 * 1024
MAX_DEVELOPMENT_SUMMARY_BYTES = 16 * 1024 * 1024
DEVELOPMENT_ARCHIVE_MAX_BYTES = 1_800_000_000
READ_CHUNK_BYTES = 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 10
GIT_EXECUTABLE = Path("/usr/bin/git")
MODEL_KEYS = ("gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py")
EXPECTED_ASSET_FILES = 24
EXPECTED_ASSET_BYTES = 1_916_375_741
EXPECTED_WEIGHT_BYTES = 1_906_255_408
REGISTERED_REQUIREMENTS_LOCKS = [
    {
        "name": "pip-bootstrap.txt",
        "bytes": 173,
        "sha256": "587c4946469d33bb2e83b0d34cbe54d0c4c4799896e5af672331e108743f1fca",
    },
    {
        "name": "requirements.lock",
        "bytes": 55_781,
        "sha256": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
    },
]

DEVELOPMENT_REPORT_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-report-v1"
)
DEVELOPMENT_ARCHIVE_MANIFEST_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-archive-manifest-v1"
)
DEVELOPMENT_ARCHIVE_TAG = (
    "corelm-crossmodel-livewiki-v3-development-control"
)
DEVELOPMENT_ARCHIVE_ASSET_ROLES = (
    "development-control-report",
    "development-control-artifacts",
    "sha256-manifest",
)
DEVELOPMENT_RIGHTS_DECLARATION = {
    "developmentCorpusLicense": DEVELOPMENT_CORPUS_LICENSE,
    "rightsStatus": DEVELOPMENT_RIGHTS_STATUS,
    "rightsScope": DEVELOPMENT_RIGHTS_SCOPE,
    "sourceRepository": DEVELOPMENT_CORPUS_REPOSITORY,
    "sourceRevision": DEVELOPMENT_CORPUS_REVISION,
    "sourceFile": DEVELOPMENT_DATASET_FILE,
    "corpusManifestPath": "inputs/development-corpus.draft.json",
    "licensePath": (
        "inputs/LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
    ),
    "readmePath": (
        "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md"
    ),
    "attributionPath": "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md",
    "sourceDerivedEvidenceLicense": DEVELOPMENT_CORPUS_LICENSE,
    "repositoryCodeLicense": "MIT",
    "noEndorsement": True,
}
DEVELOPMENT_SIGNING_KEY_FINGERPRINT = (
    "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM"
)
DEVELOPMENT_SIGNING_PUBLIC_KEY_SHA256 = (
    "beac537f2979026cd85facd195132979a5a3a77da65f87d563ffb6253d408ea2"
)
DEVELOPMENT_PLAN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-plan-v1"
DEVELOPMENT_REPLAY_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-model-replay-v1"
)
DEVELOPMENT_WORKER_SUMMARY_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-worker-summary-v1"
)
DEVELOPMENT_SUPERVISOR_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-supervisor-receipt-v1"
)
DEVELOPMENT_SUITE_ID = "corelm-voidtoken-crossmodel-v3-author-verified-development-e2e"
DEVELOPMENT_DATASET_PATH = f"inputs/corpus/{DEVELOPMENT_DATASET_FILE}"
DEVELOPMENT_RECORD_ROOT = "records/ud-english-pud"
DEVELOPMENT_PREDICTIONS_PER_PAGE = 128
DEVELOPMENT_MODEL_LAYERS = {
    "gpt-neo-125m": 12,
    "smollm2-360m": 32,
    "tiny-starcoder-py": 20,
}
DEVELOPMENT_MODEL_IDENTITIES = {
    "gpt-neo-125m": {
        "repository": "EleutherAI/gpt-neo-125m",
        "revision": "21def0189f5705e2521767faed922f1f15e7d7db",
        "layers": 12,
        "vocabSize": 50_257,
        "weightBytes": 525_979_192,
        "weightSHA256": (
            "52738cbfb54e25a232598242f60ef19ee193d36090b98fe649b10c02724b3521"
        ),
    },
    "smollm2-360m": {
        "repository": "HuggingFaceTB/SmolLM2-360M",
        "revision": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
        "layers": 32,
        "vocabSize": 49_152,
        "weightBytes": 723_674_912,
        "weightSHA256": (
            "7aaff6661428bed033abba9522bec81938678642cca3181fe752b6ca9e1e540f"
        ),
    },
    "tiny-starcoder-py": {
        "repository": "bigcode/tiny_starcoder_py",
        "revision": "8547527bef0bc927268c1653cce6948c5c242dd1",
        "layers": 20,
        "vocabSize": 49_152,
        "weightBytes": 656_601_304,
        "weightSHA256": (
            "15fa942f055b618d5ca6283f5c27278a475ff12e53dc704b9658ffd5160d4021"
        ),
    },
}
DEVELOPMENT_MODEL_FILES = (
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
)
DEVELOPMENT_CANDIDATE = {
    "backend": "voidtoken-v5",
    "groupSize": 128,
    "transformBlockSize": 128,
    "codeCompression": "zlib-9",
    "scaleCompression": "zlib-9",
    "signMode": "none",
}
DEVELOPMENT_EXECUTION = {
    "device": "cpu",
    "intraOpThreads": 2,
    "interOpThreads": 1,
    "modelDtype": "float32",
    "cacheBaseline": "float32-to-bfloat16-to-float32",
    "attentionImplementation": "eager",
    "prefillTokens": 383,
    "predictionTokensPerPage": 128,
    "maximumWorkerRSSBytes": 4_294_967_296,
    "watchdogPollMilliseconds": 250,
    "deterministicAlgorithms": "fail-closed",
    "modelsSequential": True,
}
DEVELOPMENT_CONTROL_SOURCE_PATHS = (
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
DEVELOPMENT_ARCHIVED_INPUTS = {
    "designRegistration": (
        "inputs/design-registration.draft.json",
        "v3/design-registration.draft.json",
    ),
    "modelAssetManifest": (
        "inputs/model-assets.draft.json",
        "v3/model-assets.draft.json",
    ),
    "fullAssetReceipt": (
        "inputs/model-assets.full-rehash.json",
        "v3/manifests/model-assets.full-rehash.json",
    ),
    "developmentCorpusManifest": (
        "inputs/development-corpus.draft.json",
        "v3/development-corpus.draft.json",
    ),
    "licenseSourceEvidence": (
        "inputs/LICENSES/source-evidence.json",
        "LICENSES/source-evidence.json",
    ),
    "assetLicenseMatrix": (
        "inputs/LICENSES/ASSET_LICENSES.md",
        "LICENSES/ASSET_LICENSES.md",
    ),
    "udEnglishPudReadme": (
        f"inputs/LICENSES/{README_ARCHIVED_PATH}",
        f"LICENSES/{README_ARCHIVED_PATH}",
    ),
    "udEnglishPudLicense": (
        f"inputs/LICENSES/{LICENSE_ARCHIVED_PATH}",
        f"LICENSES/{LICENSE_ARCHIVED_PATH}",
    ),
    "udEnglishPudAttribution": (
        f"inputs/LICENSES/{ATTRIBUTION_ARCHIVED_PATH}",
        f"LICENSES/{ATTRIBUTION_ARCHIVED_PATH}",
    ),
    "runtimeManifest": ("inputs/runtime-manifest.json", None),
}


FREEZE_PROCEDURE = {
    "implementationStage": "AUTHOR_VERIFIED_GREEN_EXACT_COMMIT",
    "manifestStage": "CANONICAL_MANIFEST_GENERATED_OUTSIDE_IMPLEMENTATION_TREE",
    "designBindingStage": "FROZEN_DESIGN_BINDS_EXACT_MANIFEST_FILE_SHA256",
    "designBindingField": "labSource.freezeManifestSHA256",
    "designBindingDigest": "sha256(canonical-json-with-contentSHA256-plus-terminal-LF)",
    "implementationMutationAfterManifest": "FORBIDDEN",
    "manifestContainsOwnFileSHA256": False,
}


class FreezeManifestError(ValueError):
    """A freeze artifact or identity is incomplete, mutable, or inconsistent."""


CAVerifier = Callable[[Path, str], None]
TrustVerifier = Callable[[Path, str], None]
DevelopmentControlVerifier = Callable[..., dict[str, Any]]
DevelopmentArchiveVerifier = Callable[..., dict[str, Any]]


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_no_symlinks(path: Path) -> tuple[int, Path]:
    absolute = _absolute_without_resolving(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise FreezeManifestError(
                    f"path component is not a directory: {absolute}"
                )
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise FreezeManifestError(
            f"directory path contains a symlink or invalid component: {absolute}"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute


def read_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded regular file with no-follow component traversal."""

    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise FreezeManifestError("file read bound must be positive")
    absolute = _absolute_without_resolving(path)
    parent_descriptor, _ = _open_directory_no_symlinks(absolute.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise FreezeManifestError(
                f"regular non-symlink file required: {absolute}"
            ) from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise FreezeManifestError(f"regular file required: {absolute}")
            if before.st_size > maximum_bytes:
                raise FreezeManifestError(f"file exceeds fixed bound: {absolute}")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise FreezeManifestError(f"file exceeds fixed bound: {absolute}")
            after = os.fstat(descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if identity_before != identity_after or observed != before.st_size:
                raise FreezeManifestError(f"file changed while reading: {absolute}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _required_fields(value: Any, expected: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise FreezeManifestError(f"{label} fields differ")
    return value


def _digest(value: Any, *, label: str, length: int = 64) -> str:
    pattern = SHA256 if length == 64 else GIT_OBJECT
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise FreezeManifestError(f"{label} is not lowercase {length}-hex")
    return value


def _utc_second(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise FreezeManifestError(f"{label} is not UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise FreezeManifestError(f"{label} is not a real UTC timestamp") from error


def _digest_record(value: Any, *, label: str) -> Mapping[str, Any]:
    record = _required_fields(value, {"bytes", "sha256"}, label=label)
    if type(record["bytes"]) is not int or record["bytes"] <= 0:
        raise FreezeManifestError(f"{label} byte count is invalid")
    _digest(record["sha256"], label=f"{label} SHA-256")
    return record


def _verify_embedded_content_digest(value: Mapping[str, Any], *, label: str) -> None:
    try:
        verify_content_digest(dict(value))
    except ValueError as error:
        raise FreezeManifestError(f"{label} content digest differs") from error


def _load_canonical_line_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = load_json_strict_bytes(raw, label=label)
    except ValueError as error:
        raise FreezeManifestError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise FreezeManifestError(f"{label} must be a JSON object")
    if canonical_json_bytes(value) + b"\n" != raw:
        raise FreezeManifestError(f"{label} is not canonical JSON plus terminal LF")
    return value


def _expected_development_artifact_paths() -> set[str]:
    paths = {
        "development-plan.json",
        "development-control-start.json",
        "independent-development-replay.json",
        "raw-token-evidence.jsonl",
        "container-evidence.jsonl",
        "page-token-evidence.jsonl",
        DEVELOPMENT_DATASET_PATH,
        *(item[0] for item in DEVELOPMENT_ARCHIVED_INPUTS.values()),
        *(f"jobs/{model}.json" for model in MODEL_KEYS),
        *(f"logs/{model}.log" for model in MODEL_KEYS),
        "logs/independent-development-replay.log",
        *(f"supervision/{model}.json" for model in MODEL_KEYS),
        "supervision/independent-development-replay.json",
    }
    for model in MODEL_KEYS:
        paths.update(
            {
                f"workers/{model}/raw-token-evidence.jsonl",
                f"workers/{model}/container-evidence.jsonl",
                f"workers/{model}/page-token-evidence.jsonl",
                f"workers/{model}/worker-summary.json",
            }
        )
        for page_index in range(DEVELOPMENT_PAGES_PER_MODEL):
            for layer_index in range(DEVELOPMENT_MODEL_LAYERS[model]):
                paths.add(
                    f"containers/{model}/{DEVELOPMENT_DATASET_ID}/"
                    f"slice-{page_index:02d}/layer-{layer_index:02d}.vtl5"
                )
    return paths


def _validate_development_artifact_inventory(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise FreezeManifestError("development artifact inventory must be a list")
    paths: set[str] = set()
    inventory: list[dict[str, Any]] = []
    for item in value:
        record = _required_fields(
            item, {"path", "bytes", "sha256"}, label="development artifact"
        )
        path = record["path"]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path == "development-control-report.json"
            or path in paths
        ):
            raise FreezeManifestError("development artifact path is unsafe or duplicated")
        _digest_record(
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            label=f"development artifact {path}",
        )
        paths.add(path)
        inventory.append(dict(record))
    expected = _expected_development_artifact_paths()
    if paths != expected:
        missing = sorted(expected - paths)
        extra = sorted(paths - expected)
        detail = missing[0] if missing else extra[0]
        raise FreezeManifestError(
            f"development artifact inventory path set differs: {detail}"
        )
    return inventory


def _validate_development_replay(value: Any, *, run_id: str, config_sha256: str) -> None:
    replay = _required_fields(
        value,
        {
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
            "controlConfigurationSHA256",
            "modelOrder",
            "selectedCorpora",
            "execution",
            "runtime",
            "models",
            "totalReplayedPages",
            "totalReplayedPredictions",
            "totalReplayedContainers",
            "exactTokenIds",
            "exactLossFloat32Bits",
            "exactTop1TokenIds",
            "allContainerInputsBoundToBaselineCache",
            "replayComplete",
            "contentSHA256",
        },
        label="development independent replay",
    )
    _verify_embedded_content_digest(replay, label="development independent replay")
    false_fields = (
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
    )
    true_fields = (
        "exactTokenIds",
        "exactLossFloat32Bits",
        "exactTop1TokenIds",
        "allContainerInputsBoundToBaselineCache",
        "replayComplete",
    )
    if (
        replay["schemaVersion"] != DEVELOPMENT_REPLAY_SCHEMA
        or replay["suiteId"] != DEVELOPMENT_SUITE_ID
        or replay["runId"] != run_id
        or replay["status"] != "NON_SCIENTIFIC_DEVELOPMENT_REPLAY_PASS"
        or replay["controlConfigurationSHA256"] != config_sha256
        or any(replay[field] is not False for field in false_fields)
        or any(replay[field] is not True for field in true_fields)
        or replay["modelOrder"] != list(MODEL_KEYS)
        or replay["selectedCorpora"] != [DEVELOPMENT_DATASET_ID]
    ):
        raise FreezeManifestError("development independent replay boundary differs")
    expected_execution = {
        "device": "cpu",
        "modelDtype": "float32",
        "baselineCache": "bfloat16-roundtrip-to-float32",
        "deterministicAlgorithms": True,
        "intraOpThreads": 2,
        "interOpThreads": 1,
        "modelsSequential": True,
        "networkUsed": False,
        "fixtureBackendUsed": False,
    }
    if replay["execution"] != expected_execution:
        raise FreezeManifestError("development replay execution differs")
    if replay["runtime"] != {
        "numpy": "2.5.1",
        "safetensors": "0.8.0",
        "tokenizers": "0.22.2",
        "torch": "2.13.0",
        "transformers": "5.14.1",
    }:
        raise FreezeManifestError("development replay runtime is not the locked macOS runtime")
    models = replay["models"]
    if not isinstance(models, list) or [item.get("modelKey") for item in models] != list(
        MODEL_KEYS
    ):
        raise FreezeManifestError("development replay model order differs")
    model_fields = {
        "modelKey",
        "modelFileSetSHA256",
        "weightSHA256",
        "tokenizerSHA256",
        "corpusRecordSetSHA256",
        "rawTokenEvidenceSHA256",
        "pageTokenEvidenceSHA256",
        "containerEvidenceSHA256",
        "containerByteSetSHA256",
        "pageReplaySHA256",
        "replayedPages",
        "replayedPredictions",
        "replayedContainers",
        "exactTokenIds",
        "exactLossFloat32Bits",
        "exactTop1TokenIds",
        "allContainerInputsBoundToBaselineCache",
    }
    total_containers = 0
    for model in models:
        key = model.get("modelKey")
        if not isinstance(model, dict) or set(model) != model_fields or key not in MODEL_KEYS:
            raise FreezeManifestError("development replay model summary fields differ")
        for field in (
            "modelFileSetSHA256",
            "weightSHA256",
            "tokenizerSHA256",
            "corpusRecordSetSHA256",
            "rawTokenEvidenceSHA256",
            "pageTokenEvidenceSHA256",
            "containerEvidenceSHA256",
            "containerByteSetSHA256",
            "pageReplaySHA256",
        ):
            _digest(model[field], label=f"development replay {key} {field}")
        expected_containers = (
            DEVELOPMENT_PAGES_PER_MODEL * DEVELOPMENT_MODEL_LAYERS[key]
        )
        if (
            model["weightSHA256"]
            != DEVELOPMENT_MODEL_IDENTITIES[key]["weightSHA256"]
            or model["replayedPages"] != DEVELOPMENT_PAGES_PER_MODEL
            or model["replayedPredictions"]
            != DEVELOPMENT_PAGES_PER_MODEL * DEVELOPMENT_PREDICTIONS_PER_PAGE
            or model["replayedContainers"] != expected_containers
            or any(model[field] is not True for field in true_fields[:4])
        ):
            raise FreezeManifestError(f"development replay counts differ: {key}")
        total_containers += expected_containers
    if (
        replay["totalReplayedPages"] != len(MODEL_KEYS) * DEVELOPMENT_PAGES_PER_MODEL
        or replay["totalReplayedPredictions"]
        != len(MODEL_KEYS)
        * DEVELOPMENT_PAGES_PER_MODEL
        * DEVELOPMENT_PREDICTIONS_PER_PAGE
        or replay["totalReplayedContainers"] != total_containers
        or total_containers != 2_048
    ):
        raise FreezeManifestError("development replay aggregate counts differ")


def _validate_development_supervision(
    value: Any, *, report_started: datetime, report_completed: datetime
) -> None:
    if not isinstance(value, list) or len(value) != 4:
        raise FreezeManifestError("development supervision count differs")
    expected_subjects = [
        *(f"producer:{model}" for model in MODEL_KEYS),
        "independent-real-model-replay",
    ]
    fields = {
        "schemaVersion",
        "subject",
        "startedAt",
        "completedAt",
        "durationNanoseconds",
        "exitCode",
        "peakAggregateRSSBytes",
        "maximumAggregateRSSBytes",
        "watchdogPollMilliseconds",
        "descendantsRemainingAtExit",
        "terminationApplied",
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
    }
    for receipt, subject in zip(value, expected_subjects, strict=True):
        if not isinstance(receipt, dict) or set(receipt) != fields:
            raise FreezeManifestError("development supervision fields differ")
        started = _utc_second(receipt["startedAt"], label="development child startedAt")
        completed = _utc_second(
            receipt["completedAt"], label="development child completedAt"
        )
        if (
            receipt["schemaVersion"] != DEVELOPMENT_SUPERVISOR_SCHEMA
            or receipt["subject"] != subject
            or receipt["exitCode"] != 0
            or type(receipt["durationNanoseconds"]) is not int
            or receipt["durationNanoseconds"] <= 0
            or type(receipt["peakAggregateRSSBytes"]) is not int
            or not 0 <= receipt["peakAggregateRSSBytes"] <= 4_294_967_296
            or receipt["maximumAggregateRSSBytes"] != 4_294_967_296
            or receipt["watchdogPollMilliseconds"] != 250
            or receipt["descendantsRemainingAtExit"] is not False
            or receipt["terminationApplied"] is not False
            or receipt["countsTowardScientificVerdict"] is not False
            or receipt["usedForCandidateSelectionOrTuning"] is not False
            or not report_started <= started <= completed <= report_completed
        ):
            raise FreezeManifestError(f"development supervision differs: {subject}")


def validate_development_control_report(
    value: Any, *, completed_no_later_than: datetime = DESIGN_PUBLISH_DEADLINE
) -> dict[str, Any]:
    """Validate the canonical non-scientific report without trusting its files."""

    report = _required_fields(
        value,
        {
            "schemaVersion",
            "suiteId",
            "runId",
            "executionId",
            "status",
            "countsTowardScientificVerdict",
            "usedForCandidateSelectionOrTuning",
            "scientificAttemptStateCreated",
            "nistUsed",
            "futureCorpusUsed",
            "thresholdsApplied",
            "candidateCodecInvoked",
            "realModelsUsed",
            "realDevelopmentCorpusUsed",
            "independentRealModelReplayComplete",
            "startedAt",
            "completedAt",
            "controlConfigurationSHA256",
            "plan",
            "inputs",
            "runtime",
            "hostSafetyChecks",
            "networkIsolationBackend",
            "workerProcessesSequential",
            "replayModelsSequential",
            "supervision",
            "independentReplay",
            "artifactInventory",
            "artifactSetSHA256",
            "scientificClaim",
            "candidateSelectionOrTuning",
            "contentSHA256",
        },
        label="development-control report",
    )
    _verify_embedded_content_digest(report, label="development-control report")
    config_sha256 = _digest(
        report["controlConfigurationSHA256"],
        label="development control configuration",
    )
    run_id = report["runId"]
    execution_id = report["executionId"]
    false_fields = (
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
    )
    true_fields = (
        "candidateCodecInvoked",
        "realModelsUsed",
        "realDevelopmentCorpusUsed",
        "independentRealModelReplayComplete",
        "workerProcessesSequential",
        "replayModelsSequential",
    )
    if (
        report["schemaVersion"] != DEVELOPMENT_REPORT_SCHEMA
        or report["suiteId"] != DEVELOPMENT_SUITE_ID
        or run_id != f"development-e2e-{config_sha256}"
        or not isinstance(execution_id, str)
        or re.fullmatch(
            r"development-execution-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}",
            execution_id,
        )
        is None
        or report["status"] != "NON_SCIENTIFIC_REAL_DATA_E2E_CONTROL_PASS"
        or any(report[field] is not False for field in false_fields)
        or any(report[field] is not True for field in true_fields)
        or report["networkIsolationBackend"]
        != "macOS-sandbox-exec-deny-network"
        or report["scientificClaim"] != "forbidden"
        or report["candidateSelectionOrTuning"] != "forbidden"
    ):
        raise FreezeManifestError("development-control report boundary differs")
    started = _utc_second(report["startedAt"], label="development report startedAt")
    completed = _utc_second(
        report["completedAt"], label="development report completedAt"
    )
    if started > completed or completed >= completed_no_later_than:
        raise FreezeManifestError("development control missed its registered cutoff")
    _digest_record(report["plan"], label="development plan")
    runtime = report["runtime"]
    if runtime != {
        "dontWriteBytecode": True,
        "hashAlgorithm": "siphash13",
        "hashBits": 64,
        "hashRandomization": 0,
        "hashValue": 7326695182870824334,
        "ignoreEnvironment": 0,
        "noUserSite": 1,
        "pythonVersion": "3.12.10",
        "safePath": True,
        "seedBits": 128,
    }:
        raise FreezeManifestError("development supervisor runtime differs")
    safety_checks = report["hostSafetyChecks"]
    expected_phases = [
        "before-output-materialization",
        *(f"before-producer:{model}" for model in MODEL_KEYS),
        "before-independent-replay",
    ]
    if (
        not isinstance(safety_checks, list)
        or [item.get("phase") for item in safety_checks] != expected_phases
    ):
        raise FreezeManifestError("development host-safety phase order differs")
    safety_fields = {
        "phase",
        "system",
        "machine",
        "osProductVersion",
        "osBuildVersion",
        "kernelRelease",
        "kernelVersion",
        "cpuBrand",
        "logicalCPUCount",
        "physicalMemoryBytes",
        "pythonVersion",
        "pythonExecutableSHA256",
        "effectiveExecutionEnvironment",
        "acPower",
        "freeMemoryPercent",
        "freeDiskBytes",
    }
    invariant_safety: dict[str, Any] | None = None
    for check in safety_checks:
        if not isinstance(check, dict) or set(check) != safety_fields:
            raise FreezeManifestError("development host-safety fields differ")
        invariant = {
            key: value
            for key, value in check.items()
            if key not in {"phase", "freeMemoryPercent", "freeDiskBytes"}
        }
        if invariant_safety is None:
            invariant_safety = invariant
        elif invariant != invariant_safety:
            raise FreezeManifestError("development host identity changed during run")
        if (
            check["system"] != "Darwin"
            or check["machine"] != "arm64"
            or check["pythonVersion"] != "3.12.10"
            or check["acPower"] is not True
            or type(check["freeMemoryPercent"]) is not int
            or check["freeMemoryPercent"] < 50
            or type(check["freeDiskBytes"]) is not int
            or check["freeDiskBytes"] < 12_884_901_888
            or type(check["logicalCPUCount"]) is not int
            or check["logicalCPUCount"] < 1
            or type(check["physicalMemoryBytes"]) is not int
            or check["physicalMemoryBytes"] < 1
            or SHA256.fullmatch(str(check["pythonExecutableSHA256"])) is None
            or not isinstance(check["effectiveExecutionEnvironment"], dict)
            or check["effectiveExecutionEnvironment"].get("PYTHONHASHSEED") != "0"
        ):
            raise FreezeManifestError("development host-safety gate differs")
    _validate_development_supervision(
        report["supervision"],
        report_started=started,
        report_completed=completed,
    )
    _validate_development_replay(
        report["independentReplay"], run_id=run_id, config_sha256=config_sha256
    )
    inventory = _validate_development_artifact_inventory(report["artifactInventory"])
    artifact_set_sha256 = _digest(
        report["artifactSetSHA256"], label="development artifact set"
    )
    if artifact_set_sha256 != sha256_bytes(canonical_json_bytes(inventory)):
        raise FreezeManifestError("development artifact-set digest differs")
    return {
        "runId": run_id,
        "executionId": execution_id,
        "controlConfigurationSHA256": config_sha256,
        "artifactSetSHA256": artifact_set_sha256,
        "artifactCount": len(inventory),
        "startedAt": report["startedAt"],
        "completedAt": report["completedAt"],
    }


def _stable_regular_commitment(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    absolute = _absolute_without_resolving(path)
    parent_descriptor, _ = _open_directory_no_symlinks(absolute.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise FreezeManifestError(
                f"development artifact is not a regular file: {absolute}"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > maximum_bytes
            ):
                raise FreezeManifestError(
                    f"development artifact metadata differs: {absolute}"
                )
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise FreezeManifestError(
                        f"development artifact exceeds its byte bound: {absolute}"
                    )
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or observed != before.st_size
            ):
                raise FreezeManifestError(
                    f"development artifact changed while hashing: {absolute}"
                )
            return {"bytes": observed, "sha256": digest.hexdigest()}
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _rehash_development_artifact_root(
    artifact_root: Path, *, report_path: Path
) -> list[dict[str, Any]]:
    root = _absolute_without_resolving(artifact_root)
    report = _absolute_without_resolving(report_path)
    if report.parent != root or report.name != "development-control-report.json":
        raise FreezeManifestError(
            "development report must be the completion marker at artifact-root top level"
        )
    descriptor, _ = _open_directory_no_symlinks(root)
    os.close(descriptor)
    result: list[dict[str, Any]] = []
    for directory, child_directories, filenames in os.walk(root, followlinks=False):
        child_directories.sort()
        filenames.sort()
        current = Path(directory)
        for child in child_directories:
            metadata = os.lstat(current / child)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise FreezeManifestError("development artifact root contains unsafe directory")
        for filename in filenames:
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if relative == report.name:
                continue
            commitment = _stable_regular_commitment(
                path, maximum_bytes=512 * 1024 * 1024
            )
            result.append({"path": relative, **commitment})
            if len(result) > 10_000:
                raise FreezeManifestError("development artifact count exceeds fixed bound")
    return result


def _read_bound_development_artifact(
    root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
    relative: str,
    *,
    maximum_bytes: int,
) -> bytes:
    commitment = inventory.get(relative)
    if commitment is None:
        raise FreezeManifestError(f"development artifact is absent: {relative}")
    raw = read_regular_bytes(root / relative, maximum_bytes=maximum_bytes)
    if {"bytes": len(raw), "sha256": sha256_bytes(raw)} != {
        "bytes": commitment["bytes"],
        "sha256": commitment["sha256"],
    }:
        raise FreezeManifestError(f"development artifact changed: {relative}")
    return raw


def _validate_development_rights_evidence(
    raw_by_binding: Mapping[str, bytes],
) -> None:
    """Verify the exact PUD manifest, source, declarations, and handling matrix."""

    try:
        corpus_manifest_raw = raw_by_binding["developmentCorpusManifest"]
        tracked_manifest_raw = read_regular_bytes(
            V3_ROOT / "development-corpus.draft.json",
            maximum_bytes=MAX_DESIGN_BYTES,
        )
    except (KeyError, OSError) as error:
        raise FreezeManifestError(
            "archived development corpus manifest is absent"
        ) from error
    if corpus_manifest_raw != tracked_manifest_raw:
        raise FreezeManifestError(
            "archived development corpus manifest differs from frozen source"
        )
    dataset_raw = raw_by_binding.get("developmentDataset")
    if dataset_raw is not None and (
        len(dataset_raw) != DEVELOPMENT_DATASET_BYTES
        or sha256_bytes(dataset_raw) != DEVELOPMENT_DATASET_SHA256
    ):
        raise FreezeManifestError("archived development corpus bytes differ")

    try:
        license_source_evidence = load_json_strict_bytes(
            raw_by_binding["licenseSourceEvidence"],
            label="archived UD English PUD license source evidence",
        )
        rights_status = verify_rights_evidence(
            license_source_evidence,
            raw_by_binding["udEnglishPudReadme"],
            raw_by_binding["udEnglishPudLicense"],
            raw_by_binding["udEnglishPudAttribution"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise FreezeManifestError(
            "archived UD English PUD rights evidence differs"
        ) from error
    if rights_status != DEVELOPMENT_RIGHTS_STATUS:
        raise FreezeManifestError("archived UD English PUD rights status differs")
    try:
        asset_license_matrix = raw_by_binding["assetLicenseMatrix"].decode(
            "utf-8", errors="strict"
        )
    except (KeyError, UnicodeDecodeError) as error:
        raise FreezeManifestError(
            "archived asset license matrix is not strict UTF-8"
        ) from error
    if (
        "UD English PUD" not in asset_license_matrix
        or "CC BY-SA 3.0" not in asset_license_matrix
        or "without added restrictions" not in asset_license_matrix
    ):
        raise FreezeManifestError(
            "archived asset license matrix omits PUD obligations"
        )


def _validate_development_plan(
    plan: Any,
    *,
    report: Mapping[str, Any],
    artifact_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
    expected_codec: Mapping[str, Any],
    expected_implementation: Mapping[str, Any],
    expected_runtime_manifest_sha256: str | None,
) -> None:
    plan = _required_fields(
        plan,
        {
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
        },
        label="development plan",
    )
    _verify_embedded_content_digest(plan, label="development plan")
    false_fields = (
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "thresholdsApplied",
    )
    if (
        plan["schemaVersion"] != DEVELOPMENT_PLAN_SCHEMA
        or plan["suiteId"] != DEVELOPMENT_SUITE_ID
        or plan["runId"] != report["runId"]
        or plan["status"] != "SEALED_NON_SCIENTIFIC_DEVELOPMENT_INPUT"
        or any(plan[field] is not False for field in false_fields)
        or plan["controlConfigurationSHA256"]
        != report["controlConfigurationSHA256"]
        or plan["modelExecutionOrder"] != list(MODEL_KEYS)
        or plan["selectedCorpora"] != [DEVELOPMENT_DATASET_ID]
        or plan["candidate"] != DEVELOPMENT_CANDIDATE
        or plan["execution"] != DEVELOPMENT_EXECUTION
        or plan["inputBindings"] != report["inputs"]
    ):
        raise FreezeManifestError("development plan boundary differs")

    inputs = _required_fields(
        plan["inputBindings"],
        {
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
        },
        label="development input bindings",
    )
    for field in (
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
        _digest_record(inputs[field], label=f"development input {field}")
    if inputs["developmentDataset"] != {
        "bytes": DEVELOPMENT_DATASET_BYTES,
        "sha256": DEVELOPMENT_DATASET_SHA256,
    }:
        raise FreezeManifestError("development corpus bytes differ from the pin")
    if inputs["joinedCorpusText"] != {
        "bytes": DEVELOPMENT_JOINED_TEXT_BYTES,
        "sha256": DEVELOPMENT_JOINED_TEXT_SHA256,
    }:
        raise FreezeManifestError("development joined corpus text differs")
    if inputs["conlluDecode"] != {
        "parser": "strict-stdlib-conllu-text-v1",
        "sentences": DEVELOPMENT_DATASET_SENTENCES,
        "sourceConlluSHA256": DEVELOPMENT_DATASET_SHA256,
    }:
        raise FreezeManifestError("development CoNLL-U decoder binding differs")
    lab = _required_fields(
        inputs["labSource"],
        {"repository", "commit", "tree", "worktreeClean"},
        label="development lab source",
    )
    if (
        lab["repository"] != expected_implementation["repository"]
        or lab["commit"] != expected_implementation["commit"]
        or lab["tree"] != expected_implementation["tree"]
        or lab["worktreeClean"] is not True
    ):
        raise FreezeManifestError("development lab source differs from freeze")
    if inputs["adapter"] != {
        "source": "pinned-ud-english-pud-r2.18-test-conllu",
        "sentenceText": "exact-single-#-text-comment-per-block",
        "join": "two-LF-between-sentence-texts-within-each-slice",
        "partition": "all-source-sentences-equal-floor-boundaries-32",
        "partitions": DEVELOPMENT_PAGES_PER_MODEL,
        "records": DEVELOPMENT_PAGES_PER_MODEL,
        "contentSynthetic": False,
        "metadataEnvelopeScientificUse": "forbidden",
    }:
        raise FreezeManifestError("development real-data adapter differs")
    codec = _required_fields(
        inputs["codecSource"],
        {"repository", "commit", "tree", "requiredFiles"},
        label="development codec source",
    )
    if (
        codec["repository"] != expected_codec["repository"]
        or codec["commit"] != expected_codec["commit"]
        or codec["tree"] != expected_codec["tree"]
    ):
        raise FreezeManifestError("development codec identity differs from freeze")
    tracked_design_raw = read_regular_bytes(
        V3_ROOT / "design-registration.draft.json",
        maximum_bytes=MAX_DESIGN_BYTES,
    )
    try:
        tracked_design = load_json_strict_bytes(
            tracked_design_raw, label="tracked design draft"
        )
    except ValueError as error:
        raise FreezeManifestError("tracked design draft is not strict JSON") from error
    if not isinstance(tracked_design, dict):
        raise FreezeManifestError("tracked design draft must be an object")
    if codec["requiredFiles"] != tracked_design.get("codecSource", {}).get(
        "requiredFiles"
    ):
        raise FreezeManifestError("development codec file commitments differ")

    sources = inputs["controlSources"]
    if (
        not isinstance(sources, list)
        or [item.get("path") for item in sources]
        != list(DEVELOPMENT_CONTROL_SOURCE_PATHS)
    ):
        raise FreezeManifestError("development control source order differs")
    for item, relative in zip(sources, DEVELOPMENT_CONTROL_SOURCE_PATHS, strict=True):
        source = _required_fields(
            item, {"path", "bytes", "sha256"}, label="development control source"
        )
        raw = read_regular_bytes(PROJECT_ROOT / relative, maximum_bytes=4 * 1024 * 1024)
        if source != {"path": relative, "bytes": len(raw), "sha256": sha256_bytes(raw)}:
            raise FreezeManifestError(
                f"development control was not run on the frozen source: {relative}"
            )

    archived_input_raw: dict[str, bytes] = {}
    for binding, (archived_path, tracked_path) in DEVELOPMENT_ARCHIVED_INPUTS.items():
        maximum = (
            MAX_RUNTIME_MANIFEST_BYTES
            if binding == "runtimeManifest"
            else MAX_DESIGN_BYTES
        )
        raw = _read_bound_development_artifact(
            artifact_root, inventory, archived_path, maximum_bytes=maximum
        )
        archived_input_raw[binding] = raw
        expected = {"bytes": len(raw), "sha256": sha256_bytes(raw)}
        if tracked_path is not None:
            tracked = read_regular_bytes(
                PROJECT_ROOT / tracked_path, maximum_bytes=MAX_DESIGN_BYTES
            )
            if raw != tracked:
                raise FreezeManifestError(
                    f"archived development input differs from frozen source: {binding}"
                )
        if inputs[binding] != expected:
            raise FreezeManifestError(
                f"archived development input differs from frozen source: {binding}"
            )
        if binding == "runtimeManifest":
            archived_runtime = _load_canonical_line_bytes(
                raw, label="archived development runtime manifest"
            )
            _verify_embedded_content_digest(
                archived_runtime, label="archived development runtime manifest"
            )
            _verify_runtime_receipt(
                archived_runtime,
                implementation=expected_implementation,
                codec=expected_codec,
            )
    _validate_development_rights_evidence(archived_input_raw)
    if (
        expected_runtime_manifest_sha256 is not None
        and inputs["runtimeManifest"]["sha256"]
        != expected_runtime_manifest_sha256
    ):
        raise FreezeManifestError("development runtime differs from freeze runtime")
    dataset_raw = _read_bound_development_artifact(
        artifact_root,
        inventory,
        DEVELOPMENT_DATASET_PATH,
        maximum_bytes=16 * 1024 * 1024,
    )
    if {"bytes": len(dataset_raw), "sha256": sha256_bytes(dataset_raw)} != inputs[
        "developmentDataset"
    ]:
        raise FreezeManifestError("archived development corpus bytes differ")

    models = plan["models"]
    if not isinstance(models, list) or [item.get("key") for item in models] != list(
        MODEL_KEYS
    ):
        raise FreezeManifestError("development plan model order differs")
    for model in models:
        key = model["key"]
        identity = DEVELOPMENT_MODEL_IDENTITIES[key]
        if not isinstance(model, dict) or set(model) != {
            "key",
            "repository",
            "revision",
            "layers",
            "vocabSize",
            "candidateBitsByLayer",
            "files",
        }:
            raise FreezeManifestError(f"development model fields differ: {key}")
        if any(
            model[field] != identity[field]
            for field in ("repository", "revision", "layers", "vocabSize")
        ):
            raise FreezeManifestError(f"development model identity differs: {key}")
        expected_bits = [
            9 if index in {0, identity["layers"] // 3} else 8
            for index in range(identity["layers"])
        ]
        if (
            model["candidateBitsByLayer"] != expected_bits
            or not isinstance(model["files"], dict)
            or tuple(sorted(model["files"])) != tuple(sorted(DEVELOPMENT_MODEL_FILES))
        ):
            raise FreezeManifestError(f"development model configuration differs: {key}")
        for filename in DEVELOPMENT_MODEL_FILES:
            file_record = _required_fields(
                model["files"][filename],
                {"path", "bytes", "sha256"},
                label=f"development model file {key}/{filename}",
            )
            _digest_record(
                {"bytes": file_record["bytes"], "sha256": file_record["sha256"]},
                label=f"development model file {key}/{filename}",
            )
            if file_record["path"] != f"models/{key}/{filename}":
                raise FreezeManifestError("development model private path differs")
        weight = model["files"]["model.safetensors"]
        if (
            weight["bytes"] != identity["weightBytes"]
            or weight["sha256"] != identity["weightSHA256"]
        ):
            raise FreezeManifestError(f"development model weight differs: {key}")

    pages = plan["pages"]
    if not isinstance(pages, dict) or set(pages) != {DEVELOPMENT_DATASET_ID}:
        raise FreezeManifestError("development plan corpus differs")
    page_values = pages[DEVELOPMENT_DATASET_ID]
    if (
        not isinstance(page_values, list)
        or len(page_values) != DEVELOPMENT_PAGES_PER_MODEL
    ):
        raise FreezeManifestError("development plan page count differs")
    previous_end = 0
    for index, (page, (start, end)) in enumerate(
        zip(page_values, partition_bounds(), strict=True)
    ):
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
            raise FreezeManifestError("development plan page fields differ")
        if (
            page["pageSelectionIndex"] != index
            or page["sourceSliceIndex"] != index
            or page["sentenceStart"] != start
            or page["sentenceEnd"] != end
            or page["sentenceStart"] != previous_end
            or page["recordPath"]
            != f"{DEVELOPMENT_RECORD_ROOT}/slice-{index:02d}.bin"
        ):
            raise FreezeManifestError("development deterministic page partition differs")
        previous_end = end
        for prefix in ("record", "inputText"):
            _digest_record(
                {
                    "bytes": page[f"{prefix}Bytes"],
                    "sha256": page[f"{prefix}SHA256"],
                },
                label=f"development page {prefix}",
            )
    if previous_end != DEVELOPMENT_DATASET_SENTENCES:
        raise FreezeManifestError("development sentence coverage differs")

    private_files = plan["privateFiles"]
    if not isinstance(private_files, list) or len(private_files) != 57:
        raise FreezeManifestError("development private-file inventory differs")
    private_paths: set[str] = set()
    for item in private_files:
        record = _required_fields(
            item, {"path", "bytes", "sha256", "role"}, label="private input"
        )
        if (
            record["path"] in private_paths
            or record["role"]
            not in {
                "model-asset",
                "development-corpus-record",
                "development-corpus-source",
            }
        ):
            raise FreezeManifestError("development private-file record differs")
        _digest_record(
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            label="development private input",
        )
        private_paths.add(record["path"])
    expected_private = {
        *(f"models/{model}/{name}" for model in MODEL_KEYS for name in DEVELOPMENT_MODEL_FILES),
        *(
            f"{DEVELOPMENT_RECORD_ROOT}/slice-{index:02d}.bin"
            for index in range(DEVELOPMENT_PAGES_PER_MODEL)
        ),
        DEVELOPMENT_DATASET_PATH,
    }
    if private_paths != expected_private:
        raise FreezeManifestError("development private-file path set differs")
    source_entry = next(
        item
        for item in private_files
        if item["path"] == DEVELOPMENT_DATASET_PATH
    )
    if source_entry != {
        "path": DEVELOPMENT_DATASET_PATH,
        "bytes": DEVELOPMENT_DATASET_BYTES,
        "sha256": DEVELOPMENT_DATASET_SHA256,
        "role": "development-corpus-source",
    }:
        raise FreezeManifestError("development private dataset source differs")

    jobs = plan["jobs"]
    if not isinstance(jobs, dict) or tuple(jobs) != MODEL_KEYS:
        raise FreezeManifestError("development job commitments differ")
    for key in MODEL_KEYS:
        commitment = _required_fields(
            jobs[key], {"path", "bytes", "sha256"}, label="development job"
        )
        if commitment["path"] != f"jobs/{key}.json":
            raise FreezeManifestError("development job path differs")
        raw = _read_bound_development_artifact(
            artifact_root,
            inventory,
            commitment["path"],
            maximum_bytes=MAX_DEVELOPMENT_PLAN_BYTES,
        )
        if {
            "path": commitment["path"],
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        } != dict(commitment):
            raise FreezeManifestError(f"development job commitment differs: {key}")

    configuration = {
        "schemaVersion": "corelm-crossmodel-v3-real-e2e-development-configuration-v1",
        "suiteId": DEVELOPMENT_SUITE_ID,
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "thresholdsApplied": False,
        "modelExecutionOrder": list(MODEL_KEYS),
        "selectedCorpora": [DEVELOPMENT_DATASET_ID],
        "candidate": DEVELOPMENT_CANDIDATE,
        "models": models,
        "pages": pages,
        "execution": DEVELOPMENT_EXECUTION,
        "inputBindings": inputs,
    }
    if sha256_bytes(canonical_json_bytes(configuration)) != plan[
        "controlConfigurationSHA256"
    ]:
        raise FreezeManifestError("development configuration digest differs")


def _validate_development_worker_summaries(
    *,
    artifact_root: Path,
    inventory: Mapping[str, Mapping[str, Any]],
    report: Mapping[str, Any],
) -> None:
    for key in MODEL_KEYS:
        relative = f"workers/{key}/worker-summary.json"
        raw = _read_bound_development_artifact(
            artifact_root,
            inventory,
            relative,
            maximum_bytes=MAX_DEVELOPMENT_SUMMARY_BYTES,
        )
        summary = _load_canonical_line_bytes(raw, label=f"development worker {key}")
        required = {
            "schemaVersion",
            "suiteId",
            "runId",
            "modelKey",
            "geometry",
            "pages",
            "rawTokenEvidence",
            "containerEvidence",
            "pageTokenEvidence",
            "durationNanoseconds",
            "networkUsed",
            "modelLoad",
            "countsTowardScientificVerdict",
            "usedForCandidateSelectionOrTuning",
            "scientificAttemptStateCreated",
            "nistUsed",
            "futureCorpusUsed",
            "controlConfigurationSHA256",
        }
        if set(summary) != required:
            raise FreezeManifestError(f"development worker fields differ: {key}")
        if (
            summary["schemaVersion"] != DEVELOPMENT_WORKER_SUMMARY_SCHEMA
            or summary["suiteId"] != DEVELOPMENT_SUITE_ID
            or summary["runId"] != report["runId"]
            or summary["modelKey"] != key
            or not isinstance(summary["geometry"], dict)
            or summary["geometry"].get("layers") != DEVELOPMENT_MODEL_LAYERS[key]
            or not isinstance(summary["pages"], list)
            or len(summary["pages"]) != 32
            or type(summary["durationNanoseconds"]) is not int
            or summary["durationNanoseconds"] <= 0
            or summary["networkUsed"] is not False
            or summary["modelLoad"]
            != "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained"
            or summary["countsTowardScientificVerdict"] is not False
            or summary["usedForCandidateSelectionOrTuning"] is not False
            or summary["scientificAttemptStateCreated"] is not False
            or summary["nistUsed"] is not False
            or summary["futureCorpusUsed"] is not False
            or summary["controlConfigurationSHA256"]
            != report["controlConfigurationSHA256"]
        ):
            raise FreezeManifestError(f"development worker boundary differs: {key}")
        for field, filename in (
            ("rawTokenEvidence", "raw-token-evidence.jsonl"),
            ("containerEvidence", "container-evidence.jsonl"),
            ("pageTokenEvidence", "page-token-evidence.jsonl"),
        ):
            commitment = _required_fields(
                summary[field], {"path", "bytes", "sha256"}, label=field
            )
            artifact = inventory[f"workers/{key}/{filename}"]
            if commitment != {"path": filename, **{k: artifact[k] for k in ("bytes", "sha256")}}:
                raise FreezeManifestError(f"development worker evidence differs: {key}")


def verify_development_control_report(
    report_path: Path,
    *,
    artifact_root: Path | None = None,
    expected_implementation: Mapping[str, Any] | None = None,
    expected_codec: Mapping[str, Any] | None = None,
    completed_no_later_than: datetime = DESIGN_PUBLISH_DEADLINE,
    expected_runtime_manifest_sha256: str | None = None,
    require_artifacts: bool = True,
) -> dict[str, Any]:
    """Independently verify the completed real-data control and all archived bytes."""

    report_raw = read_regular_bytes(
        report_path, maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES
    )
    report = _load_canonical_line_bytes(
        report_raw, label="development-control report"
    )
    summary = validate_development_control_report(
        report, completed_no_later_than=completed_no_later_than
    )
    summary["reportFileSHA256"] = sha256_bytes(report_raw)
    summary["reportFileBytes"] = len(report_raw)
    if not require_artifacts:
        return summary
    if artifact_root is None or expected_implementation is None or expected_codec is None:
        raise FreezeManifestError(
            "development artifact root and source identities are required for freeze"
        )
    _validate_source(expected_implementation, label="development implementation")
    _validate_source(expected_codec, label="development codec")
    observed_inventory = _rehash_development_artifact_root(
        artifact_root, report_path=report_path
    )
    if observed_inventory != report["artifactInventory"]:
        raise FreezeManifestError("development artifact inventory differs from disk")
    if sha256_bytes(canonical_json_bytes(observed_inventory)) != report[
        "artifactSetSHA256"
    ]:
        raise FreezeManifestError("development artifact set changed after completion")
    inventory = {item["path"]: item for item in observed_inventory}
    root = _absolute_without_resolving(artifact_root)
    plan_raw = _read_bound_development_artifact(
        root,
        inventory,
        "development-plan.json",
        maximum_bytes=MAX_DEVELOPMENT_PLAN_BYTES,
    )
    if {"bytes": len(plan_raw), "sha256": sha256_bytes(plan_raw)} != report["plan"]:
        raise FreezeManifestError("development report plan commitment differs")
    plan = _load_canonical_line_bytes(plan_raw, label="development plan")
    start_raw = _read_bound_development_artifact(
        root,
        inventory,
        "development-control-start.json",
        maximum_bytes=1024 * 1024,
    )
    start_marker = _load_canonical_line_bytes(
        start_raw, label="development-control start marker"
    )
    start_marker = _required_fields(
        start_marker,
        {
            "schemaVersion",
            "suiteId",
            "executionId",
            "status",
            "startedAt",
            "countsTowardScientificVerdict",
            "usedForCandidateSelectionOrTuning",
            "scientificAttemptStateCreated",
            "nistUsed",
            "futureCorpusUsed",
            "contentSHA256",
        },
        label="development-control start marker",
    )
    _verify_embedded_content_digest(
        start_marker, label="development-control start marker"
    )
    if (
        start_marker["schemaVersion"]
        != "corelm-crossmodel-v3-real-e2e-development-start-v1"
        or start_marker["suiteId"] != DEVELOPMENT_SUITE_ID
        or start_marker["executionId"] != report["executionId"]
        or start_marker["status"]
        != "NON_SCIENTIFIC_DEVELOPMENT_CONTROL_STARTED"
        or start_marker["startedAt"] != report["startedAt"]
        or any(
            start_marker[field] is not False
            for field in (
                "countsTowardScientificVerdict",
                "usedForCandidateSelectionOrTuning",
                "scientificAttemptStateCreated",
                "nistUsed",
                "futureCorpusUsed",
            )
        )
    ):
        raise FreezeManifestError("development-control start marker differs")
    _validate_development_plan(
        plan,
        report=report,
        artifact_root=root,
        inventory=inventory,
        expected_codec=expected_codec,
        expected_implementation=expected_implementation,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
    )
    replay_raw = _read_bound_development_artifact(
        root,
        inventory,
        "independent-development-replay.json",
        maximum_bytes=MAX_DEVELOPMENT_SUMMARY_BYTES,
    )
    replay = _load_canonical_line_bytes(
        replay_raw, label="archived independent development replay"
    )
    if replay != report["independentReplay"]:
        raise FreezeManifestError("archived independent replay differs from report")
    for index, subject in enumerate(
        [*(f"producer:{model}" for model in MODEL_KEYS), "independent-real-model-replay"]
    ):
        filename = (
            f"{MODEL_KEYS[index]}.json"
            if index < len(MODEL_KEYS)
            else "independent-development-replay.json"
        )
        raw = _read_bound_development_artifact(
            root,
            inventory,
            f"supervision/{filename}",
            maximum_bytes=1024 * 1024,
        )
        archived = _load_canonical_line_bytes(raw, label=f"supervision {subject}")
        if archived != report["supervision"][index]:
            raise FreezeManifestError(f"archived supervision differs: {subject}")
    _validate_development_worker_summaries(
        artifact_root=root, inventory=inventory, report=report
    )
    try:
        verify_artifact_semantics(
            root,
            plan,
            report,
            inventory,
            lambda relative, maximum: _read_bound_development_artifact(
                root,
                inventory,
                relative,
                maximum_bytes=maximum,
            ),
        )
    except DevelopmentArtifactVerificationError as error:
        raise FreezeManifestError(
            "development artifact semantic verification failed"
        ) from error
    return summary


def _validate_development_archive_manifest(
    value: Any,
    *,
    report_summary: Mapping[str, Any],
    report_raw: bytes,
    archive_bytes: int,
    archive_sha256: str,
) -> None:
    """Validate the non-self-referential inventory shipped with the archive."""

    manifest = _required_fields(
        value,
        {
            "schemaVersion",
            "suiteId",
            "executionId",
            "status",
            "countsTowardScientificVerdict",
            "usedForCandidateSelectionOrTuning",
            "scientificAttemptStateCreated",
            "nistUsed",
            "futureCorpusUsed",
            "thresholdsApplied",
            "artifactSetSHA256",
            "artifactCount",
            "rights",
            "assets",
            "excludedRole",
            "selfReferencePolicy",
            "contentSHA256",
        },
        label="development archive SHA-256 manifest",
    )
    _verify_embedded_content_digest(
        manifest, label="development archive SHA-256 manifest"
    )
    if (
        manifest["schemaVersion"] != DEVELOPMENT_ARCHIVE_MANIFEST_SCHEMA
        or manifest["suiteId"] != DEVELOPMENT_SUITE_ID
        or manifest["executionId"] != report_summary["executionId"]
        or manifest["status"]
        != "COMPLETE_NON_SCIENTIFIC_DEVELOPMENT_ARCHIVE_INVENTORY"
        or manifest["countsTowardScientificVerdict"] is not False
        or manifest["usedForCandidateSelectionOrTuning"] is not False
        or manifest["scientificAttemptStateCreated"] is not False
        or manifest["nistUsed"] is not False
        or manifest["futureCorpusUsed"] is not False
        or manifest["thresholdsApplied"] is not False
        or manifest["artifactSetSHA256"] != report_summary["artifactSetSHA256"]
        or manifest["artifactCount"] != report_summary["artifactCount"]
        or manifest["rights"] != DEVELOPMENT_RIGHTS_DECLARATION
        or manifest["excludedRole"] != "sha256-manifest"
        or manifest["selfReferencePolicy"]
        != "MANIFEST_EXCLUDES_ONLY_ITS_OWN_FILE_BYTES;GITHUB_RELEASE_ATTESTATION_BINDS_ALL_THREE_ASSETS"
    ):
        raise FreezeManifestError("development archive SHA-256 manifest differs")
    expected_assets = [
        {
            "role": "development-control-report",
            "name": "development-control-report.json",
            "bytes": len(report_raw),
            "sha256": sha256_bytes(report_raw),
        },
        {
            "role": "development-control-artifacts",
            "name": "development-control-artifacts.zip",
            "bytes": archive_bytes,
            "sha256": archive_sha256,
        },
    ]
    if manifest["assets"] != expected_assets:
        raise FreezeManifestError("development archive asset inventory differs")


def _verify_development_archive_zip(
    archive_path: Path,
    *,
    inventory: Sequence[Mapping[str, Any]],
    expected_sha256: str,
) -> int:
    """Stream one deterministic ZIP and bind every member to the report inventory."""

    absolute = _absolute_without_resolving(archive_path)
    parent_descriptor, _ = _open_directory_no_symlinks(absolute.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise FreezeManifestError(
                "development artifact archive is not a no-follow file"
            ) from error
    finally:
        os.close(parent_descriptor)
    expected = {item["path"]: item for item in inventory}
    rights_paths = {
        DEVELOPMENT_ARCHIVED_INPUTS[binding][0]: binding
        for binding in (
            "developmentCorpusManifest",
            "licenseSourceEvidence",
            "assetLicenseMatrix",
            "udEnglishPudReadme",
            "udEnglishPudLicense",
            "udEnglishPudAttribution",
        )
    }
    rights_paths[DEVELOPMENT_DATASET_PATH] = "developmentDataset"
    rights_raw: dict[str, bytes] = {}
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size >= DEVELOPMENT_ARCHIVE_MAX_BYTES
            ):
                raise FreezeManifestError(
                    "development artifact archive metadata or size cap differs"
                )
            archive_digest = hashlib.sha256()
            observed_archive_bytes = 0
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                archive_digest.update(chunk)
                observed_archive_bytes += len(chunk)
                if observed_archive_bytes >= DEVELOPMENT_ARCHIVE_MAX_BYTES:
                    raise FreezeManifestError(
                        "development artifact archive exceeds release size cap"
                    )
            if archive_digest.hexdigest() != expected_sha256:
                raise FreezeManifestError(
                    "development artifact archive SHA-256 differs"
                )
            stream.seek(0)
            try:
                with zipfile.ZipFile(stream, "r") as archive:
                    if archive.comment != b"":
                        raise FreezeManifestError(
                            "development artifact archive comment is forbidden"
                        )
                    information = archive.infolist()
                    expected_order = sorted(expected, key=os.fsencode)
                    if [item.filename for item in information] != expected_order:
                        raise FreezeManifestError(
                            "development artifact archive member order/set differs"
                        )
                    if len({item.filename for item in information}) != len(information):
                        raise FreezeManifestError(
                            "development artifact archive contains duplicate members"
                        )
                    for item in information:
                        commitment = expected[item.filename]
                        mode = item.external_attr >> 16
                        if (
                            item.filename.startswith("/")
                            or "\\" in item.filename
                            or any(
                                part in {"", ".", ".."}
                                for part in item.filename.split("/")
                            )
                            or item.is_dir()
                            or item.date_time != (1980, 1, 1, 0, 0, 0)
                            or item.compress_type != zipfile.ZIP_STORED
                            or item.flag_bits & 0x1
                            or item.extra != b""
                            or item.comment != b""
                            or item.create_system != 3
                            or not stat.S_ISREG(mode)
                            or stat.S_IMODE(mode) != 0o444
                            or item.file_size != commitment["bytes"]
                            or item.compress_size != commitment["bytes"]
                        ):
                            raise FreezeManifestError(
                                f"development archive member metadata differs: {item.filename}"
                            )
                        digest = hashlib.sha256()
                        observed = 0
                        captured = (
                            bytearray() if item.filename in rights_paths else None
                        )
                        with archive.open(item, "r") as member:
                            while True:
                                chunk = member.read(READ_CHUNK_BYTES)
                                if not chunk:
                                    break
                                digest.update(chunk)
                                observed += len(chunk)
                                if captured is not None:
                                    captured.extend(chunk)
                                    if observed > MAX_DESIGN_BYTES:
                                        raise FreezeManifestError(
                                            "development rights artifact exceeds fixed bound"
                                        )
                                if observed > commitment["bytes"]:
                                    raise FreezeManifestError(
                                        "development archive member exceeds commitment"
                                    )
                        if (
                            observed != commitment["bytes"]
                            or digest.hexdigest() != commitment["sha256"]
                        ):
                            raise FreezeManifestError(
                                f"development archive member bytes differ: {item.filename}"
                            )
                        if captured is not None:
                            rights_raw[rights_paths[item.filename]] = bytes(captured)
                    _validate_development_rights_evidence(rights_raw)
            except (OSError, zipfile.BadZipFile, RuntimeError) as error:
                raise FreezeManifestError(
                    "development artifact archive is not a valid deterministic ZIP"
                ) from error
            after = os.fstat(stream.fileno())
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or observed_archive_bytes != before.st_size
            ):
                raise FreezeManifestError(
                    "development artifact archive changed while verifying"
                )
            return observed_archive_bytes
    except Exception:
        # ``os.fdopen`` owns the descriptor after construction; this branch is
        # deliberately descriptor-agnostic.
        raise


def verify_development_control_archive(
    receipt_path: Path,
    *,
    archive_asset_root: Path,
    report_path: Path,
    report_summary: Mapping[str, Any],
    expected_implementation: Mapping[str, Any],
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> dict[str, Any]:
    """Verify the signed, GitHub-attested pre-freeze development archive."""

    _validate_source(expected_implementation, label="development archive source")
    receipt_raw = read_regular_bytes(receipt_path, maximum_bytes=MAX_RECEIPT_BYTES)
    try:
        verified = verify_release_receipt(
            receipt_raw,
            archive_asset_root,
            expected_repository=_github_repository_slug(
                expected_implementation["repository"],
                label="development archive repository",
            ),
            expected_kind="development-control",
            expected_tag=DEVELOPMENT_ARCHIVE_TAG,
            expected_commit=expected_implementation["commit"],
            expected_tree=expected_implementation["tree"],
            expected_deadline="2026-08-15T00:00:00Z",
            expected_signature_type="SSH",
            expected_key_fingerprint=DEVELOPMENT_SIGNING_KEY_FINGERPRINT,
            expected_public_key_sha256=DEVELOPMENT_SIGNING_PUBLIC_KEY_SHA256,
            cryptographic_attestation_verifier=(
                cryptographic_attestation_verifier
            ),
        )
    except ReleaseReceiptError as error:
        raise FreezeManifestError(
            "development archive release receipt failed offline verification"
        ) from error
    published = _utc_second(
        verified.published_at, label="development archive publishedAt"
    )
    attested = _utc_second(
        verified.attested_at, label="development archive attestedAt"
    )
    completed = _utc_second(
        report_summary.get("completedAt"), label="development control completedAt"
    )
    if (
        published < completed
        or published > attested
        or attested < completed
        or attested >= DESIGN_PUBLISH_DEADLINE
    ):
        raise FreezeManifestError(
            "development archive was not attested after completion and before freeze"
        )
    asset_hashes = dict(verified.asset_sha256)
    if set(asset_hashes) != {
        "development-control-report.json",
        "development-control-artifacts.zip",
        "sha256-manifest.json",
    }:
        raise FreezeManifestError("development archive receipt asset set differs")
    archived_report_raw = read_regular_bytes(
        archive_asset_root / "development-control-report.json",
        maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES,
    )
    report_raw = read_regular_bytes(
        report_path, maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES
    )
    if archived_report_raw != report_raw:
        raise FreezeManifestError(
            "development archive report differs from verified completion marker"
        )
    report = _load_canonical_line_bytes(
        report_raw, label="development-control archive report"
    )
    if (
        sha256_bytes(report_raw) != report_summary.get("reportFileSHA256")
        or report.get("executionId") != report_summary.get("executionId")
        or report.get("artifactSetSHA256")
        != report_summary.get("artifactSetSHA256")
    ):
        raise FreezeManifestError("development archive report binding differs")
    archive_path = archive_asset_root / "development-control-artifacts.zip"
    archive_bytes = _verify_development_archive_zip(
        archive_path,
        inventory=report["artifactInventory"],
        expected_sha256=asset_hashes["development-control-artifacts.zip"],
    )
    manifest_raw = read_regular_bytes(
        archive_asset_root / "sha256-manifest.json",
        maximum_bytes=MAX_DEVELOPMENT_REPORT_BYTES,
    )
    manifest = _load_canonical_line_bytes(
        manifest_raw, label="development archive SHA-256 manifest"
    )
    _validate_development_archive_manifest(
        manifest,
        report_summary=report_summary,
        report_raw=report_raw,
        archive_bytes=archive_bytes,
        archive_sha256=asset_hashes["development-control-artifacts.zip"],
    )
    if sha256_bytes(manifest_raw) != asset_hashes["sha256-manifest.json"]:
        raise FreezeManifestError(
            "development archive SHA-256 manifest differs from release receipt"
        )
    return {
        "status": "VERIFIED_GITHUB_ATTESTED_DEVELOPMENT_ARCHIVE",
        "receiptSHA256": sha256_bytes(receipt_raw),
        "publishedAt": verified.published_at,
        "attestedAt": verified.attested_at,
        "attestationBundleSHA256": verified.attestation_bundle_sha256,
        "attestationOutputSHA256": verified.attestation_output_sha256,
        "artifactArchiveSHA256": asset_hashes[
            "development-control-artifacts.zip"
        ],
        "archiveManifestSHA256": sha256_bytes(manifest_raw),
        "reportSHA256": asset_hashes["development-control-report.json"],
    }


def _github_repository_base(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise FreezeManifestError(f"{label} must be a GitHub HTTPS repository")
    parsed = urlsplit(value)
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or len(parts) != 2
        or any(not part for part in parts)
    ):
        raise FreezeManifestError(f"{label} must be a GitHub HTTPS repository")
    repository = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if not repository or any(
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
        for part in (parts[0], repository)
    ):
        raise FreezeManifestError(f"{label} GitHub owner/repository is invalid")
    return f"https://github.com/{parts[0]}/{repository}"


def _validate_source(value: Any, *, label: str) -> Mapping[str, Any]:
    source = _required_fields(
        value, {"repository", "commit", "tree"}, label=label
    )
    _github_repository_base(source["repository"], label=f"{label} repository")
    _digest(source["commit"], label=f"{label} commit", length=40)
    _digest(source["tree"], label=f"{label} tree", length=40)
    return source


def _run_live_git(arguments: Sequence[str], *, label: str) -> bytes:
    if not GIT_EXECUTABLE.is_file() or not os.access(GIT_EXECUTABLE, os.X_OK):
        raise FreezeManifestError("trusted /usr/bin/git executable is unavailable")
    try:
        completed = subprocess.run(
            [
                str(GIT_EXECUTABLE),
                "-C",
                str(PROJECT_ROOT),
                "-c",
                "core.fileMode=true",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.ignoreStat=false",
                "-c",
                "core.untrackedCache=false",
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=GIT_COMMAND_TIMEOUT_SECONDS,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FreezeManifestError(f"live Git {label} check failed closed") from error
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > MAX_GIT_OUTPUT_BYTES
    ):
        raise FreezeManifestError(f"live Git {label} check failed closed")
    return completed.stdout


def _single_git_line(raw: bytes, *, label: str) -> str:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        raise FreezeManifestError(f"live Git {label} output is not one canonical line")
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise FreezeManifestError(f"live Git {label} output is not ASCII") from error
    if not value or "\x00" in value:
        raise FreezeManifestError(f"live Git {label} output is invalid")
    return value


def _verify_live_implementation_source(implementation: Mapping[str, Any]) -> None:
    """Bind freeze operations to the exact, completely clean live checkout.

    Git's normal ignored-file exclusion is intentional: runtime and release
    artifacts may be ignored, while every tracked modification and every
    non-ignored untracked path causes a fail-closed rejection.
    """

    expected = _validate_source(implementation, label="implementation")
    observed_commit = _single_git_line(
        _run_live_git(
            ("rev-parse", "--verify", "HEAD^{commit}"), label="HEAD commit"
        ),
        label="HEAD commit",
    )
    observed_tree = _single_git_line(
        _run_live_git(
            ("rev-parse", "--verify", "HEAD^{tree}"), label="HEAD tree"
        ),
        label="HEAD tree",
    )
    observed_origin = _single_git_line(
        _run_live_git(("remote", "get-url", "origin"), label="origin"),
        label="origin",
    )
    if observed_commit != expected["commit"]:
        raise FreezeManifestError("live implementation HEAD commit differs")
    if observed_tree != expected["tree"]:
        raise FreezeManifestError("live implementation HEAD tree differs")
    if _github_repository_base(
        observed_origin, label="live implementation origin"
    ) != _github_repository_base(
        expected["repository"], label="implementation repository"
    ):
        raise FreezeManifestError("live implementation origin differs")

    index_entries = _run_live_git(
        ("ls-files", "-v", "-z"), label="tracked index flags"
    )
    if index_entries and (
        not index_entries.endswith(b"\x00")
        or any(
            len(entry) < 3 or entry[:2] != b"H "
            for entry in index_entries[:-1].split(b"\x00")
        )
    ):
        raise FreezeManifestError(
            "live implementation index has non-canonical tracked flags or state"
        )

    status = _run_live_git(
        (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ),
        label="worktree status",
    )
    if status:
        raise FreezeManifestError(
            "live implementation worktree is not clean: tracked or untracked "
            "paths are present"
        )


def _github_repository_slug(value: Any, *, label: str) -> str:
    base = _github_repository_base(value, label=label)
    return urlsplit(base).path.strip("/")


def _gate_manifest_sections(
    verified: VerifiedGitHubGateReceipt,
    *,
    implementation_repository: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    implementation_base = _github_repository_base(
        implementation_repository, label="implementation repository"
    )
    author_verification = {
        "pullRequestURL": (
            f"{implementation_base}/pull/{verified.pull_request_number}"
        ),
        "pullRequestNumber": verified.pull_request_number,
        "mode": verified.author_verification_mode,
        "authorName": verified.author_name,
        "authorORCID": verified.author_orcid,
        "authorGitHubLogin": verified.author_github_login,
        "implementationCommit": verified.implementation_commit,
        "independentHumanReviewRequired": (
            verified.independent_human_review_required
        ),
        "independentHumanReviewPerformed": (
            verified.independent_human_review_performed
        ),
        "declaration": verified.author_verification_declaration,
        "claimBoundary": verified.author_verification_claim_boundary,
    }
    continuous_integration = {
        "runURL": f"{implementation_base}/actions/runs/{verified.workflow_run_id}",
        "runId": verified.workflow_run_id,
        "workflowId": verified.workflow_id,
        "workflowName": verified.workflow_name,
        "workflowPath": verified.workflow_path,
        "status": "completed",
        "conclusion": "success",
        "headSHA": verified.implementation_commit,
        "allJobsCompletedSuccess": True,
        "zeroSkippedOrCancelledJobs": True,
        "jobIds": list(verified.job_ids),
        "linuxJobIds": list(verified.linux_job_ids),
        "macOSArm64JobIds": list(verified.macos_arm64_job_ids),
        "artifactSHA256": [
            {"name": name, "sha256": digest}
            for name, digest in verified.artifact_sha256
        ],
        "evidenceBoundary": verified.evidence_boundary,
        "gateFirstServerDate": verified.first_server_date,
        "gateLastServerDate": verified.last_server_date,
        "observationCapturedAt": verified.receipt_created_at,
    }
    return author_verification, continuous_integration


def _verify_github_gate_input(
    path: Path,
    *,
    implementation: Mapping[str, Any],
) -> tuple[VerifiedGitHubGateReceipt, bytes]:
    raw = read_regular_bytes(path, maximum_bytes=MAX_GITHUB_GATE_RECEIPT_BYTES)
    try:
        value = load_json_strict_bytes(raw, label="GitHub gate receipt")
    except ValueError as error:
        raise FreezeManifestError("GitHub gate receipt is not strict JSON") from error
    if not isinstance(value, dict):
        raise FreezeManifestError("GitHub gate receipt must be an object")
    try:
        author_verification = value["authorVerification"]
        ci_gate = value["ciGate"]
        if not isinstance(author_verification, dict) or not isinstance(ci_gate, dict):
            raise KeyError("gate summary")
        verified = verify_github_gate_receipt(
            raw,
            expected_repository=_github_repository_slug(
                implementation["repository"], label="implementation repository"
            ),
            expected_pull_request_number=value["pullRequestNumber"],
            expected_implementation_commit=implementation["commit"],
            expected_workflow_run_id=ci_gate["runId"],
            expected_workflow_name=ci_gate["workflowName"],
            expected_workflow_path=ci_gate["workflowPath"],
        )
    except (GitHubGateReceiptError, KeyError, TypeError) as error:
        raise FreezeManifestError(
            "GitHub CI receipt failed offline structural verification"
        ) from error
    return verified, raw


def validate_freeze_manifest(value: Any) -> None:
    """Validate the closed canonical contract and all cross-field identities."""

    manifest = _required_fields(
        value,
        {
            "schemaVersion",
            "status",
            "suiteId",
            "countsTowardScientificVerdict",
            "freezeProcedure",
            "implementation",
            "codec",
            "developmentControl",
            "artifacts",
            "authorVerification",
            "continuousIntegration",
            "createdAt",
            "contentSHA256",
        },
        label="freeze manifest",
    )
    if manifest["schemaVersion"] != SCHEMA_VERSION:
        raise FreezeManifestError("freeze manifest schema differs")
    if manifest["status"] != STATUS:
        raise FreezeManifestError("freeze manifest status differs")
    if manifest["suiteId"] != SUITE_ID:
        raise FreezeManifestError("freeze manifest suite differs")
    if manifest["countsTowardScientificVerdict"] is not False:
        raise FreezeManifestError("freeze manifest cannot claim a scientific verdict")
    if manifest["freezeProcedure"] != FREEZE_PROCEDURE:
        raise FreezeManifestError("two-stage freeze procedure differs")
    implementation = _validate_source(manifest["implementation"], label="implementation")
    _validate_source(manifest["codec"], label="codec")

    development = _required_fields(
        manifest["developmentControl"],
        {
            "status",
            "reportSchemaVersion",
            "reportFileName",
            "executionId",
            "artifactCount",
            "completedAt",
            "archivePublishedAt",
            "archiveAttestedAt",
            "serverTimestampedArchiveVerified",
            "countsTowardScientificVerdict",
            "usedForCandidateSelectionOrTuning",
            "scientificAttemptStateCreated",
            "nistUsed",
            "futureCorpusUsed",
            "thresholdsApplied",
        },
        label="development control freeze gate",
    )
    if (
        development["status"] != "VERIFIED_REAL_DATA_E2E_FREEZE_GATE"
        or development["reportSchemaVersion"] != DEVELOPMENT_REPORT_SCHEMA
        or development["reportFileName"] != "development-control-report.json"
        or not isinstance(development["executionId"], str)
        or re.fullmatch(
            r"development-execution-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}",
            development["executionId"],
        )
        is None
        or development["artifactCount"] != len(_expected_development_artifact_paths())
        or development["serverTimestampedArchiveVerified"] is not True
        or development["countsTowardScientificVerdict"] is not False
        or development["usedForCandidateSelectionOrTuning"] is not False
        or development["scientificAttemptStateCreated"] is not False
        or development["nistUsed"] is not False
        or development["futureCorpusUsed"] is not False
        or development["thresholdsApplied"] is not False
    ):
        raise FreezeManifestError("development control freeze gate differs")
    development_completed = _utc_second(
        development["completedAt"], label="development control completedAt"
    )
    development_archive_published = _utc_second(
        development["archivePublishedAt"],
        label="development control archivePublishedAt",
    )
    development_archive_attested = _utc_second(
        development["archiveAttestedAt"],
        label="development control archiveAttestedAt",
    )
    if (
        development_completed >= DESIGN_PUBLISH_DEADLINE
        or development_archive_published < development_completed
        or development_archive_published > development_archive_attested
        or development_archive_attested >= DESIGN_PUBLISH_DEADLINE
    ):
        raise FreezeManifestError("development control missed the registered cutoff")

    artifacts = _required_fields(
        manifest["artifacts"],
        {
            "runtimeManifestSHA256",
            "fullAssetReceiptSHA256",
            "transportCABundleSHA256",
            "offlineTrustBundleSHA256",
            "githubGateReceiptSHA256",
            "developmentControlReportSHA256",
            "developmentControlArtifactSetSHA256",
            "developmentControlConfigurationSHA256",
            "developmentControlArchiveReceiptSHA256",
            "developmentControlReleaseAttestationBundleSHA256",
            "developmentControlReleaseAttestationOutputSHA256",
            "developmentControlArtifactArchiveSHA256",
            "developmentControlArchiveManifestSHA256",
        },
        label="freeze artifact commitments",
    )
    for field, digest in artifacts.items():
        _digest(digest, label=field)

    author_verification = _required_fields(
        manifest["authorVerification"],
        {
            "pullRequestURL",
            "pullRequestNumber",
            "mode",
            "authorName",
            "authorORCID",
            "authorGitHubLogin",
            "implementationCommit",
            "independentHumanReviewRequired",
            "independentHumanReviewPerformed",
            "declaration",
            "claimBoundary",
        },
        label="author verification",
    )
    pr_number = author_verification["pullRequestNumber"]
    if type(pr_number) is not int or pr_number < 1:
        raise FreezeManifestError("pull request number must be positive")
    implementation_base = _github_repository_base(
        implementation["repository"], label="implementation repository"
    )
    if author_verification["pullRequestURL"] != f"{implementation_base}/pull/{pr_number}":
        raise FreezeManifestError("pull request URL does not match implementation repository")
    if (
        author_verification["mode"] != "AUTHOR_SELF_VERIFICATION"
        or author_verification["authorName"] != "Ivan Tyshchenko"
        or author_verification["authorORCID"]
        != "https://orcid.org/0009-0000-7935-6090"
        or author_verification["authorGitHubLogin"] != "ALLPROTO"
        or author_verification["implementationCommit"]
        != implementation["commit"]
        or author_verification["independentHumanReviewRequired"] is not False
        or author_verification["independentHumanReviewPerformed"] is not False
        or not isinstance(author_verification["declaration"], str)
        or "not independent human review"
        not in author_verification["declaration"]
        or author_verification["claimBoundary"]
        != (
            "AUTHOR_SELF_VERIFICATION_ONLY;"
            "NO_INDEPENDENT_HUMAN_REVIEW;"
            "NO_PEER_REVIEW;"
            "NO_OPERATOR_BLINDNESS;"
            "NO_INDEPENDENT_REPLICATION"
        )
    ):
        raise FreezeManifestError("author self-verification disclosure differs")
    repository_owner = urlsplit(implementation_base).path.strip("/").split("/", 1)[0]
    if author_verification["authorGitHubLogin"].casefold() != repository_owner.casefold():
        raise FreezeManifestError("author login does not match repository owner")

    ci = _required_fields(
        manifest["continuousIntegration"],
        {
            "runURL",
            "runId",
            "workflowId",
            "workflowName",
            "workflowPath",
            "status",
            "conclusion",
            "headSHA",
            "allJobsCompletedSuccess",
            "zeroSkippedOrCancelledJobs",
            "jobIds",
            "linuxJobIds",
            "macOSArm64JobIds",
            "artifactSHA256",
            "evidenceBoundary",
            "gateFirstServerDate",
            "gateLastServerDate",
            "observationCapturedAt",
        },
        label="continuous integration",
    )
    run_id = ci["runId"]
    if type(run_id) is not int or run_id < 1:
        raise FreezeManifestError("CI run id must be positive")
    if ci["runURL"] != f"{implementation_base}/actions/runs/{run_id}":
        raise FreezeManifestError("CI run URL does not match implementation repository")
    if type(ci["workflowId"]) is not int or ci["workflowId"] < 1:
        raise FreezeManifestError("CI workflow id must be positive")
    if ci["workflowName"] != REQUIRED_WORKFLOW_NAME:
        raise FreezeManifestError("CI workflow name is not the registered gate")
    workflow_path = ci["workflowPath"]
    if (
        workflow_path != REQUIRED_WORKFLOW_PATH
    ):
        raise FreezeManifestError("CI workflow path is not the registered gate")
    if ci["status"] != "completed" or ci["conclusion"] != "success":
        raise FreezeManifestError("CI run is not completed successfully")
    if ci["headSHA"] != implementation["commit"]:
        raise FreezeManifestError("CI head SHA does not bind implementation commit")
    if (
        ci["allJobsCompletedSuccess"] is not True
        or ci["zeroSkippedOrCancelledJobs"] is not True
    ):
        raise FreezeManifestError("CI job gate is not zero-skip completed success")
    job_ids = ci["jobIds"]
    linux_job_ids = ci["linuxJobIds"]
    macos_job_ids = ci["macOSArm64JobIds"]
    if (
        not isinstance(job_ids, list)
        or len(job_ids) < 2
        or len(job_ids) > 100
        or any(type(item) is not int or item < 1 for item in job_ids)
        or len(set(job_ids)) != len(job_ids)
        or not isinstance(linux_job_ids, list)
        or not linux_job_ids
        or any(type(item) is not int or item < 1 for item in linux_job_ids)
        or len(set(linux_job_ids)) != len(linux_job_ids)
        or any(item not in job_ids for item in linux_job_ids)
        or not isinstance(macos_job_ids, list)
        or not macos_job_ids
        or any(type(item) is not int or item < 1 for item in macos_job_ids)
        or len(set(macos_job_ids)) != len(macos_job_ids)
        or any(item not in job_ids for item in macos_job_ids)
    ):
        raise FreezeManifestError("CI exact job/platform identity set differs")
    artifact_digests = ci["artifactSHA256"]
    if not isinstance(artifact_digests, list):
        raise FreezeManifestError("CI artifact digest inventory is invalid")
    artifact_names: set[str] = set()
    for artifact in artifact_digests:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"name", "sha256"}
            or not isinstance(artifact["name"], str)
            or not artifact["name"]
            or artifact["name"] in artifact_names
        ):
            raise FreezeManifestError("CI artifact digest record differs")
        artifact_names.add(artifact["name"])
        _digest(artifact["sha256"], label="CI artifact SHA-256")
    try:
        canonical_artifacts = canonical_ci_artifact_commitments(
            [(item["name"], item["sha256"]) for item in artifact_digests],
            run_id=run_id,
        )
    except GitHubGateReceiptError as error:
        raise FreezeManifestError(
            "CI artifact digest inventory lacks exact platform payloads"
        ) from error
    if tuple((item["name"], item["sha256"]) for item in artifact_digests) != (
        canonical_artifacts
    ):
        raise FreezeManifestError("CI artifact digest order is not canonical")
    gate_first = _utc_second(
        ci["gateFirstServerDate"], label="CI gate first server Date"
    )
    gate_last = _utc_second(
        ci["gateLastServerDate"], label="CI gate last server Date"
    )
    gate_captured = _utc_second(
        ci["observationCapturedAt"], label="CI gate observationCapturedAt"
    )
    if ci["evidenceBoundary"] != GITHUB_GATE_EVIDENCE_BOUNDARY:
        raise FreezeManifestError("GitHub gate evidence boundary is overstated")
    if gate_first > gate_last:
        raise FreezeManifestError("CI gate server-Date window is reversed")
    if gate_last > DECISION_CHECKPOINT:
        raise FreezeManifestError("GitHub CI gate missed the decision checkpoint")
    created_at = _utc_second(manifest["createdAt"], label="freeze manifest createdAt")
    if created_at >= DESIGN_PUBLISH_DEADLINE:
        raise FreezeManifestError("freeze manifest missed the design publication deadline")
    if (
        gate_last > created_at
        or gate_captured < gate_last
        or gate_captured > created_at
        or (created_at - gate_captured).total_seconds()
        > GITHUB_GATE_MAXIMUM_CAPTURE_SPAN_SECONDS
        or development_completed > created_at
        or development_archive_published > created_at
        or development_archive_attested > created_at
    ):
        raise FreezeManifestError(
            "freeze manifest predates CI or development-control completion"
        )
    _digest(manifest["contentSHA256"], label="freeze manifest contentSHA256")
    try:
        verify_content_digest(dict(manifest))
    except ValueError as error:
        raise FreezeManifestError(str(error)) from error


def canonical_freeze_manifest_bytes(value: Mapping[str, Any]) -> bytes:
    validate_freeze_manifest(value)
    return canonical_json_bytes(value) + b"\n"


def load_freeze_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, maximum_bytes=MAX_FREEZE_MANIFEST_BYTES)
    value = load_json_strict_bytes(raw, label="freeze manifest")
    if not isinstance(value, dict):
        raise FreezeManifestError("freeze manifest must be a JSON object")
    if canonical_json_bytes(value) + b"\n" != raw:
        raise FreezeManifestError("freeze manifest is not canonical JSON plus terminal LF")
    validate_freeze_manifest(value)
    return value, raw


def _load_canonical_receipt(
    path: Path, *, label: str, maximum_bytes: int
) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(path, maximum_bytes=maximum_bytes)
    value = load_json_strict_bytes(raw, label=label)
    if not isinstance(value, dict):
        raise FreezeManifestError(f"{label} must be a JSON object")
    if canonical_json_bytes(value) + b"\n" != raw:
        raise FreezeManifestError(f"{label} is not canonical JSON plus terminal LF")
    try:
        verify_content_digest(value)
    except ValueError as error:
        raise FreezeManifestError(f"{label}: {error}") from error
    return value, raw


def _verify_runtime_receipt(
    runtime: Mapping[str, Any],
    *,
    implementation: Mapping[str, Any],
    codec: Mapping[str, Any],
) -> None:
    try:
        verify_runtime_manifest_integrity(runtime)
    except ValueError as error:
        raise FreezeManifestError(f"runtime manifest integrity failed: {error}") from error
    expected_fields = {
        "schemaVersion",
        "status",
        "countsTowardScientificVerdict",
        "networkUsed",
        "modelInferenceUsed",
        "python",
        "host",
        "environment",
        "requirementsLocks",
        "installedDistributions",
        "installedDistributionCount",
        "runtimeTree",
        "basePythonTree",
        "basePythonDistinctFromRuntime",
        "labSource",
        "codecSource",
        "contentSHA256",
    }
    if set(runtime) != expected_fields:
        raise FreezeManifestError("runtime manifest fields differ")
    if runtime.get("schemaVersion") != RUNTIME_SCHEMA:
        raise FreezeManifestError("runtime manifest schema differs")
    if runtime.get("status") != "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY":
        raise FreezeManifestError("runtime manifest status differs")
    for field in ("countsTowardScientificVerdict", "networkUsed", "modelInferenceUsed"):
        if runtime.get(field) is not False:
            raise FreezeManifestError(f"runtime manifest boundary differs: {field}")
    python = runtime.get("python")
    if (
        not isinstance(python, dict)
        or python.get("registeredVersion") != "3.12.10"
        or python.get("version") != "3.12.10"
        or not isinstance(python.get("platformTag"), str)
        or re.fullmatch(r"macosx-[A-Za-z0-9_.-]+-arm64", python["platformTag"])
        is None
        or not isinstance(python.get("executable"), dict)
    ):
        raise FreezeManifestError("runtime Python identity differs")
    executable = python["executable"]
    if (
        type(executable.get("bytes")) is not int
        or executable["bytes"] <= 0
        or not isinstance(executable.get("sha256"), str)
        or SHA256.fullmatch(executable["sha256"]) is None
    ):
        raise FreezeManifestError("runtime Python executable commitment differs")
    host = runtime.get("host")
    if (
        not isinstance(host, dict)
        or host.get("system") != "Darwin"
        or host.get("machine") != "arm64"
        or not isinstance(host.get("macVersion"), str)
        or not host["macVersion"]
    ):
        raise FreezeManifestError("runtime primary host is not macOS arm64")
    locks = runtime.get("requirementsLocks")
    if locks != REGISTERED_REQUIREMENTS_LOCKS:
        raise FreezeManifestError("runtime requirements lock set differs")
    distributions = runtime.get("installedDistributions")
    distribution_count = runtime.get("installedDistributionCount")
    if (
        not isinstance(distributions, list)
        or not distributions
        or type(distribution_count) is not int
        or distribution_count != len(distributions)
    ):
        raise FreezeManifestError("runtime distribution inventory differs")
    for field in ("runtimeTree", "basePythonTree"):
        tree = runtime.get(field)
        if (
            not isinstance(tree, dict)
            or type(tree.get("entryCount")) is not int
            or tree["entryCount"] <= 0
            or not isinstance(tree.get("treeSHA256"), str)
            or SHA256.fullmatch(tree["treeSHA256"]) is None
        ):
            raise FreezeManifestError(f"runtime {field} inventory differs")
    if type(runtime.get("basePythonDistinctFromRuntime")) is not bool:
        raise FreezeManifestError("runtime base-Python boundary differs")
    for field, expected in (("labSource", implementation), ("codecSource", codec)):
        source = runtime.get(field)
        if not isinstance(source, dict):
            raise FreezeManifestError(f"runtime {field} is missing")
        if source.get("commit") != expected["commit"] or source.get("tree") != expected["tree"]:
            raise FreezeManifestError(f"runtime {field} Git identity differs")
        if source.get("worktreeClean") is not True:
            raise FreezeManifestError(f"runtime {field} worktree was not clean")
        if _github_repository_base(
            source.get("origin"), label=f"runtime {field} origin"
        ) != _github_repository_base(
            expected["repository"], label=f"freeze {field} repository"
        ):
            raise FreezeManifestError(f"runtime {field} repository differs")


def _verify_asset_receipt(assets: Mapping[str, Any]) -> None:
    expected_fields = {
        "schemaVersion",
        "status",
        "countsTowardScientificVerdict",
        "networkUsed",
        "modelInferenceUsed",
        "manifestFile",
        "manifestSchemaVersion",
        "manifestDeclaredStatus",
        "manifestDeclaredFullSafetensorsBytesLocallyVerified",
        "manifestFileBytes",
        "manifestFileSHA256",
        "assetLayout",
        "fileCount",
        "totalBytes",
        "fullSafetensorsBytesLocallyVerified",
        "fullSafetensorsBytes",
        "models",
        "contentSHA256",
    }
    if set(assets) != expected_fields:
        raise FreezeManifestError("asset receipt fields differ")
    if assets.get("schemaVersion") != ASSET_RECEIPT_SCHEMA:
        raise FreezeManifestError("asset receipt schema differs")
    if assets.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED":
        raise FreezeManifestError("asset receipt status differs")
    for field in ("countsTowardScientificVerdict", "networkUsed", "modelInferenceUsed"):
        if assets.get(field) is not False:
            raise FreezeManifestError(f"asset receipt boundary differs: {field}")
    if assets.get("fullSafetensorsBytesLocallyVerified") is not True:
        raise FreezeManifestError("asset receipt does not bind fully rehashed weights")
    if (
        assets.get("fileCount") != EXPECTED_ASSET_FILES
        or assets.get("totalBytes") != EXPECTED_ASSET_BYTES
        or assets.get("fullSafetensorsBytes") != EXPECTED_WEIGHT_BYTES
    ):
        raise FreezeManifestError("asset receipt aggregate commitments differ")
    if (
        type(assets.get("manifestFileBytes")) is not int
        or assets["manifestFileBytes"] <= 0
        or not isinstance(assets.get("manifestFileSHA256"), str)
        or SHA256.fullmatch(assets["manifestFileSHA256"]) is None
    ):
        raise FreezeManifestError("asset manifest commitment differs")
    models = assets.get("models")
    if not isinstance(models, dict) or tuple(models) != MODEL_KEYS:
        raise FreezeManifestError("asset receipt model set/order differs")
    total_files = 0
    total_bytes = 0
    total_weight_bytes = 0
    for model_key in MODEL_KEYS:
        model = models[model_key]
        if not isinstance(model, dict) or set(model) != {
            "repository",
            "revision",
            "license",
            "licenseURL",
            "files",
        }:
            raise FreezeManifestError(f"asset receipt model fields differ: {model_key}")
        files = model["files"]
        if not isinstance(files, dict) or len(files) != 8 or "model.safetensors" not in files:
            raise FreezeManifestError(f"asset receipt file list differs: {model_key}")
        for filename, commitment in files.items():
            if (
                not isinstance(filename, str)
                or not filename
                or not isinstance(commitment, dict)
                or set(commitment) != {"bytes", "sha256"}
                or type(commitment["bytes"]) is not int
                or commitment["bytes"] <= 0
                or not isinstance(commitment["sha256"], str)
                or SHA256.fullmatch(commitment["sha256"]) is None
            ):
                raise FreezeManifestError(
                    f"asset receipt file commitment differs: {model_key}/{filename}"
                )
            total_files += 1
            total_bytes += commitment["bytes"]
            if filename == "model.safetensors":
                total_weight_bytes += commitment["bytes"]
    if (
        total_files != EXPECTED_ASSET_FILES
        or total_bytes != EXPECTED_ASSET_BYTES
        or total_weight_bytes != EXPECTED_WEIGHT_BYTES
    ):
        raise FreezeManifestError("asset receipt recomputed aggregates differ")


def default_ca_verifier(path: Path, expected_sha256: str) -> None:
    PinnedHTTPSClient(
        ca_bundle=path,
        ca_bundle_sha256=expected_sha256,
        allowed_hosts=PROJECTS,
    )


def default_trust_verifier(path: Path, expected_sha256: str) -> None:
    bundle = load_offline_trust_bundle(
        path,
        expected_time=PULSE_TIME,
        expected_manifest_sha256=expected_sha256,
        expected_root_der_sha256=(NIST_TRUST_ROOT_DER_SHA256,),
        allow_fixture=False,
    )
    if bundle.fixture_only:
        raise FreezeManifestError("fixture NIST trust bundle cannot enter a freeze")


def verify_artifact_inputs(
    manifest: Mapping[str, Any],
    *,
    runtime_manifest_path: Path,
    asset_receipt_path: Path,
    ca_bundle_path: Path,
    trust_manifest_path: Path,
    github_gate_receipt_path: Path,
    development_control_report_path: Path,
    development_control_artifact_root: Path,
    development_control_archive_receipt_path: Path,
    development_control_archive_asset_root: Path,
    ca_verifier: CAVerifier = default_ca_verifier,
    trust_verifier: TrustVerifier = default_trust_verifier,
    development_control_verifier: DevelopmentControlVerifier = (
        verify_development_control_report
    ),
    development_archive_verifier: DevelopmentArchiveVerifier = (
        verify_development_control_archive
    ),
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> dict[str, Any]:
    """Re-open every bound artifact and verify bytes, receipts, and source identities."""

    validate_freeze_manifest(manifest)
    _verify_live_implementation_source(manifest["implementation"])
    runtime, runtime_raw = _load_canonical_receipt(
        runtime_manifest_path,
        label="runtime manifest",
        maximum_bytes=MAX_RUNTIME_MANIFEST_BYTES,
    )
    assets, asset_raw = _load_canonical_receipt(
        asset_receipt_path,
        label="full asset receipt",
        maximum_bytes=MAX_RECEIPT_BYTES,
    )
    _verify_runtime_receipt(
        runtime,
        implementation=manifest["implementation"],
        codec=manifest["codec"],
    )
    _verify_asset_receipt(assets)
    verified_gate, gate_raw = _verify_github_gate_input(
        github_gate_receipt_path,
        implementation=manifest["implementation"],
    )
    expected_author_verification, expected_ci = _gate_manifest_sections(
        verified_gate,
        implementation_repository=manifest["implementation"]["repository"],
    )
    if manifest["authorVerification"] != expected_author_verification:
        raise FreezeManifestError(
            "author verification differs from verified GitHub CI receipt"
        )
    if manifest["continuousIntegration"] != expected_ci:
        raise FreezeManifestError("CI fields differ from verified GitHub gate receipt")
    commitments = manifest["artifacts"]
    if sha256_bytes(runtime_raw) != commitments["runtimeManifestSHA256"]:
        raise FreezeManifestError("runtime manifest file SHA-256 differs")
    if sha256_bytes(asset_raw) != commitments["fullAssetReceiptSHA256"]:
        raise FreezeManifestError("full asset receipt file SHA-256 differs")
    if sha256_bytes(gate_raw) != commitments["githubGateReceiptSHA256"]:
        raise FreezeManifestError("GitHub gate receipt file SHA-256 differs")

    development = development_control_verifier(
        development_control_report_path,
        artifact_root=development_control_artifact_root,
        expected_implementation=manifest["implementation"],
        expected_codec=manifest["codec"],
        completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
        expected_runtime_manifest_sha256=sha256_bytes(runtime_raw),
        require_artifacts=True,
    )
    development_archive = development_archive_verifier(
        development_control_archive_receipt_path,
        archive_asset_root=development_control_archive_asset_root,
        report_path=development_control_report_path,
        report_summary=development,
        expected_implementation=manifest["implementation"],
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    if (
        development.get("reportFileSHA256")
        != commitments["developmentControlReportSHA256"]
        or development.get("artifactSetSHA256")
        != commitments["developmentControlArtifactSetSHA256"]
        or development.get("controlConfigurationSHA256")
        != commitments["developmentControlConfigurationSHA256"]
        or development.get("artifactCount")
        != manifest["developmentControl"]["artifactCount"]
        or development.get("completedAt")
        != manifest["developmentControl"]["completedAt"]
        or development.get("executionId")
        != manifest["developmentControl"]["executionId"]
        or development_archive.get("publishedAt")
        != manifest["developmentControl"]["archivePublishedAt"]
        or development_archive.get("attestedAt")
        != manifest["developmentControl"]["archiveAttestedAt"]
        or development_archive.get("reportSHA256")
        != commitments["developmentControlReportSHA256"]
        or development_archive.get("receiptSHA256")
        != commitments["developmentControlArchiveReceiptSHA256"]
        or development_archive.get("attestationBundleSHA256")
        != commitments["developmentControlReleaseAttestationBundleSHA256"]
        or development_archive.get("attestationOutputSHA256")
        != commitments["developmentControlReleaseAttestationOutputSHA256"]
        or development_archive.get("artifactArchiveSHA256")
        != commitments["developmentControlArtifactArchiveSHA256"]
        or development_archive.get("archiveManifestSHA256")
        != commitments["developmentControlArchiveManifestSHA256"]
    ):
        raise FreezeManifestError(
            "development control differs from freeze-manifest commitments"
        )

    ca_raw = read_regular_bytes(ca_bundle_path, maximum_bytes=MAX_CA_BUNDLE_BYTES)
    ca_sha256 = sha256_bytes(ca_raw)
    if ca_sha256 != commitments["transportCABundleSHA256"]:
        raise FreezeManifestError("transport CA bundle SHA-256 differs")
    ca_verifier(ca_bundle_path, ca_sha256)

    trust_raw = read_regular_bytes(
        trust_manifest_path, maximum_bytes=MAX_TRUST_MANIFEST_BYTES
    )
    trust_sha256 = sha256_bytes(trust_raw)
    if trust_sha256 != commitments["offlineTrustBundleSHA256"]:
        raise FreezeManifestError("offline trust manifest SHA-256 differs")
    trust_value = load_json_strict_bytes(trust_raw, label="offline NIST trust manifest")
    if not isinstance(trust_value, dict) or canonical_json_bytes(trust_value) != trust_raw:
        raise FreezeManifestError("offline trust manifest is not canonical JSON")
    if (
        trust_value.get("schemaVersion") != TRUST_SCHEMA
        or trust_value.get("status") != "FROZEN_OFFLINE_TRUST_BUNDLE"
        or trust_value.get("fixtureOnly") is not False
    ):
        raise FreezeManifestError("offline trust manifest is not normative")
    trust_verifier(trust_manifest_path, trust_sha256)
    return {
        "status": "VERIFIED_FREEZE_INPUT_ARTIFACTS",
        "runtimeManifestSHA256": sha256_bytes(runtime_raw),
        "fullAssetReceiptSHA256": sha256_bytes(asset_raw),
        "transportCABundleSHA256": ca_sha256,
        "offlineTrustBundleSHA256": trust_sha256,
        "githubGateReceiptSHA256": sha256_bytes(gate_raw),
        "developmentControlReportSHA256": development["reportFileSHA256"],
        "developmentControlArtifactSetSHA256": development["artifactSetSHA256"],
        "developmentControlConfigurationSHA256": development[
            "controlConfigurationSHA256"
        ],
        "developmentControlCompletedAt": development["completedAt"],
        "developmentControlExecutionId": development["executionId"],
        "developmentControlArtifactCount": development["artifactCount"],
        "developmentControlArchiveReceiptSHA256": development_archive[
            "receiptSHA256"
        ],
        "developmentControlArchivePublishedAt": development_archive[
            "publishedAt"
        ],
        "developmentControlArchiveAttestedAt": development_archive[
            "attestedAt"
        ],
        "developmentControlReleaseAttestationBundleSHA256": development_archive[
            "attestationBundleSHA256"
        ],
        "developmentControlReleaseAttestationOutputSHA256": development_archive[
            "attestationOutputSHA256"
        ],
        "developmentControlArtifactArchiveSHA256": development_archive[
            "artifactArchiveSHA256"
        ],
        "developmentControlArchiveManifestSHA256": development_archive[
            "archiveManifestSHA256"
        ],
    }


def build_freeze_manifest(
    *,
    runtime_manifest_path: Path,
    asset_receipt_path: Path,
    ca_bundle_path: Path,
    trust_manifest_path: Path,
    lab_repository: str,
    lab_commit: str,
    lab_tree: str,
    codec_repository: str,
    codec_commit: str,
    codec_tree: str,
    github_gate_receipt_path: Path,
    development_control_report_path: Path,
    development_control_artifact_root: Path,
    development_control_archive_receipt_path: Path,
    development_control_archive_asset_root: Path,
    created_at: str,
    ca_verifier: CAVerifier = default_ca_verifier,
    trust_verifier: TrustVerifier = default_trust_verifier,
    development_control_verifier: DevelopmentControlVerifier = (
        verify_development_control_report
    ),
    development_archive_verifier: DevelopmentArchiveVerifier = (
        verify_development_control_archive
    ),
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
) -> dict[str, Any]:
    """Build the stage-one manifest only from independently re-opened artifacts."""

    implementation = {
        "repository": lab_repository,
        "commit": lab_commit,
        "tree": lab_tree,
    }
    _verify_live_implementation_source(implementation)
    runtime_raw = read_regular_bytes(
        runtime_manifest_path, maximum_bytes=MAX_RUNTIME_MANIFEST_BYTES
    )
    asset_raw = read_regular_bytes(asset_receipt_path, maximum_bytes=MAX_RECEIPT_BYTES)
    ca_raw = read_regular_bytes(ca_bundle_path, maximum_bytes=MAX_CA_BUNDLE_BYTES)
    trust_raw = read_regular_bytes(
        trust_manifest_path, maximum_bytes=MAX_TRUST_MANIFEST_BYTES
    )
    verified_gate, gate_raw = _verify_github_gate_input(
        github_gate_receipt_path,
        implementation=implementation,
    )
    author_verification, continuous_integration = _gate_manifest_sections(
        verified_gate,
        implementation_repository=lab_repository,
    )
    codec = {
        "repository": codec_repository,
        "commit": codec_commit,
        "tree": codec_tree,
    }
    development = development_control_verifier(
        development_control_report_path,
        artifact_root=development_control_artifact_root,
        expected_implementation=implementation,
        expected_codec=codec,
        completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
        expected_runtime_manifest_sha256=sha256_bytes(runtime_raw),
        require_artifacts=True,
    )
    development_archive = development_archive_verifier(
        development_control_archive_receipt_path,
        archive_asset_root=development_control_archive_asset_root,
        report_path=development_control_report_path,
        report_summary=development,
        expected_implementation=implementation,
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "status": STATUS,
        "suiteId": SUITE_ID,
        "countsTowardScientificVerdict": False,
        "freezeProcedure": dict(FREEZE_PROCEDURE),
        "implementation": implementation,
        "codec": codec,
        "developmentControl": {
            "status": "VERIFIED_REAL_DATA_E2E_FREEZE_GATE",
            "reportSchemaVersion": DEVELOPMENT_REPORT_SCHEMA,
            "reportFileName": "development-control-report.json",
            "executionId": development["executionId"],
            "artifactCount": development["artifactCount"],
            "completedAt": development["completedAt"],
            "archivePublishedAt": development_archive["publishedAt"],
            "archiveAttestedAt": development_archive["attestedAt"],
            "serverTimestampedArchiveVerified": True,
            "countsTowardScientificVerdict": False,
            "usedForCandidateSelectionOrTuning": False,
            "scientificAttemptStateCreated": False,
            "nistUsed": False,
            "futureCorpusUsed": False,
            "thresholdsApplied": False,
        },
        "artifacts": {
            "runtimeManifestSHA256": sha256_bytes(runtime_raw),
            "fullAssetReceiptSHA256": sha256_bytes(asset_raw),
            "transportCABundleSHA256": sha256_bytes(ca_raw),
            "offlineTrustBundleSHA256": sha256_bytes(trust_raw),
            "githubGateReceiptSHA256": sha256_bytes(gate_raw),
            "developmentControlReportSHA256": development[
                "reportFileSHA256"
            ],
            "developmentControlArtifactSetSHA256": development[
                "artifactSetSHA256"
            ],
            "developmentControlConfigurationSHA256": development[
                "controlConfigurationSHA256"
            ],
            "developmentControlArchiveReceiptSHA256": development_archive[
                "receiptSHA256"
            ],
            "developmentControlReleaseAttestationBundleSHA256": development_archive[
                "attestationBundleSHA256"
            ],
            "developmentControlReleaseAttestationOutputSHA256": development_archive[
                "attestationOutputSHA256"
            ],
            "developmentControlArtifactArchiveSHA256": development_archive[
                "artifactArchiveSHA256"
            ],
            "developmentControlArchiveManifestSHA256": development_archive[
                "archiveManifestSHA256"
            ],
        },
        "authorVerification": author_verification,
        "continuousIntegration": continuous_integration,
        "createdAt": created_at,
    }
    manifest = with_content_digest(payload)
    validate_freeze_manifest(manifest)
    verify_artifact_inputs(
        manifest,
        runtime_manifest_path=runtime_manifest_path,
        asset_receipt_path=asset_receipt_path,
        ca_bundle_path=ca_bundle_path,
        trust_manifest_path=trust_manifest_path,
        github_gate_receipt_path=github_gate_receipt_path,
        development_control_report_path=development_control_report_path,
        development_control_artifact_root=development_control_artifact_root,
        development_control_archive_receipt_path=(
            development_control_archive_receipt_path
        ),
        development_control_archive_asset_root=(
            development_control_archive_asset_root
        ),
        ca_verifier=ca_verifier,
        trust_verifier=trust_verifier,
        development_control_verifier=development_control_verifier,
        development_archive_verifier=development_archive_verifier,
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    return manifest


def verify_design_binding(
    manifest: Mapping[str, Any], manifest_raw: bytes, design_path: Path
) -> dict[str, Any]:
    """Verify stage two: the frozen design binds the exact manifest file SHA."""

    validate_freeze_manifest(manifest)
    if canonical_json_bytes(manifest) + b"\n" != manifest_raw:
        raise FreezeManifestError("freeze manifest bytes are not canonical")
    design_raw = read_regular_bytes(design_path, maximum_bytes=MAX_DESIGN_BYTES)
    design = load_json_strict_bytes(design_raw, label="frozen design")
    if not isinstance(design, dict) or canonical_json_bytes(design) + b"\n" != design_raw:
        raise FreezeManifestError("frozen design is not canonical JSON plus terminal LF")
    try:
        validate_frozen_design_registration(design)
    except ValueError as error:
        raise FreezeManifestError("frozen design fails the normative contract") from error
    if (
        design.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-design-v1"
        or design.get("status") != "PUBLIC_DESIGN_FROZEN"
        or design.get("suiteId") != SUITE_ID
        or design.get("readyToFreeze") is not True
        or design.get("countsTowardScientificVerdict") is not False
        or design.get("freezeBlockers") != []
    ):
        raise FreezeManifestError("frozen design lifecycle boundary differs")
    implementation = manifest["implementation"]
    codec = manifest["codec"]
    artifacts = manifest["artifacts"]
    lab_source = design.get("labSource")
    codec_source = design.get("codecSource")
    runtime = design.get("runtime")
    beacon = design.get("beacon")
    if not all(isinstance(item, dict) for item in (lab_source, codec_source, runtime, beacon)):
        raise FreezeManifestError("frozen design source/artifact binding is incomplete")
    freeze_file_sha256 = sha256_bytes(manifest_raw)
    if (
        lab_source.get("status") != "FROZEN_BOUND"
        or lab_source.get("repository") != implementation["repository"]
        or lab_source.get("commit") != implementation["commit"]
        or lab_source.get("tree") != implementation["tree"]
        or lab_source.get("freezeManifestSHA256") != freeze_file_sha256
    ):
        raise FreezeManifestError("frozen design lab/freeze-manifest binding differs")
    if (
        codec_source.get("repository") != codec["repository"]
        or codec_source.get("commit") != codec["commit"]
        or codec_source.get("tree") != codec["tree"]
    ):
        raise FreezeManifestError("frozen design codec binding differs")
    if (
        runtime.get("status") != "FROZEN_BOUND"
        or runtime.get("runtimeManifestSHA256")
        != artifacts["runtimeManifestSHA256"]
    ):
        raise FreezeManifestError("frozen design runtime binding differs")
    controls = design.get("developmentControls")
    development_gate = (
        controls.get("realDataE2EFreezeGate")
        if isinstance(controls, dict)
        else None
    )
    if (
        not isinstance(development_gate, dict)
        or development_gate.get("status")
        != "ARCHIVED_VERIFIED_BEFORE_FREEZE"
        or development_gate.get("executionId")
        != manifest["developmentControl"]["executionId"]
        or development_gate.get("archiveReceiptSHA256")
        != artifacts["developmentControlArchiveReceiptSHA256"]
        or development_gate.get("archivePublishedAt")
        != manifest["developmentControl"]["archivePublishedAt"]
        or development_gate.get("archiveAttestedAt")
        != manifest["developmentControl"]["archiveAttestedAt"]
        or development_gate.get("releaseAttestationBundleSHA256")
        != artifacts["developmentControlReleaseAttestationBundleSHA256"]
        or development_gate.get("releaseAttestationOutputSHA256")
        != artifacts["developmentControlReleaseAttestationOutputSHA256"]
        or development_gate.get("reportSHA256")
        != artifacts["developmentControlReportSHA256"]
        or development_gate.get("artifactSetSHA256")
        != artifacts["developmentControlArtifactSetSHA256"]
        or development_gate.get("controlConfigurationSHA256")
        != artifacts["developmentControlConfigurationSHA256"]
        or development_gate.get("completedAt")
        != manifest["developmentControl"]["completedAt"]
    ):
        raise FreezeManifestError("frozen design development-control binding differs")
    if (
        beacon.get("transportCABundleSHA256")
        != artifacts["transportCABundleSHA256"]
        or beacon.get("offlineTrustBundleSHA256")
        != artifacts["offlineTrustBundleSHA256"]
    ):
        raise FreezeManifestError("frozen design CA/trust binding differs")
    registered_ci = design.get("continuousIntegration")
    observed_ci = manifest.get("continuousIntegration")
    if (
        not isinstance(registered_ci, dict)
        or not isinstance(observed_ci, dict)
        or observed_ci.get("workflowName") != registered_ci.get("workflowName")
        or observed_ci.get("workflowPath") != registered_ci.get("workflowPath")
        or observed_ci.get("allJobsCompletedSuccess") is not True
        or observed_ci.get("zeroSkippedOrCancelledJobs") is not True
    ):
        raise FreezeManifestError("frozen design and CI gate binding differ")
    release = design.get("designRelease")
    if not isinstance(release, dict):
        raise FreezeManifestError("frozen design release plan is missing")
    deadline = _utc_second(
        release.get("publishNoLaterThan"), label="design publication deadline"
    )
    created_at = _utc_second(manifest["createdAt"], label="freeze manifest createdAt")
    if created_at >= deadline:
        raise FreezeManifestError("freeze manifest was created after design deadline")
    return {
        "status": "VERIFIED_TWO_STAGE_DESIGN_BINDING",
        "freezeManifestSHA256": freeze_file_sha256,
        "implementationCommit": implementation["commit"],
        "implementationTree": implementation["tree"],
    }


def _add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--asset-receipt", type=Path, required=True)
    parser.add_argument("--transport-ca-bundle", type=Path, required=True)
    parser.add_argument("--offline-trust-manifest", type=Path, required=True)
    parser.add_argument("--github-gate-receipt", type=Path, required=True)
    parser.add_argument("--development-control-report", type=Path, required=True)
    parser.add_argument(
        "--development-control-artifact-root", type=Path, required=True
    )
    parser.add_argument(
        "--development-control-archive-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--development-control-archive-asset-root", type=Path, required=True
    )
    parser.add_argument("--cosign", type=Path, required=True)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="generate a new canonical manifest")
    _add_artifact_arguments(create)
    create.add_argument("--lab-repository", required=True)
    create.add_argument("--lab-commit", required=True)
    create.add_argument("--lab-tree", required=True)
    create.add_argument("--codec-repository", required=True)
    create.add_argument("--codec-commit", required=True)
    create.add_argument("--codec-tree", required=True)
    create.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="independently verify manifest inputs")
    verify.add_argument("--manifest", type=Path, required=True)
    _add_artifact_arguments(verify)
    verify.add_argument("--frozen-design", type=Path)

    development = subparsers.add_parser(
        "verify-development-control",
        help="independently rehash one completed real-data development control",
    )
    development.add_argument("--report", type=Path, required=True)
    development.add_argument("--artifact-root", type=Path, required=True)
    development.add_argument("--lab-repository", required=True)
    development.add_argument("--lab-commit", required=True)
    development.add_argument("--lab-tree", required=True)
    development.add_argument("--codec-repository", required=True)
    development.add_argument("--codec-commit", required=True)
    development.add_argument("--codec-tree", required=True)
    archive = subparsers.add_parser(
        "verify-development-archive",
        help="verify the signed GitHub-attested development-control release",
    )
    archive.add_argument("--receipt", type=Path, required=True)
    archive.add_argument("--archive-asset-root", type=Path, required=True)
    archive.add_argument("--report", type=Path, required=True)
    archive.add_argument("--lab-repository", required=True)
    archive.add_argument("--lab-commit", required=True)
    archive.add_argument("--lab-tree", required=True)
    archive.add_argument("--cosign", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        cryptographic_attestation_verifier = (
            PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            if arguments.command in {"create", "verify", "verify-development-archive"}
            else None
        )
        if arguments.command == "create":
            manifest = build_freeze_manifest(
                runtime_manifest_path=arguments.runtime_manifest,
                asset_receipt_path=arguments.asset_receipt,
                ca_bundle_path=arguments.transport_ca_bundle,
                trust_manifest_path=arguments.offline_trust_manifest,
                lab_repository=arguments.lab_repository,
                lab_commit=arguments.lab_commit,
                lab_tree=arguments.lab_tree,
                codec_repository=arguments.codec_repository,
                codec_commit=arguments.codec_commit,
                codec_tree=arguments.codec_tree,
                github_gate_receipt_path=arguments.github_gate_receipt,
                development_control_report_path=arguments.development_control_report,
                development_control_artifact_root=(
                    arguments.development_control_artifact_root
                ),
                development_control_archive_receipt_path=(
                    arguments.development_control_archive_receipt
                ),
                development_control_archive_asset_root=(
                    arguments.development_control_archive_asset_root
                ),
                created_at=datetime.now(timezone.utc).replace(
                    microsecond=0
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                cryptographic_attestation_verifier=(
                    cryptographic_attestation_verifier
                ),
            )
            output_bytes = canonical_freeze_manifest_bytes(manifest)
            write_new_bytes(arguments.output, output_bytes)
            report = {
                "status": manifest["status"],
                "output": str(arguments.output),
                "fileBytes": len(output_bytes),
                "freezeManifestSHA256": sha256_bytes(output_bytes),
                "contentSHA256": manifest["contentSHA256"],
                "nextStage": "set frozen design labSource.freezeManifestSHA256 to freezeManifestSHA256",
            }
        elif arguments.command == "verify":
            manifest, manifest_raw = load_freeze_manifest(arguments.manifest)
            report = verify_artifact_inputs(
                manifest,
                runtime_manifest_path=arguments.runtime_manifest,
                asset_receipt_path=arguments.asset_receipt,
                ca_bundle_path=arguments.transport_ca_bundle,
                trust_manifest_path=arguments.offline_trust_manifest,
                github_gate_receipt_path=arguments.github_gate_receipt,
                development_control_report_path=arguments.development_control_report,
                development_control_artifact_root=(
                    arguments.development_control_artifact_root
                ),
                development_control_archive_receipt_path=(
                    arguments.development_control_archive_receipt
                ),
                development_control_archive_asset_root=(
                    arguments.development_control_archive_asset_root
                ),
                cryptographic_attestation_verifier=(
                    cryptographic_attestation_verifier
                ),
            )
            report["freezeManifestSHA256"] = sha256_bytes(manifest_raw)
            report["contentSHA256"] = manifest["contentSHA256"]
            if arguments.frozen_design is not None:
                report["designBinding"] = verify_design_binding(
                    manifest, manifest_raw, arguments.frozen_design
                )
        elif arguments.command == "verify-development-control":
            report = verify_development_control_report(
                arguments.report,
                artifact_root=arguments.artifact_root,
                expected_implementation={
                    "repository": arguments.lab_repository,
                    "commit": arguments.lab_commit,
                    "tree": arguments.lab_tree,
                },
                expected_codec={
                    "repository": arguments.codec_repository,
                    "commit": arguments.codec_commit,
                    "tree": arguments.codec_tree,
                },
                completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
                require_artifacts=True,
            )
            report["status"] = "VERIFIED_REAL_DATA_E2E_FREEZE_GATE"
        else:
            summary = verify_development_control_report(
                arguments.report,
                completed_no_later_than=DESIGN_PUBLISH_DEADLINE,
                require_artifacts=False,
            )
            report = verify_development_control_archive(
                arguments.receipt,
                archive_asset_root=arguments.archive_asset_root,
                report_path=arguments.report,
                report_summary=summary,
                expected_implementation={
                    "repository": arguments.lab_repository,
                    "commit": arguments.lab_commit,
                    "tree": arguments.lab_tree,
                },
                cryptographic_attestation_verifier=(
                    cryptographic_attestation_verifier
                ),
            )
    except (OSError, ValueError, KeyError) as error:
        print(f"FREEZE MANIFEST FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
