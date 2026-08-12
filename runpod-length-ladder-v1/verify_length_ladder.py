#!/usr/bin/env python3
"""Independently verify and replay the six-point RunPod length ladder."""

from __future__ import annotations

import argparse
import gc
import importlib.util
import json
import math
import os
import re
import stat
import sys
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


os.umask(0o077)
for _name, _value in {
    "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
    "DO_NOT_TRACK": "1",
    "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "TOKENIZERS_PARALLELISM": "false",
    "PYTHONDONTWRITEBYTECODE": "1",
}.items():
    os.environ[_name] = _value
sys.dont_write_bytecode = True

from common import (  # noqa: E402
    ADAPTER_SUITE_ROOT,
    ATTEMPT_SCHEMA_VERSION_LENGTH,
    DIRECT_TIMEOUT_BY_LEVEL,
    EXECUTION_LEVEL_IDS,
    HORIZON,
    INPUT_SCHEMA_VERSION_LENGTH,
    LADDER_PATH,
    LENGTH_ADAPTER_ID,
    LENGTH_CLASSIFICATION,
    LENGTH_CONTENT_CLASS,
    LENGTH_MODEL_ID,
    LENGTH_PROFILE_ID,
    LENGTH_PROTOCOL_PATH,
    LENGTH_WORKLOAD_ID,
    LEVEL_IDS,
    PREFILL_LEVELS,
    PREFLIGHT_SCHEMA_VERSION_LENGTH,
    PROFILES_PATH,
    REPLAY_SCHEMA_VERSION_LENGTH,
    RESULT_SCHEMA_VERSION_LENGTH,
    RUN_SCHEMA_VERSION_LENGTH,
    SECONDARY_SCHEMA_VERSION_LENGTH,
    SECONDARY_TIMEOUT_SECONDS,
    VERIFY_SCHEMA_VERSION_LENGTH,
    WORKLOADS_PATH,
    canonical_json_bytes,
    load_ladder,
    profile_for_length,
    profile_object_sha256,
    require,
    require_digest,
    require_exact_keys,
    require_int,
    require_regular,
    selected_profile,
    selected_workload,
    sha256_bytes,
    sha256_file,
    strict_json_file,
    validate_codec_root,
    verify_length_assets,
    workload_text,
    write_canonical_json,
)


def _load_adapter_verifier() -> Any:
    if str(ADAPTER_SUITE_ROOT) not in sys.path:
        sys.path.insert(1, str(ADAPTER_SUITE_ROOT))
    path = ADAPTER_SUITE_ROOT / "verify_adapter_sweep.py"
    spec = importlib.util.spec_from_file_location(
        "_corelm_runpod_adapter_verifier_v1", path
    )
    require(spec is not None and spec.loader is not None, "cannot load adapter verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASEV = _load_adapter_verifier()
np: Any = None
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_RAW_LAYER_BYTES = 16 * 1024 * 1024
MAX_CONTAINER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_CONTAINER_BYTES = 16 * 1024 * 1024 * 1024
DECIMAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

RUN_MANIFEST_KEYS = {
    "analysisOrder",
    "assetReceiptSHA256",
    "cells",
    "classification",
    "codecSource",
    "completeCells",
    "completeSecondaryControls",
    "countsTowardScientificVerdict",
    "directPrimaryAnalysis",
    "directPayloadOnlyDiagnostic",
    "executionOrder",
    "expectedCells",
    "expectedSecondaryControls",
    "ladderSHA256",
    "lengthProtocolSHA256",
    "masterSliceSecondaryAnalysis",
    "masterSlicePayloadOnlyDiagnostic",
    "preflightSHA256",
    "runId",
    "schemaVersion",
    "secondaryControls",
    "selectedProfileObjectSHA256",
    "source",
    "sourceProfilesSHA256",
    "sourceWorkloadsSHA256",
    "status",
    "supportDecision",
}

DIRECT_RESULT_KEYS = {
    "assetReceiptSHA256",
    "cacheObservation",
    "classification",
    "codecSource",
    "countsTowardScientificVerdict",
    "directBehavior",
    "directCanonicalCacheBF16SHA256",
    "directEncoding",
    "directRawEvidence",
    "directStructuralReplay",
    "inputManifestSHA256",
    "inputTokenMasterSHA256",
    "ladderSHA256",
    "lengthLevelId",
    "lengthProtocolSHA256",
    "model",
    "prefillTokens",
    "runtime",
    "schemaVersion",
    "selectedProfileObjectSHA256",
    "selectedTokenIds",
    "source",
    "sourceProfilesSHA256",
    "sourceWorkloadsSHA256",
    "status",
    "workload",
}

SECONDARY_RESULT_KEYS = {
    "anchorDirectCanonicalCacheBF16SHA256",
    "anchorDirectResultSHA256",
    "anchorLengthLevelId",
    "assetReceiptSHA256",
    "classification",
    "codecSource",
    "countsTowardScientificVerdict",
    "directResultSHA256",
    "directVersusMasterSlice",
    "inputManifestSHA256",
    "inputTokenMasterSHA256",
    "ladderSHA256",
    "lengthLevelId",
    "lengthProtocolSHA256",
    "masterSliceCanonicalCacheBF16SHA256",
    "masterSliceEncoding",
    "prefillTokens",
    "runtime",
    "schemaVersion",
    "selectedProfileObjectSHA256",
    "sliceBindings",
    "source",
    "sourceProfilesSHA256",
    "sourceWorkloadsSHA256",
    "status",
}

STRUCTURAL_ROW_KEYS = {
    "controlledTop1AgreementCount",
    "directCanonicalCacheBF16SHA256",
    "directContainerBytes",
    "directContainerBytesPerPrefillToken",
    "directContainerOverheadBytes",
    "directDenseBF16Bytes",
    "directPayloadBytes",
    "directResultSHA256",
    "directSpaceSavingFraction",
    "directVersusMasterSliceBitwiseIdentical",
    "directVersusMasterSliceDifferingBF16Words",
    "freeRunExact",
    "freeRunLongestCommonPrefixTokens",
    "freeRunSamePositionCount",
    "lengthLevelId",
    "meanBaselineSelectedTokenSurprisalDeltaNat",
    "meanKLDivergenceNat",
    "predictionTokens",
    "prefillTokens",
    "secondaryContainerBytes",
    "secondaryContainerOverheadBytes",
    "secondaryPayloadBytes",
}

STRUCTURAL_PUBLIC_KEYS = {
    "allSixModelReplaysRequiredForPublication",
    "assetReceiptSHA256",
    "classification",
    "countsTowardScientificVerdict",
    "directCells",
    "directContainers",
    "directPayloadOnlyDiagnostic",
    "directPrimaryAnalysis",
    "inputManifestSHA256",
    "inputTokenMasterSHA256",
    "masterSlicePayloadOnlyDiagnostic",
    "masterSliceSecondaryAnalysis",
    "modelReplayPerformed",
    "preflightSHA256",
    "rows",
    "runId",
    "runSHA256",
    "schemaVersion",
    "secondaryContainers",
    "secondaryControls",
    "source",
    "status",
    "supportDecision",
}


def _timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value), f"{label} is not canonical UTC")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is invalid") from error


def _safe_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    require(
        absolute.is_dir() and not absolute.is_symlink(), f"{label} is not a directory"
    )
    require(absolute == absolute.resolve(), f"{label} traverses a symlink")
    status = absolute.stat()
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is not private")
    return absolute


def _bounded_json(path: Path, label: str) -> dict[str, Any]:
    status = require_regular(path, label)
    require(0 < status.st_size <= MAX_JSON_BYTES, f"{label} exceeds its bound")
    value = strict_json_file(path, label)
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def _verify_sidecar(path: Path) -> str:
    digest = sha256_file(path)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    status = require_regular(sidecar, f"{path.name} digest sidecar")
    require(status.st_size < 1024, "digest sidecar exceeds its bound")
    require(
        sidecar.read_bytes() == f"{digest}  {path.name}\n".encode("ascii"),
        f"{path.name} digest sidecar differs",
    )
    return digest


def _source_bindings(source: dict[str, Any]) -> dict[str, Any]:
    profile = selected_profile()
    return {
        "source": source,
        "ladderSHA256": sha256_file(LADDER_PATH),
        "lengthProtocolSHA256": sha256_file(LENGTH_PROTOCOL_PATH),
        "sourceProfilesSHA256": sha256_file(PROFILES_PATH),
        "sourceWorkloadsSHA256": sha256_file(WORKLOADS_PATH),
        "selectedProfileObjectSHA256": profile_object_sha256(profile),
    }


def _require_source_bindings(
    value: dict[str, Any], source: dict[str, Any], label: str
) -> None:
    for name, expected in _source_bindings(source).items():
        require(value.get(name) == expected, f"{label} {name} differs")


def _safe_relative(root: Path, relative: Any, expected: str, label: str) -> Path:
    require(relative == expected, f"{label} path differs")
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and ".." not in pure.parts, f"{label} path is unsafe")
    path = root.joinpath(*pure.parts)
    require_regular(path, label)
    require(path.resolve(strict=True).is_relative_to(root), f"{label} escaped its root")
    return path


def _tokenizer_ids(tokenizer: Any, text: str) -> list[int]:
    previous = tokenizer.model_max_length
    tokenizer.model_max_length = sys.maxsize
    try:
        values = tokenizer(
            text,
            add_special_tokens=False,
            truncation=False,
            return_attention_mask=False,
            return_token_type_ids=False,
        )["input_ids"]
    finally:
        tokenizer.model_max_length = previous
    require(
        isinstance(values, list)
        and all(type(value) is int and 0 <= value <= 0xFFFFFFFF for value in values),
        "tokenizer produced invalid token IDs",
    )
    return values


def _token_bytes(values: list[int]) -> bytes:
    return np.asarray(values, dtype="<u4").tobytes()


def _cache_digest(raw_layers: list[bytes]) -> str:
    import hashlib

    digest = hashlib.sha256()
    for index, raw in enumerate(raw_layers):
        digest.update(index.to_bytes(4, "little"))
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def _bf16_matrix(raw: bytes, rows: int, columns: int) -> Any:
    require(len(raw) == rows * columns * 2, "BF16 matrix byte count differs")
    words = np.frombuffer(raw, dtype="<u2")
    floats = (words.astype("<u4") << 16).view("<f4")
    matrix = np.ascontiguousarray(floats.reshape(rows, columns), dtype=np.float32)
    require(np.isfinite(matrix).all(), "BF16 matrix contains non-finite values")
    return matrix


def _verify_input_and_preflight(
    *,
    preflight_path: Path,
    cache_root: Path,
    codec: dict[str, Any],
    asset_digest: str,
    source: dict[str, Any],
) -> tuple[dict[str, Any], str, dict[str, Any], bytes, dict[str, dict[str, Any]]]:
    preflight = _bounded_json(preflight_path, "length-ladder preflight")
    preflight_digest = _verify_sidecar(preflight_path)
    require_exact_keys(
        preflight,
        {
            "adapterId",
            "assetReceiptSHA256",
            "cells",
            "classification",
            "codecSource",
            "countsTowardScientificVerdict",
            "executionOrder",
            "horizon",
            "inputManifest",
            "ladderSHA256",
            "lengthOrder",
            "lengthProtocolSHA256",
            "modelId",
            "prefillOrder",
            "schemaVersion",
            "selectedProfileObjectSHA256",
            "source",
            "sourceProfilesSHA256",
            "sourceWorkloadsSHA256",
            "status",
            "workloadId",
        },
        "length-ladder preflight",
    )
    require(
        preflight["schemaVersion"] == PREFLIGHT_SCHEMA_VERSION_LENGTH
        and preflight["status"] == "TOKENIZER_ONLY_NO_MODEL_INFERENCE"
        and preflight["classification"] == LENGTH_CLASSIFICATION
        and preflight["countsTowardScientificVerdict"] is False,
        "preflight claim boundary differs",
    )
    require(
        preflight["codecSource"] == codec
        and preflight["assetReceiptSHA256"] == asset_digest,
        "preflight codec or asset binding differs",
    )
    _require_source_bindings(preflight, source, "preflight")
    require(
        preflight["modelId"] == LENGTH_MODEL_ID
        and preflight["adapterId"] == LENGTH_ADAPTER_ID
        and preflight["workloadId"] == LENGTH_WORKLOAD_ID
        and preflight["lengthOrder"] == list(LEVEL_IDS)
        and preflight["prefillOrder"] == list(PREFILL_LEVELS)
        and preflight["executionOrder"] == list(EXECUTION_LEVEL_IDS)
        and preflight["horizon"] == HORIZON,
        "preflight registered geometry differs",
    )

    workload = selected_workload()
    text, inventory = workload_text(workload)
    framed = text.encode("utf-8")
    from transformers import AutoTokenizer

    snapshot = cache_root / LENGTH_MODEL_ID
    tokenizer = AutoTokenizer.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False
    )
    all_ids = _tokenizer_ids(tokenizer, text)
    require(len(all_ids) >= PREFILL_LEVELS[-1] + 1, "workload is too short")
    cells = preflight["cells"]
    require(isinstance(cells, list) and len(cells) == 6, "preflight needs six cells")
    indexed: dict[str, dict[str, Any]] = {}
    previous: bytes | None = None
    for position, (cell, level_id, prefill) in enumerate(
        zip(cells, LEVEL_IDS, PREFILL_LEVELS)
    ):
        require_exact_keys(
            cell,
            {
                "availableTokens",
                "category",
                "framedUTF8Bytes",
                "lengthLevelId",
                "prefillTokens",
                "promptUTF8SHA256",
                "selectedTokens",
                "sourceFiles",
                "tokenIdsU32LESHA256",
                "workloadId",
            },
            f"preflight cell {position}",
        )
        selected = _token_bytes(all_ids[: prefill + 1])
        require(
            cell["lengthLevelId"] == level_id
            and cell["prefillTokens"] == prefill
            and cell["workloadId"] == LENGTH_WORKLOAD_ID
            and cell["category"] == LENGTH_CONTENT_CLASS
            and cell["promptUTF8SHA256"] == sha256_bytes(framed)
            and cell["framedUTF8Bytes"] == len(framed)
            and cell["availableTokens"] == len(all_ids)
            and cell["selectedTokens"] == prefill + 1
            and cell["sourceFiles"] == inventory
            and cell["tokenIdsU32LESHA256"] == sha256_bytes(selected),
            f"preflight cell {position} input binding differs",
        )
        if previous is not None:
            require(selected.startswith(previous), "preflight token vectors are not nested")
        previous = selected
        indexed[level_id] = cell

    binding = preflight["inputManifest"]
    require_exact_keys(
        binding,
        {"path", "sha256", "tokenIdsPath", "tokenIdsSHA256"},
        "preflight input manifest binding",
    )
    manifest_path = _safe_relative(
        preflight_path.parent, binding["path"], "input.json", "input manifest"
    )
    manifest = _bounded_json(manifest_path, "input manifest")
    require_exact_keys(
        manifest,
        {
            "adapterId",
            "assetReceiptSHA256",
            "classification",
            "codecSource",
            "countsTowardScientificVerdict",
            "ladderSHA256",
            "lengthProtocolSHA256",
            "modelId",
            "schemaVersion",
            "selectedProfileObjectSHA256",
            "source",
            "sourceProfilesSHA256",
            "sourceWorkloadsSHA256",
            "status",
            "tokenIds",
            "workload",
            "workloadId",
        },
        "input manifest",
    )
    manifest_digest = _verify_sidecar(manifest_path)
    require(
        manifest_digest == binding["sha256"]
        and manifest.get("schemaVersion") == INPUT_SCHEMA_VERSION_LENGTH
        and manifest.get("status")
        == "INPUT_TOKEN_MASTER_MATERIALIZED_NO_MODEL_INFERENCE"
        and manifest.get("classification") == LENGTH_CLASSIFICATION
        and manifest.get("countsTowardScientificVerdict") is False,
        "input manifest claim boundary differs",
    )
    require(
        manifest.get("codecSource") == codec
        and manifest.get("assetReceiptSHA256") == asset_digest,
        "input manifest codec or asset binding differs",
    )
    _require_source_bindings(manifest, source, "input manifest")
    require(
        manifest.get("modelId") == LENGTH_MODEL_ID
        and manifest.get("adapterId") == LENGTH_ADAPTER_ID
        and manifest.get("workloadId") == LENGTH_WORKLOAD_ID,
        "input manifest identity differs",
    )
    token_binding = manifest.get("tokenIds")
    require_exact_keys(
        token_binding,
        {"bytes", "count", "dtype", "path", "sha256"},
        "input token file binding",
    )
    token_path = _safe_relative(
        preflight_path.parent,
        token_binding["path"],
        "input-token-ids.u32le",
        "input token file",
    )
    token_raw = token_path.read_bytes()
    require(
        token_binding["dtype"] == "uint32-little-endian"
        and token_binding["count"] == 8193
        and token_binding["bytes"] == len(token_raw) == 8193 * 4
        and token_binding["sha256"] == sha256_bytes(token_raw)
        and token_binding["sha256"] == binding["tokenIdsSHA256"]
        and token_raw == _token_bytes(all_ids[:8193])
        and _verify_sidecar(token_path) == token_binding["sha256"],
        "input token file differs",
    )
    expected_manifest_workload = dict(indexed[LEVEL_IDS[-1]])
    require(
        manifest.get("workload") == expected_manifest_workload,
        "input manifest workload differs",
    )
    return preflight, preflight_digest, manifest, token_raw, indexed


def _verify_direct_raw(
    *,
    cell_root: Path,
    result: dict[str, Any],
    profile: dict[str, Any],
    input_token_raw: bytes,
) -> tuple[list[Any], list[bytes], set[str], set[str]]:
    prefill = int(profile["maxPrefillTokens"])
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    token = result["selectedTokenIds"]
    require_exact_keys(
        token, {"bytes", "count", "dtype", "path", "sha256"}, "selected token IDs"
    )
    token_path = _safe_relative(
        cell_root,
        token["path"],
        "selected-token-ids.u32le",
        "selected token IDs",
    )
    token_raw = token_path.read_bytes()
    require(
        token["dtype"] == "uint32-little-endian"
        and token["count"] == prefill + 1
        and token["bytes"] == len(token_raw) == (prefill + 1) * 4
        and token["sha256"] == sha256_bytes(token_raw)
        and token_raw == input_token_raw[: len(token_raw)],
        "selected token evidence differs",
    )
    raw_evidence = result["directRawEvidence"]
    require_exact_keys(
        raw_evidence,
        {"canonicalCacheBF16SHA256", "layers"},
        "direct raw evidence",
    )
    entries = raw_evidence["layers"]
    require(
        isinstance(entries, list)
        and len(entries) == int(profile["geometry"]["layers"]),
        "direct raw layer count differs",
    )
    matrices: list[Any] = []
    raws: list[bytes] = []
    files = {"selected-token-ids.u32le"}
    directories = {"direct-raw"}
    for index, entry in enumerate(entries):
        require_exact_keys(
            entry,
            {"bytes", "columns", "layerIndex", "path", "rows", "sha256"},
            f"direct raw layer {index}",
        )
        expected_path = f"direct-raw/layer-{index:03d}.bf16le"
        require(
            entry["layerIndex"] == index
            and entry["rows"] == prefill
            and entry["columns"] == columns
            and entry["bytes"] == prefill * columns * 2,
            f"direct raw layer {index} geometry differs",
        )
        path = _safe_relative(cell_root, entry["path"], expected_path, f"raw layer {index}")
        status = path.stat()
        require(0 < status.st_size <= MAX_RAW_LAYER_BYTES, "raw layer exceeds bound")
        raw = path.read_bytes()
        require(
            len(raw) == entry["bytes"]
            and sha256_bytes(raw) == entry["sha256"],
            f"direct raw layer {index} bytes differ",
        )
        raws.append(raw)
        matrices.append(_bf16_matrix(raw, prefill, columns))
        files.add(expected_path)
    digest = _cache_digest(raws)
    require(
        digest
        == raw_evidence["canonicalCacheBF16SHA256"]
        == result["directCanonicalCacheBF16SHA256"],
        "direct raw cache digest differs",
    )
    return matrices, raws, files, directories


def _read_direct_raw_fast(
    *, result_path: Path, result: dict[str, Any], profile: dict[str, Any]
) -> tuple[list[Any], list[bytes], list[bytes], bytes, str]:
    """Bound one replay cell's retained raw bytes without rechecking all cells."""

    cell_root = result_path.parent
    prefill = int(profile["maxPrefillTokens"])
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    token = result.get("selectedTokenIds")
    require_exact_keys(token, {"bytes", "count", "dtype", "path", "sha256"}, "replay token binding")
    expected_token_bytes = (prefill + 1) * 4
    require(
        token["dtype"] == "uint32-little-endian"
        and token["count"] == prefill + 1
        and token["bytes"] == expected_token_bytes,
        "replay token manifest differs",
    )
    require_digest(token["sha256"], "replay token digest")
    token_path = _safe_relative(cell_root, token["path"], "selected-token-ids.u32le", "replay token file")
    require(token_path.stat().st_size == expected_token_bytes, "replay token file size differs")
    token_raw = token_path.read_bytes()
    require(
        token["bytes"] == len(token_raw) == expected_token_bytes
        and token["sha256"] == sha256_bytes(token_raw),
        "replay token file differs",
    )
    evidence = result.get("directRawEvidence")
    require_exact_keys(evidence, {"canonicalCacheBF16SHA256", "layers"}, "replay raw evidence")
    entries = evidence["layers"]
    require(isinstance(entries, list) and len(entries) == int(profile["geometry"]["layers"]), "replay raw layer count differs")
    matrices: list[Any] = []
    raws: list[bytes] = []
    for index, entry in enumerate(entries):
        require_exact_keys(entry, {"bytes", "columns", "layerIndex", "path", "rows", "sha256"}, f"replay raw layer {index}")
        expected_path = f"direct-raw/layer-{index:03d}.bf16le"
        require(
            entry["layerIndex"] == index
            and entry["rows"] == prefill
            and entry["columns"] == columns
            and entry["bytes"] == prefill * columns * 2,
            "replay raw geometry differs",
        )
        path = _safe_relative(cell_root, entry["path"], expected_path, f"replay raw layer {index}")
        status = path.stat()
        require(status.st_size == entry["bytes"] <= MAX_RAW_LAYER_BYTES, "replay raw size differs")
        raw = path.read_bytes()
        require(sha256_bytes(raw) == entry["sha256"], "replay raw digest differs")
        raws.append(raw)
        matrices.append(_bf16_matrix(raw, prefill, columns))
    require(
        _cache_digest(raws)
        == evidence["canonicalCacheBF16SHA256"]
        == result["directCanonicalCacheBF16SHA256"],
        "replay retained cache digest differs",
    )
    return matrices, raws, raws, token_raw, sha256_file(result_path)


def _verify_encoding(
    *,
    root: Path,
    encoding: dict[str, Any],
    profile: dict[str, Any],
    matrices: list[Any],
    backend: Any,
    prefix: str,
) -> tuple[dict[str, Any], set[str], set[str]]:
    require_exact_keys(
        encoding,
        {
            "configuration",
            "configurationSHA256",
            "containerBytes",
            "containers",
            "denseBF16Bytes",
            "encodingNanoseconds",
            "payloadBytes",
            "compressionRatio",
        },
        f"{prefix} encoding",
    )
    from common import configuration_for_profile, configuration_sha256

    require(
        encoding["configuration"] == configuration_for_profile(profile)
        and encoding["configurationSHA256"] == configuration_sha256(profile),
        f"{prefix} codec configuration differs",
    )
    require_int(encoding["encodingNanoseconds"], f"{prefix} encoding time", 0)
    prefill = int(profile["maxPrefillTokens"])
    columns = matrices[0].shape[1]
    layers = int(profile["geometry"]["layers"])
    dense_expected = prefill * columns * 2 * layers
    require(encoding["denseBF16Bytes"] == dense_expected, f"{prefix} dense bytes differ")
    manifests = encoding["containers"]
    require(isinstance(manifests, list) and len(manifests) == layers, f"{prefix} layer count differs")
    schedule = encoding["configuration"]["bitsByLayer"]
    total_container = 0
    total_payload = 0
    files: set[str] = set()
    directories = {"containers"}
    for index, (entry, input_matrix) in enumerate(zip(manifests, matrices)):
        require_exact_keys(
            entry,
            {
                "bits",
                "columns",
                "containerBytes",
                "containerSHA256",
                "denseBF16Bytes",
                "layerIndex",
                "path",
                "payloadBytes",
                "payloadSHA256",
                "rows",
            },
            f"{prefix} container {index}",
        )
        expected_path = f"containers/layer-{index:03d}.vtl5"
        require(
            entry["layerIndex"] == index
            and entry["bits"] == schedule[index]
            and entry["rows"] == prefill
            and entry["columns"] == columns
            and entry["denseBF16Bytes"] == prefill * columns * 2,
            f"{prefix} container {index} geometry differs",
        )
        path = _safe_relative(root, entry["path"], expected_path, f"{prefix} container {index}")
        status = path.stat()
        require(
            0 < status.st_size <= MAX_CONTAINER_BYTES,
            f"{prefix} container {index} exceeds its bound",
        )
        raw = path.read_bytes()
        require(
            len(raw) == entry["containerBytes"]
            and sha256_bytes(raw) == entry["containerSHA256"],
            f"{prefix} container {index} bytes differ",
        )
        metadata, payload = BASEV._parse_container_header(raw, f"{prefix} container {index}")
        require(
            len(payload) == entry["payloadBytes"]
            and sha256_bytes(payload) == entry["payloadSHA256"],
            f"{prefix} container {index} payload differs",
        )
        require(
            metadata.get("format") == "voidtoken-rotated-entropy-v5"
            and metadata.get("shape") == [prefill, columns]
            and metadata.get("layerIndex") == index
            and metadata.get("bits") == schedule[index]
            and metadata.get("groupSize") == 128
            and metadata.get("transformBlockSize") == 128
            and metadata.get("scaleCompression") == "zlib-9"
            and metadata.get("codeCompression") == "zlib-9"
            and metadata.get("signMode") == "none"
            and metadata.get("payloadBytes") == len(payload)
            and metadata.get("payloadSha256") == sha256_bytes(payload),
            f"{prefix} container {index} metadata differs",
        )
        for digest_name in ("inputSha256", "payloadSha256", "reconstructionSha256"):
            require_digest(
                metadata.get(digest_name),
                f"{prefix} container {index} {digest_name}",
            )
        parsed = backend.from_bytes(raw)
        require(parsed.to_bytes() == raw, f"{prefix} parser changed bytes")
        require(
            parsed.reconstructed.shape == input_matrix.shape
            and parsed.reconstructed.dtype == np.float32
            and np.isfinite(parsed.reconstructed).all(),
            f"{prefix} reconstruction geometry differs",
        )
        # The retained raw canonical BF16 is sufficient to independently run
        # the exact encoder again and require byte-for-byte determinism.
        fresh = backend.encode(
            input_matrix,
            bits=schedule[index],
            group_size=128,
            transform_block_size=128,
            layer_index=index,
            scale_compression="zlib-9",
            code_compression="zlib-9",
            sign_mode="none",
        ).to_bytes()
        require(fresh == raw, f"{prefix} fresh re-encoding differs at layer {index}")
        total_container += len(raw)
        total_payload += len(payload)
        require(
            total_container <= MAX_TOTAL_CONTAINER_BYTES,
            f"{prefix} aggregate container bytes exceed bound",
        )
        files.add(expected_path)
    require(
        encoding["containerBytes"] == total_container
        and encoding["payloadBytes"] == total_payload
        and math.isclose(
            float(encoding["compressionRatio"]),
            dense_expected / total_container,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ),
        f"{prefix} aggregate encoding differs",
    )
    return {
        "denseBF16Bytes": dense_expected,
        "containerBytes": total_container,
        "payloadBytes": total_payload,
    }, files, directories


def _independent_analysis(points: list[dict[str, Any]]) -> dict[str, Any]:
    require(isinstance(points, list) and len(points) == 6, "analysis needs six points")
    normalized: list[dict[str, Any]] = []
    for position, (point, level_id, prefill) in enumerate(
        zip(points, LEVEL_IDS, PREFILL_LEVELS)
    ):
        require_exact_keys(
            point,
            {"containerBytes", "denseBF16Bytes", "lengthLevelId", "prefillTokens"},
            f"analysis point {position}",
        )
        dense = require_int(point["denseBF16Bytes"], "analysis dense bytes", 1)
        container = require_int(point["containerBytes"], "analysis container bytes", 1)
        require(
            point["lengthLevelId"] == level_id
            and point["prefillTokens"] == prefill,
            "analysis point identity differs",
        )
        normalized.append(
            {
                "lengthLevelId": level_id,
                "prefillTokens": prefill,
                "denseBF16Bytes": dense,
                "containerBytes": container,
                "compressionRatio": dense / container,
            }
        )
    adjacent: list[dict[str, Any]] = []
    for left, right in zip(normalized, normalized[1:]):
        numerator = (
            right["denseBF16Bytes"] * left["containerBytes"]
            - left["denseBF16Bytes"] * right["containerBytes"]
        )
        adjacent.append(
            {
                "fromLengthLevelId": left["lengthLevelId"],
                "toLengthLevelId": right["lengthLevelId"],
                "deltaPrefillTokens": right["prefillTokens"] - left["prefillTokens"],
                "descriptiveDeltaCompressionRatio": right["compressionRatio"]
                - left["compressionRatio"],
                "exactCrossProductNumeratorDecimal": str(numerator),
                "strictlyIncreasing": numerator > 0,
                "nondecreasing": numerator >= 0,
            }
        )
    first = normalized[0]
    last = normalized[-1]
    endpoint = (
        last["denseBF16Bytes"] * first["containerBytes"]
        - first["denseBF16Bytes"] * last["containerBytes"]
    )
    materiality = (
        100 * last["denseBF16Bytes"] * first["containerBytes"]
        - 101 * first["denseBF16Bytes"] * last["containerBytes"]
    )
    return {
        "ratioDefinition": "complete-dense-bf16-cache-bytes-divided-by-complete-container-bytes",
        "decisionArithmetic": "exact-integer-cross-products",
        "points": normalized,
        "adjacentComparisons": adjacent,
        "primaryAllAdjacentStrictlyIncreasing": all(item["strictlyIncreasing"] for item in adjacent),
        "allAdjacentNondecreasing": all(item["nondecreasing"] for item in adjacent),
        "endpointDescriptiveDeltaCompressionRatio": last["compressionRatio"] - first["compressionRatio"],
        "endpointExactCrossProductNumeratorDecimal": str(endpoint),
        "endpointIncreasing": endpoint > 0,
        "endpointOnePercentMaterialityNumeratorDecimal": str(materiality),
        "endpointRelativeIncreaseAtLeastOnePercent": materiality >= 0,
        "statisticalInferencePerformed": False,
    }


def _independent_support_decision(complete: bool, analysis: dict[str, Any] | None) -> str:
    if not complete or analysis is None:
        return "INDETERMINATE"
    if analysis["primaryAllAdjacentStrictlyIncreasing"]:
        return "STRONG_DIRECTIONAL_SUPPORT"
    if analysis["endpointIncreasing"]:
        return "WEAK_DIRECTIONAL_SUPPORT"
    endpoint = int(analysis["endpointExactCrossProductNumeratorDecimal"])
    return "NO_POSITIVE_SUPPORT_EQUAL" if endpoint == 0 else "NO_POSITIVE_SUPPORT_DECREASE"


def _structural_rows(value: Any) -> dict[str, dict[str, Any]]:
    require(isinstance(value, list) and len(value) == 6, "structural rows differ")
    indexed: dict[str, dict[str, Any]] = {}
    for row, level_id, prefill in zip(value, LEVEL_IDS, PREFILL_LEVELS):
        require_exact_keys(row, STRUCTURAL_ROW_KEYS, f"structural row {level_id}")
        require(
            row["lengthLevelId"] == level_id and row["prefillTokens"] == prefill,
            f"structural row {level_id} identity differs",
        )
        require_digest(row["directResultSHA256"], f"structural row {level_id} result digest")
        require_digest(
            row["directCanonicalCacheBF16SHA256"],
            f"structural row {level_id} raw-cache digest",
        )
        dense = require_int(row["directDenseBF16Bytes"], "structural dense bytes", 1)
        container = require_int(row["directContainerBytes"], "structural container bytes", 1)
        payload = require_int(row["directPayloadBytes"], "structural payload bytes", 1)
        require(
            payload <= container
            and row["directContainerOverheadBytes"] == container - payload,
            f"structural row {level_id} direct byte accounting differs",
        )
        secondary_container = require_int(
            row["secondaryContainerBytes"], "structural secondary container bytes", 1
        )
        secondary_payload = require_int(
            row["secondaryPayloadBytes"], "structural secondary payload bytes", 1
        )
        require(
            secondary_payload <= secondary_container
            and row["secondaryContainerOverheadBytes"]
            == secondary_container - secondary_payload,
            f"structural row {level_id} secondary byte accounting differs",
        )
        for name in (
            "directContainerBytesPerPrefillToken",
            "directSpaceSavingFraction",
            "meanKLDivergenceNat",
            "meanBaselineSelectedTokenSurprisalDeltaNat",
        ):
            number = row[name]
            require(
                type(number) in (int, float) and math.isfinite(float(number)),
                f"structural row {level_id} {name} differs",
            )
        require(
            row["directContainerBytesPerPrefillToken"] == container / prefill
            and row["directSpaceSavingFraction"] == 1.0 - container / dense,
            f"structural row {level_id} direct derived metrics differ",
        )
        prediction_tokens = require_int(
            row["predictionTokens"], "structural prediction tokens", 1
        )
        agreement = require_int(
            row["controlledTop1AgreementCount"], "structural top-1 count", 0
        )
        require(
            prediction_tokens == HORIZON
            and agreement <= prediction_tokens
            and type(row["freeRunExact"]) is bool
            and 0
            <= require_int(
                row["freeRunSamePositionCount"], "structural free-run same count", 0
            )
            <= HORIZON
            and 0
            <= require_int(
                row["freeRunLongestCommonPrefixTokens"],
                "structural free-run prefix",
                0,
            )
            <= HORIZON
            and type(row["directVersusMasterSliceBitwiseIdentical"]) is bool
            and require_int(
                row["directVersusMasterSliceDifferingBF16Words"],
                "structural differing BF16 words",
                0,
            )
            >= 0,
            f"structural row {level_id} behavior fields differ",
        )
        indexed[level_id] = row
    return indexed


def _structural_boundary(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require_exact_keys(value, STRUCTURAL_PUBLIC_KEYS, "structural verification receipt")
    require(
        value["schemaVersion"] == VERIFY_SCHEMA_VERSION_LENGTH
        and value["status"] == "STRUCTURALLY_VERIFIED"
        and value["classification"] == LENGTH_CLASSIFICATION
        and value["countsTowardScientificVerdict"] is False
        and value["modelReplayPerformed"] is False
        and value["directCells"] == 6
        and value["secondaryControls"] == 6
        and value["directContainers"]
        == 6 * int(selected_profile()["geometry"]["layers"])
        and value["secondaryContainers"]
        == 6 * int(selected_profile()["geometry"]["layers"])
        and value["allSixModelReplaysRequiredForPublication"] is True,
        "structural receipt boundary differs",
    )
    for name in (
        "runSHA256",
        "preflightSHA256",
        "inputManifestSHA256",
        "inputTokenMasterSHA256",
        "assetReceiptSHA256",
    ):
        require_digest(value[name], f"structural {name}")
    try:
        require(str(uuid.UUID(value["runId"])) == value["runId"], "structural run ID differs")
    except (TypeError, ValueError) as error:
        raise ValueError("structural run ID is invalid") from error
    source = value["source"]
    require_exact_keys(source, {"branch", "commit", "tree"}, "structural source")
    require(
        isinstance(source["branch"], str)
        and bool(source["branch"])
        and isinstance(source["commit"], str)
        and re.fullmatch(r"[0-9a-f]{40}", source["commit"])
        and isinstance(source["tree"], str)
        and re.fullmatch(r"[0-9a-f]{40}", source["tree"]),
        "structural source identity differs",
    )
    require(
        value["supportDecision"]
        in {
            "STRONG_DIRECTIONAL_SUPPORT",
            "WEAK_DIRECTIONAL_SUPPORT",
            "NO_POSITIVE_SUPPORT_EQUAL",
            "NO_POSITIVE_SUPPORT_DECREASE",
        },
        "structural support decision differs",
    )
    return _structural_rows(value["rows"])


def _independent_payload_analysis(points: list[dict[str, Any]]) -> dict[str, Any]:
    require(len(points) == 6, "payload diagnostic needs six points")
    normalized: list[dict[str, Any]] = []
    for point, level_id, prefill in zip(points, LEVEL_IDS, PREFILL_LEVELS):
        dense = int(point["denseBF16Bytes"])
        payload = int(point["payloadBytes"])
        container = int(point["containerBytes"])
        require(point["lengthLevelId"] == level_id and point["prefillTokens"] == prefill and 0 < payload <= container, "payload point differs")
        normalized.append({
            "lengthLevelId": level_id, "prefillTokens": prefill,
            "denseBF16Bytes": dense, "payloadBytes": payload, "containerBytes": container,
            "containerOverheadBytes": container - payload,
            "containerBytesPerPrefillToken": container / prefill,
            "payloadBytesPerPrefillToken": payload / prefill,
            "payloadOnlyCompressionRatio": dense / payload,
        })
    adjacent: list[dict[str, Any]] = []
    for left, right in zip(normalized, normalized[1:]):
        numerator = right["denseBF16Bytes"] * left["payloadBytes"] - left["denseBF16Bytes"] * right["payloadBytes"]
        adjacent.append({
            "fromLengthLevelId": left["lengthLevelId"], "toLengthLevelId": right["lengthLevelId"],
            "exactPayloadCrossProductNumeratorDecimal": str(numerator),
            "payloadRatioStrictlyIncreasing": numerator > 0,
        })
    first, last = normalized[0], normalized[-1]
    endpoint = last["denseBF16Bytes"] * first["payloadBytes"] - first["denseBF16Bytes"] * last["payloadBytes"]
    material = 100 * last["denseBF16Bytes"] * first["payloadBytes"] - 101 * first["denseBF16Bytes"] * last["payloadBytes"]
    return {
        "role": "secondary-payload-only-header-amortization-diagnostic-never-controls-support-decision",
        "points": normalized, "adjacentComparisons": adjacent,
        "endpointExactPayloadCrossProductNumeratorDecimal": str(endpoint),
        "endpointPayloadRatioIncreasing": endpoint > 0,
        "endpointOnePercentPayloadMaterialityNumeratorDecimal": str(material),
        "endpointPayloadRelativeIncreaseAtLeastOnePercent": material >= 0,
    }


def _verify_analysis(value: Any, points: list[dict[str, Any]], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} analysis is absent")
    expected = _independent_analysis(points)
    require(value == expected, f"{label} analysis differs from recomputation")
    for comparison in value["adjacentComparisons"]:
        text = comparison["exactCrossProductNumeratorDecimal"]
        require(
            isinstance(text, str)
            and DECIMAL_INTEGER.fullmatch(text) is not None,
            f"{label} exact numerator is not a canonical decimal string",
        )
    for name in (
        "endpointExactCrossProductNumeratorDecimal",
        "endpointOnePercentMaterialityNumeratorDecimal",
    ):
        text = value[name]
        require(
            isinstance(text, str) and DECIMAL_INTEGER.fullmatch(text),
            f"{label} {name} is not a canonical decimal string",
        )
    return value


def _record_fields(record: dict[str, Any], label: str, expected_timeout: int) -> tuple[datetime, datetime]:
    require_exact_keys(
        record,
        {
            "completedAt",
            "exitSignal",
            "kind",
            "lengthLevelId",
            "prefillTokens",
            "resultPath",
            "resultSHA256",
            "returnCode",
            "startedAt",
            "status",
            "stderrSHA256",
            "stdoutSHA256",
            "terminationReason",
            "timedOut",
            "timeoutLimitSeconds",
        },
        label,
    )
    require(
        record["status"] == "COMPLETE"
        and record["returnCode"] == 0
        and record["exitSignal"] is None
        and record["timedOut"] is False
        and record["terminationReason"] == "completed"
        and record["timeoutLimitSeconds"] == expected_timeout,
        f"{label} process outcome differs",
    )
    require_digest(record["resultSHA256"], f"{label} result digest")
    require_digest(record["stdoutSHA256"], f"{label} stdout digest")
    require_digest(record["stderrSHA256"], f"{label} stderr digest")
    started = _timestamp(record["startedAt"], f"{label} start")
    completed = _timestamp(record["completedAt"], f"{label} completion")
    require(started <= completed, f"{label} completion precedes start")
    return started, completed


def _verify_attempt(
    *,
    path: Path,
    status: str,
    run_id: str,
    level_id: str,
    prefill: int,
    source: dict[str, Any],
    codec: dict[str, Any],
    asset_digest: str,
    preflight_digest: str,
    input_manifest_digest: str,
    input_token_digest: str,
    extra: dict[str, Any],
    expected_timeout: int,
) -> tuple[dict[str, Any], datetime]:
    attempt = _bounded_json(path, "cell attempt")
    _verify_sidecar(path)
    require(
        attempt.get("schemaVersion") == ATTEMPT_SCHEMA_VERSION_LENGTH
        and attempt.get("status") == status
        and attempt.get("classification") == LENGTH_CLASSIFICATION
        and attempt.get("countsTowardScientificVerdict") is False
        and attempt.get("runId") == run_id
        and attempt.get("lengthLevelId") == level_id
        and attempt.get("prefillTokens") == prefill
        and attempt.get("timeoutLimitSeconds") == expected_timeout
        and attempt.get("codecSource") == codec
        and attempt.get("assetReceiptSHA256") == asset_digest
        and attempt.get("preflightSHA256") == preflight_digest
        and attempt.get("inputManifestSHA256") == input_manifest_digest
        and attempt.get("inputTokenMasterSHA256") == input_token_digest,
        "cell attempt binding differs",
    )
    _require_source_bindings(attempt, source, "cell attempt")
    try:
        require(str(uuid.UUID(attempt["runId"])) == attempt["runId"], "run ID differs")
        require(str(uuid.UUID(attempt["attemptId"])) == attempt["attemptId"], "attempt ID differs")
    except (ValueError, TypeError, KeyError) as error:
        raise ValueError("attempt UUID differs") from error
    for name, expected in extra.items():
        require(attempt.get(name) == expected, f"cell attempt {name} differs")
    expected_keys = {
        "adapterId",
        "assetReceiptSHA256",
        "attemptId",
        "classification",
        "codecSource",
        "countsTowardScientificVerdict",
        "inputManifestSHA256",
        "inputTokenMasterSHA256",
        "ladderSHA256",
        "lengthLevelId",
        "lengthProtocolSHA256",
        "prefillTokens",
        "preflightSHA256",
        "runId",
        "schemaVersion",
        "selectedProfileObjectSHA256",
        "source",
        "sourceProfilesSHA256",
        "sourceWorkloadsSHA256",
        "startedAt",
        "status",
        "timeoutLimitSeconds",
        *extra.keys(),
    }
    # Adapter ID is deliberately present in the closed attempt identity.
    require(attempt.get("adapterId") == LENGTH_ADAPTER_ID, "attempt adapter differs")
    require(set(attempt) == expected_keys, "cell attempt keys differ")
    attempt_started = _timestamp(attempt["startedAt"], "attempt start")
    return attempt, attempt_started


def _verify_direct_result(
    *,
    run_root: Path,
    record: dict[str, Any],
    level_id: str,
    prefill: int,
    expected_preflight: dict[str, Any],
    input_token_raw: bytes,
    source: dict[str, Any],
    codec: dict[str, Any],
    asset_digest: str,
    preflight_digest: str,
    input_manifest_digest: str,
    input_token_digest: str,
    run_id: str,
    backend: Any,
) -> tuple[dict[str, Any], list[Any], list[bytes], dict[str, Any], set[str], set[str]]:
    record_started, record_completed = _record_fields(
        record, f"direct record {level_id}", DIRECT_TIMEOUT_BY_LEVEL[level_id]
    )
    require(
        record["kind"] == "LENGTH_CELL"
        and record["lengthLevelId"] == level_id
        and record["prefillTokens"] == prefill
        and record["resultPath"] == f"cells/{level_id}/result.json",
        "direct record identity differs",
    )
    cell_root = run_root / "cells" / level_id
    require(cell_root.is_dir() and not cell_root.is_symlink(), "direct cell root differs")
    attempt_path = cell_root / "attempt.json"
    _, attempt_started = _verify_attempt(
        path=attempt_path,
        status="CELL_STARTED",
        run_id=run_id,
        level_id=level_id,
        prefill=prefill,
        source=source,
        codec=codec,
        asset_digest=asset_digest,
        preflight_digest=preflight_digest,
        input_manifest_digest=input_manifest_digest,
        input_token_digest=input_token_digest,
        extra={},
        expected_timeout=DIRECT_TIMEOUT_BY_LEVEL[level_id],
    )
    result_path = _safe_relative(
        run_root,
        record["resultPath"],
        f"cells/{level_id}/result.json",
        "direct result",
    )
    result = _bounded_json(result_path, "direct result")
    require_exact_keys(result, DIRECT_RESULT_KEYS, "direct result")
    require(
        _verify_sidecar(result_path) == record["resultSHA256"],
        "direct result record digest differs",
    )
    require(
        result.get("schemaVersion") == RESULT_SCHEMA_VERSION_LENGTH
        and result.get("status") == "COMPLETE"
        and result.get("classification") == LENGTH_CLASSIFICATION
        and result.get("countsTowardScientificVerdict") is False
        and result.get("lengthLevelId") == level_id
        and result.get("prefillTokens") == prefill
        and result.get("codecSource") == codec
        and result.get("assetReceiptSHA256") == asset_digest
        and result.get("inputManifestSHA256") == input_manifest_digest
        and result.get("inputTokenMasterSHA256") == input_token_digest,
        "direct result binding differs",
    )
    _require_source_bindings(result, source, "direct result")
    profile = profile_for_length(prefill)
    selected = selected_profile()
    require(
        result.get("model")
        == {
            "modelId": LENGTH_MODEL_ID,
            "adapterId": LENGTH_ADAPTER_ID,
            "profileId": LENGTH_PROFILE_ID,
            "repository": selected["repository"],
            "revision": selected["revision"],
            "geometry": selected["geometry"],
        },
        "direct result model differs",
    )
    expected_workload = dict(expected_preflight)
    expected_workload.pop("lengthLevelId")
    require(result.get("workload") == expected_workload, "direct workload differs")
    BASEV._verify_cache_observation(result.get("cacheObservation"), profile)
    structural = result.get("directStructuralReplay")
    require(
        structural == {"maxAbsLogitDifference": 0.0, "top1Identical": True},
        "direct structural replay differs",
    )
    matrices, raws, raw_files, raw_directories = _verify_direct_raw(
        cell_root=cell_root,
        result=result,
        profile=profile,
        input_token_raw=input_token_raw,
    )
    direct_root = cell_root / "direct"
    require(direct_root.is_dir() and not direct_root.is_symlink(), "direct encoding root differs")
    encoding, container_files, container_directories = _verify_encoding(
        root=direct_root,
        encoding=result.get("directEncoding"),
        profile=profile,
        matrices=matrices,
        backend=backend,
        prefix="direct",
    )
    BASEV._verify_behavior(result.get("directBehavior"), profile)
    BASEV._verify_runtime(
        result.get("runtime"),
        profile,
        encoding["denseBF16Bytes"],
        codec["files"]["RealLLM/requirements.lock"]["sha256"],
    )
    runtime_started = _timestamp(result["runtime"]["startedAt"], "direct runtime start")
    runtime_completed = _timestamp(result["runtime"]["completedAt"], "direct runtime completion")
    require(
        attempt_started <= record_started <= runtime_started <= runtime_completed <= record_completed,
        "direct attempt/process/runtime interval nesting differs",
    )
    expected_files = {
        f"cells/{level_id}/attempt.json",
        f"cells/{level_id}/attempt.json.sha256",
        f"cells/{level_id}/result.json",
        f"cells/{level_id}/result.json.sha256",
        *{f"cells/{level_id}/{name}" for name in raw_files},
        *{f"cells/{level_id}/direct/{name}" for name in container_files},
    }
    expected_directories = {
        f"cells/{level_id}",
        *{f"cells/{level_id}/{name}" for name in raw_directories},
        f"cells/{level_id}/direct",
        *{f"cells/{level_id}/direct/{name}" for name in container_directories},
    }
    return result, matrices, raws, encoding, expected_files, expected_directories


def _verify_secondary_result(
    *,
    run_root: Path,
    record: dict[str, Any],
    level_id: str,
    prefill: int,
    direct_result: dict[str, Any],
    direct_raws: list[bytes],
    direct_matrices: list[Any],
    anchor_result: dict[str, Any],
    anchor_raws: list[bytes],
    source: dict[str, Any],
    codec: dict[str, Any],
    asset_digest: str,
    preflight_digest: str,
    input_manifest_digest: str,
    input_token_digest: str,
    run_id: str,
    backend: Any,
) -> tuple[dict[str, Any], dict[str, Any], set[str], set[str]]:
    record_started, record_completed = _record_fields(
        record, f"secondary record {level_id}", SECONDARY_TIMEOUT_SECONDS
    )
    require(
        record["kind"] == "SECONDARY_CODEC_CONTROL"
        and record["lengthLevelId"] == level_id
        and record["prefillTokens"] == prefill
        and record["resultPath"] == f"secondary/{level_id}/result.json",
        "secondary record identity differs",
    )
    secondary_root = run_root / "secondary" / level_id
    require(
        secondary_root.is_dir() and not secondary_root.is_symlink(),
        "secondary root differs",
    )
    direct_digest = sha256_file(run_root / "cells" / level_id / "result.json")
    anchor_digest = sha256_file(run_root / "cells" / LEVEL_IDS[-1] / "result.json")
    _, attempt_started = _verify_attempt(
        path=secondary_root / "attempt.json",
        status="SECONDARY_STARTED",
        run_id=run_id,
        level_id=level_id,
        prefill=prefill,
        source=source,
        codec=codec,
        asset_digest=asset_digest,
        preflight_digest=preflight_digest,
        input_manifest_digest=input_manifest_digest,
        input_token_digest=input_token_digest,
        extra={
            "directResultSHA256": direct_digest,
            "anchorDirectResultSHA256": anchor_digest,
        },
        expected_timeout=SECONDARY_TIMEOUT_SECONDS,
    )
    result_path = _safe_relative(
        run_root,
        record["resultPath"],
        f"secondary/{level_id}/result.json",
        "secondary result",
    )
    result = _bounded_json(result_path, "secondary result")
    require_exact_keys(result, SECONDARY_RESULT_KEYS, "secondary result")
    require(
        _verify_sidecar(result_path) == record["resultSHA256"],
        "secondary result record digest differs",
    )
    require(
        result.get("schemaVersion") == SECONDARY_SCHEMA_VERSION_LENGTH
        and result.get("status") == "SECONDARY_COMPLETE"
        and result.get("classification") == LENGTH_CLASSIFICATION
        and result.get("countsTowardScientificVerdict") is False
        and result.get("lengthLevelId") == level_id
        and result.get("prefillTokens") == prefill
        and result.get("codecSource") == codec
        and result.get("assetReceiptSHA256") == asset_digest
        and result.get("inputManifestSHA256") == input_manifest_digest
        and result.get("inputTokenMasterSHA256") == input_token_digest
        and result.get("directResultSHA256") == direct_digest
        and result.get("anchorDirectResultSHA256") == anchor_digest
        and result.get("anchorLengthLevelId") == LEVEL_IDS[-1]
        and result.get("anchorDirectCanonicalCacheBF16SHA256")
        == anchor_result["directCanonicalCacheBF16SHA256"],
        "secondary result binding differs",
    )
    _require_source_bindings(result, source, "secondary result")
    profile = profile_for_length(prefill)
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    slice_bytes = prefill * columns * 2
    master_raws = [raw[:slice_bytes] for raw in anchor_raws]
    master_matrices = [_bf16_matrix(raw, prefill, columns) for raw in master_raws]
    slice_bindings = result.get("sliceBindings")
    require(
        isinstance(slice_bindings, list)
        and len(slice_bindings) == int(profile["geometry"]["layers"]),
        "secondary slice binding count differs",
    )
    for index, (entry, raw) in enumerate(zip(slice_bindings, master_raws)):
        require_exact_keys(
            entry,
            {"anchorPath", "anchorSHA256", "bytes", "layerIndex", "sha256"},
            f"secondary slice binding {index}",
        )
        anchor_entry = anchor_result["directRawEvidence"]["layers"][index]
        require(
            entry
            == {
                "layerIndex": index,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "anchorPath": anchor_entry["path"],
                "anchorSHA256": anchor_entry["sha256"],
            },
            f"secondary slice binding {index} differs",
        )
    master_digest = _cache_digest(master_raws)
    require(
        result.get("masterSliceCanonicalCacheBF16SHA256") == master_digest,
        "secondary master-slice cache digest differs",
    )
    encoding, files, directories = _verify_encoding(
        root=secondary_root,
        encoding=result.get("masterSliceEncoding"),
        profile=profile,
        matrices=master_matrices,
        backend=backend,
        prefix="secondary",
    )
    differing = 0
    max_difference = 0.0
    for direct_raw, master_raw, direct_matrix, master_matrix in zip(
        direct_raws, master_raws, direct_matrices, master_matrices
    ):
        differing += int(
            np.count_nonzero(
                np.frombuffer(direct_raw, dtype="<u2")
                != np.frombuffer(master_raw, dtype="<u2")
            )
        )
        max_difference = max(
            max_difference,
            float(np.max(np.abs(direct_matrix - master_matrix), initial=0.0)),
        )
    dense = encoding["denseBF16Bytes"]
    require(
        result.get("directVersusMasterSlice")
        == {
            "bitwiseIdentical": differing == 0,
            "differingBF16Words": differing,
            "totalBF16Words": dense // 2,
            "maxAbsElementDifference": max_difference,
            "directCanonicalCacheBF16SHA256": direct_result[
                "directCanonicalCacheBF16SHA256"
            ],
            "masterSliceCanonicalCacheBF16SHA256": master_digest,
        },
        "direct-versus-master diagnostic differs",
    )
    runtime = result.get("runtime")
    require_exact_keys(
        runtime,
        {
            "completedAt",
            "gpuRequired",
            "modelInferencePerformed",
            "packages",
            "peakRssBytes",
            "python",
            "startedAt",
            "torch",
        },
        "secondary runtime",
    )
    require(
        runtime["modelInferencePerformed"] is False
        and runtime["gpuRequired"] is False
        and require_int(runtime["peakRssBytes"], "secondary peak RSS", 1) > 0,
        "secondary runtime boundary differs",
    )
    runtime_started = _timestamp(runtime["startedAt"], "secondary runtime start")
    runtime_completed = _timestamp(runtime["completedAt"], "secondary runtime completion")
    require(
        attempt_started <= record_started <= runtime_started <= runtime_completed <= record_completed,
        "secondary attempt/process/runtime interval nesting differs",
    )
    expected_files = {
        f"secondary/{level_id}/attempt.json",
        f"secondary/{level_id}/attempt.json.sha256",
        f"secondary/{level_id}/result.json",
        f"secondary/{level_id}/result.json.sha256",
        *{f"secondary/{level_id}/{name}" for name in files},
    }
    expected_directories = {
        f"secondary/{level_id}",
        *{f"secondary/{level_id}/{name}" for name in directories},
    }
    return result, encoding, expected_files, expected_directories


def verify_run(
    *,
    codec_root: Path,
    cache: Path,
    assets_path: Path,
    preflight_path: Path,
    run_dir: Path,
) -> dict[str, Any]:
    load_ladder()
    codec = validate_codec_root(codec_root.resolve(strict=True))
    source = BASEV._source_identity()
    cache_root = _safe_directory(cache, "asset cache")
    _, asset_digest = verify_length_assets(assets_path, cache_root)
    preflight, preflight_digest, input_manifest, input_token_raw, preflight_cells = (
        _verify_input_and_preflight(
            preflight_path=preflight_path,
            cache_root=cache_root,
            codec=codec,
            asset_digest=asset_digest,
            source=source,
        )
    )
    input_manifest_digest = preflight["inputManifest"]["sha256"]
    input_token_digest = preflight["inputManifest"]["tokenIdsSHA256"]
    run_root = _safe_directory(run_dir, "run directory")
    run_path = run_root / "run.json"
    run = _bounded_json(run_path, "run manifest")
    run_digest = _verify_sidecar(run_path)
    require_exact_keys(run, RUN_MANIFEST_KEYS, "run manifest")
    require(
        run["schemaVersion"] == RUN_SCHEMA_VERSION_LENGTH
        and run["status"] == "COMPLETE"
        and run["classification"] == LENGTH_CLASSIFICATION
        and run["countsTowardScientificVerdict"] is False
        and run["codecSource"] == codec
        and run["assetReceiptSHA256"] == asset_digest
        and run["preflightSHA256"] == preflight_digest,
        "run manifest binding differs",
    )
    _require_source_bindings(run, source, "run manifest")
    try:
        require(str(uuid.UUID(run["runId"])) == run["runId"], "run ID differs")
    except (ValueError, TypeError) as error:
        raise ValueError("run ID is invalid") from error
    require(
        run["expectedCells"] == run["completeCells"] == 6
        and run["expectedSecondaryControls"]
        == run["completeSecondaryControls"]
        == 6
        and run["executionOrder"] == list(EXECUTION_LEVEL_IDS)
        and run["analysisOrder"] == list(LEVEL_IDS),
        "run matrix closure differs",
    )
    records = run["cells"]
    require(isinstance(records, list) and len(records) == 6, "run direct records differ")
    direct_results: dict[str, dict[str, Any]] = {}
    direct_matrices: dict[str, list[Any]] = {}
    direct_raws: dict[str, list[bytes]] = {}
    direct_encodings: dict[str, dict[str, Any]] = {}
    expected_files = {"run.json", "run.json.sha256"}
    expected_directories = {"cells", "secondary", "logs"}
    backend = BASEV._load_codec(codec_root.resolve(strict=True))
    for position, level_id in enumerate(EXECUTION_LEVEL_IDS):
        record = records[position]
        prefill = dict(zip(LEVEL_IDS, PREFILL_LEVELS))[level_id]
        result, matrices, raws, encoding, files, directories = _verify_direct_result(
            run_root=run_root,
            record=record,
            level_id=level_id,
            prefill=prefill,
            expected_preflight=preflight_cells[level_id],
            input_token_raw=input_token_raw,
            source=source,
            codec=codec,
            asset_digest=asset_digest,
            preflight_digest=preflight_digest,
            input_manifest_digest=input_manifest_digest,
            input_token_digest=input_token_digest,
            run_id=run["runId"],
            backend=backend,
        )
        direct_results[level_id] = result
        direct_matrices[level_id] = matrices
        direct_raws[level_id] = raws
        direct_encodings[level_id] = encoding
        expected_files.update(files)
        expected_directories.update(directories)
        for suffix in ("stdout.log", "stderr.log"):
            log = run_root / "logs" / f"{level_id}.{suffix}"
            status = require_regular(log, f"direct {suffix}")
            require(status.st_size <= MAX_LOG_BYTES, "direct log exceeds bound")
            expected_digest = record[
                "stdoutSHA256" if suffix.startswith("stdout") else "stderrSHA256"
            ]
            require(sha256_file(log) == expected_digest, "direct log digest differs")
            expected_files.add(f"logs/{level_id}.{suffix}")
    for left, right in zip(records, records[1:]):
        require(
            _timestamp(left["completedAt"], "direct completion")
            <= _timestamp(right["startedAt"], "next direct start"),
            "direct cells overlap or violate registered execution order",
        )

    secondary_records = run["secondaryControls"]
    require(
        isinstance(secondary_records, list) and len(secondary_records) == 6,
        "run secondary records differ",
    )
    secondary_encodings: dict[str, dict[str, Any]] = {}
    secondary_results: dict[str, dict[str, Any]] = {}
    anchor = LEVEL_IDS[-1]
    for position, (level_id, prefill) in enumerate(zip(LEVEL_IDS, PREFILL_LEVELS)):
        record = secondary_records[position]
        secondary_result, encoding, files, directories = _verify_secondary_result(
            run_root=run_root,
            record=record,
            level_id=level_id,
            prefill=prefill,
            direct_result=direct_results[level_id],
            direct_raws=direct_raws[level_id],
            direct_matrices=direct_matrices[level_id],
            anchor_result=direct_results[anchor],
            anchor_raws=direct_raws[anchor],
            source=source,
            codec=codec,
            asset_digest=asset_digest,
            preflight_digest=preflight_digest,
            input_manifest_digest=input_manifest_digest,
            input_token_digest=input_token_digest,
            run_id=run["runId"],
            backend=backend,
        )
        secondary_encodings[level_id] = encoding
        secondary_results[level_id] = secondary_result
        expected_files.update(files)
        expected_directories.update(directories)
        for suffix in ("stdout.log", "stderr.log"):
            log = run_root / "logs" / f"secondary-{level_id}.{suffix}"
            status = require_regular(log, f"secondary {suffix}")
            require(status.st_size <= MAX_LOG_BYTES, "secondary log exceeds bound")
            expected_digest = record[
                "stdoutSHA256" if suffix.startswith("stdout") else "stderrSHA256"
            ]
            require(sha256_file(log) == expected_digest, "secondary log digest differs")
            expected_files.add(f"logs/secondary-{level_id}.{suffix}")
    require(
        _timestamp(records[-1]["completedAt"], "last direct completion")
        <= _timestamp(secondary_records[0]["startedAt"], "first secondary start"),
        "secondary controls began before all direct cells completed",
    )
    for left, right in zip(secondary_records, secondary_records[1:]):
        require(
            _timestamp(left["completedAt"], "secondary completion")
            <= _timestamp(right["startedAt"], "next secondary start"),
            "secondary controls overlap or violate ascending order",
        )

    hardware_fields = (
        "gpuName",
        "gpuDriverVersion",
        "gpuTotalBytes",
        "torch",
        "cuda",
        "packages",
        "modelRequirementsLockSHA256",
        "pipBootstrapLockSHA256",
        "portableRuntimeLockSHA256",
        "cudaRuntimeLockSHA256",
        "dtype",
        "attentionImplementation",
        "deterministicAlgorithms",
    )
    anchor_runtime = direct_results[EXECUTION_LEVEL_IDS[0]]["runtime"]
    for level_id in LEVEL_IDS:
        runtime = direct_results[level_id]["runtime"]
        require(
            all(runtime[name] == anchor_runtime[name] for name in hardware_fields),
            "direct runtime identity changed within the attempt",
        )
    require(
        int(anchor_runtime["gpuTotalBytes"]) >= 40960 * 1024 * 1024,
        "GPU memory is below the registered suite-specific minimum",
    )

    direct_points = [
        {
            "lengthLevelId": level_id,
            "prefillTokens": prefill,
            "denseBF16Bytes": direct_encodings[level_id]["denseBF16Bytes"],
            "containerBytes": direct_encodings[level_id]["containerBytes"],
        }
        for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS)
    ]
    secondary_points = [
        {
            "lengthLevelId": level_id,
            "prefillTokens": prefill,
            "denseBF16Bytes": secondary_encodings[level_id]["denseBF16Bytes"],
            "containerBytes": secondary_encodings[level_id]["containerBytes"],
        }
        for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS)
    ]
    direct_analysis = _verify_analysis(
        run["directPrimaryAnalysis"], direct_points, "direct primary"
    )
    _verify_analysis(
        run["masterSliceSecondaryAnalysis"], secondary_points, "master-slice secondary"
    )
    direct_payload_points = [
        {
            **point,
            "payloadBytes": direct_encodings[point["lengthLevelId"]]["payloadBytes"],
        }
        for point in direct_points
    ]
    secondary_payload_points = [
        {
            **point,
            "payloadBytes": secondary_encodings[point["lengthLevelId"]]["payloadBytes"],
        }
        for point in secondary_points
    ]
    require(
        run["directPayloadOnlyDiagnostic"]
        == _independent_payload_analysis(direct_payload_points),
        "direct payload-only diagnostic differs",
    )
    require(
        run["masterSlicePayloadOnlyDiagnostic"]
        == _independent_payload_analysis(secondary_payload_points),
        "master-slice payload-only diagnostic differs",
    )
    decision = _independent_support_decision(True, direct_analysis)
    require(run["supportDecision"] == decision, "run support decision differs")

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in run_root.rglob("*"):
        status = path.lstat()
        require(not stat.S_ISLNK(status.st_mode), "run tree contains a symlink")
        require(status.st_uid == os.getuid(), "run tree has foreign ownership")
        require(status.st_mode & 0o077 == 0, "run tree contains a nonprivate path")
        relative = path.relative_to(run_root).as_posix()
        if stat.S_ISREG(status.st_mode):
            actual_files.add(relative)
        elif stat.S_ISDIR(status.st_mode):
            actual_directories.add(relative)
        else:
            raise ValueError("run tree contains a special file")
    require(actual_files == expected_files, "run tree contains missing or extra files")
    require(actual_directories == expected_directories, "run tree contains missing or extra directories")
    rows: list[dict[str, Any]] = []
    for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS):
        result = direct_results[level_id]
        behavior = result["directBehavior"]
        direct_encoding = direct_encodings[level_id]
        secondary_encoding = secondary_encodings[level_id]
        direct_container = direct_encoding["containerBytes"]
        direct_payload = direct_encoding["payloadBytes"]
        secondary_container = secondary_encoding["containerBytes"]
        secondary_payload = secondary_encoding["payloadBytes"]
        rows.append(
            {
                "lengthLevelId": level_id,
                "prefillTokens": prefill,
                "directResultSHA256": sha256_file(
                    run_root / "cells" / level_id / "result.json"
                ),
                "directCanonicalCacheBF16SHA256": result[
                    "directCanonicalCacheBF16SHA256"
                ],
                "directDenseBF16Bytes": direct_encoding["denseBF16Bytes"],
                "directContainerBytes": direct_container,
                "directPayloadBytes": direct_payload,
                "directContainerOverheadBytes": direct_container - direct_payload,
                "directContainerBytesPerPrefillToken": direct_container / prefill,
                "directSpaceSavingFraction": 1.0
                - direct_container / direct_encoding["denseBF16Bytes"],
                "controlledTop1AgreementCount": behavior[
                    "controlledTop1AgreementCount"
                ],
                "predictionTokens": behavior["predictionTokens"],
                "meanKLDivergenceNat": behavior["meanKLDivergenceNat"],
                "meanBaselineSelectedTokenSurprisalDeltaNat": behavior[
                    "meanBaselineSelectedTokenSurprisalDeltaNat"
                ],
                "freeRunExact": behavior["freeRunExact"],
                "freeRunSamePositionCount": behavior["freeRunSamePositionCount"],
                "freeRunLongestCommonPrefixTokens": behavior[
                    "freeRunLongestCommonPrefixTokens"
                ],
                "directVersusMasterSliceBitwiseIdentical": secondary_results[
                    level_id
                ]["directVersusMasterSlice"]["bitwiseIdentical"],
                "directVersusMasterSliceDifferingBF16Words": secondary_results[
                    level_id
                ]["directVersusMasterSlice"]["differingBF16Words"],
                "secondaryContainerBytes": secondary_container,
                "secondaryPayloadBytes": secondary_payload,
                "secondaryContainerOverheadBytes": secondary_container
                - secondary_payload,
            }
        )
    return {
        "schemaVersion": VERIFY_SCHEMA_VERSION_LENGTH,
        "status": "STRUCTURALLY_VERIFIED",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "modelReplayPerformed": False,
        "runId": run["runId"],
        "source": source,
        "runSHA256": run_digest,
        "preflightSHA256": preflight_digest,
        "inputManifestSHA256": input_manifest_digest,
        "inputTokenMasterSHA256": input_token_digest,
        "assetReceiptSHA256": asset_digest,
        "directCells": 6,
        "secondaryControls": 6,
        "directContainers": 6 * int(selected_profile()["geometry"]["layers"]),
        "secondaryContainers": 6 * int(selected_profile()["geometry"]["layers"]),
        "directPrimaryAnalysis": direct_analysis,
        "masterSliceSecondaryAnalysis": run["masterSliceSecondaryAnalysis"],
        "directPayloadOnlyDiagnostic": run["directPayloadOnlyDiagnostic"],
        "masterSlicePayloadOnlyDiagnostic": run[
            "masterSlicePayloadOnlyDiagnostic"
        ],
        "supportDecision": decision,
        "allSixModelReplaysRequiredForPublication": True,
        "rows": rows,
        "_internal": {
            "source": source,
            "codec": codec,
            "cacheRoot": cache_root,
            "preflight": preflight,
            "preflightCells": preflight_cells,
            "inputTokenRaw": input_token_raw,
            "run": run,
            "runRoot": run_root,
            "directResults": direct_results,
            "directMatrices": direct_matrices,
            "directRaw": direct_raws,
            "backend": backend,
        },
    }


def _load_structural_context(
    *,
    codec_root: Path,
    cache: Path,
    assets_path: Path,
    preflight_path: Path,
    run_dir: Path,
    structural_path: Path,
) -> dict[str, Any]:
    structural = _bounded_json(structural_path, "structural verification receipt")
    structural_digest = _verify_sidecar(structural_path)
    structural_rows = _structural_boundary(structural)
    codec = validate_codec_root(codec_root.resolve(strict=True))
    source = BASEV._source_identity()
    require(structural["source"] == source, "structural source identity differs")
    cache_root = _safe_directory(cache, "asset cache")
    _, asset_digest = verify_length_assets(assets_path, cache_root)
    preflight, preflight_digest, _, input_token_raw, preflight_cells = (
        _verify_input_and_preflight(
            preflight_path=preflight_path,
            cache_root=cache_root,
            codec=codec,
            asset_digest=asset_digest,
            source=source,
        )
    )
    run_root = _safe_directory(run_dir, "run directory")
    run_path = run_root / "run.json"
    run = _bounded_json(run_path, "run manifest")
    run_digest = _verify_sidecar(run_path)
    require_exact_keys(run, RUN_MANIFEST_KEYS, "replay run manifest")
    require(
        structural["runId"] == run.get("runId")
        and structural["runSHA256"] == run_digest
        and structural["preflightSHA256"] == preflight_digest
        and structural["inputManifestSHA256"]
        == preflight["inputManifest"]["sha256"]
        and structural["inputTokenMasterSHA256"]
        == preflight["inputManifest"]["tokenIdsSHA256"]
        and structural["assetReceiptSHA256"] == asset_digest
        and structural["supportDecision"] == run.get("supportDecision")
        and structural["directPrimaryAnalysis"]
        == run.get("directPrimaryAnalysis")
        and structural["masterSliceSecondaryAnalysis"]
        == run.get("masterSliceSecondaryAnalysis"),
        "structural receipt no longer binds current run inputs",
    )
    require(
        run.get("schemaVersion") == RUN_SCHEMA_VERSION_LENGTH
        and run.get("status") == "COMPLETE"
        and run.get("classification") == LENGTH_CLASSIFICATION
        and run.get("countsTowardScientificVerdict") is False
        and run.get("codecSource") == codec
        and run.get("assetReceiptSHA256") == asset_digest
        and run.get("preflightSHA256") == preflight_digest
        and run.get("expectedCells") == run.get("completeCells") == 6
        and run.get("expectedSecondaryControls")
        == run.get("completeSecondaryControls")
        == 6
        and run.get("executionOrder") == list(EXECUTION_LEVEL_IDS)
        and run.get("analysisOrder") == list(LEVEL_IDS),
        "replay run manifest boundary differs",
    )
    _require_source_bindings(run, source, "replay run manifest")
    try:
        require(str(uuid.UUID(run["runId"])) == run["runId"], "replay run ID differs")
    except (TypeError, ValueError) as error:
        raise ValueError("replay run ID is invalid") from error
    records = run["cells"]
    require(
        isinstance(records, list)
        and len(records) == 6
        and [record.get("lengthLevelId") for record in records]
        == list(EXECUTION_LEVEL_IDS),
        "replay direct record order differs",
    )
    secondary_records = run["secondaryControls"]
    require(
        isinstance(secondary_records, list)
        and len(secondary_records) == 6
        and [record.get("lengthLevelId") for record in secondary_records]
        == list(LEVEL_IDS),
        "replay secondary record order differs",
    )
    direct_digests: dict[str, str] = {}
    direct_intervals: list[tuple[datetime, datetime]] = []
    direct_attempt_starts: dict[str, datetime] = {}
    for record, level_id in zip(records, EXECUTION_LEVEL_IDS):
        prefill = dict(zip(LEVEL_IDS, PREFILL_LEVELS))[level_id]
        started, completed = _record_fields(
            record,
            f"replay direct record {level_id}",
            DIRECT_TIMEOUT_BY_LEVEL[level_id],
        )
        require(
            record["kind"] == "LENGTH_CELL"
            and record["lengthLevelId"] == level_id
            and record["prefillTokens"] == prefill
            and record["resultPath"] == f"cells/{level_id}/result.json",
            f"replay direct record {level_id} identity differs",
        )
        result_path = _safe_relative(
            run_root,
            record["resultPath"],
            f"cells/{level_id}/result.json",
            f"replay direct result {level_id}",
        )
        digest = _verify_sidecar(result_path)
        require(digest == record["resultSHA256"], f"replay direct result {level_id} digest differs")
        _, attempt_started = _verify_attempt(
            path=run_root / f"cells/{level_id}/attempt.json",
            status="CELL_STARTED",
            run_id=run["runId"],
            level_id=level_id,
            prefill=prefill,
            source=source,
            codec=codec,
            asset_digest=asset_digest,
            preflight_digest=preflight_digest,
            input_manifest_digest=preflight["inputManifest"]["sha256"],
            input_token_digest=preflight["inputManifest"]["tokenIdsSHA256"],
            extra={},
            expected_timeout=DIRECT_TIMEOUT_BY_LEVEL[level_id],
        )
        require(attempt_started <= started, f"replay direct attempt {level_id} began after its process")
        direct_digests[level_id] = digest
        direct_intervals.append((started, completed))
        direct_attempt_starts[level_id] = attempt_started
    for left, right in zip(direct_intervals, direct_intervals[1:]):
        require(left[1] <= right[0], "replay direct records overlap or violate order")

    secondary_intervals: list[tuple[datetime, datetime]] = []
    for record, level_id, prefill in zip(secondary_records, LEVEL_IDS, PREFILL_LEVELS):
        started, completed = _record_fields(
            record, f"replay secondary record {level_id}", SECONDARY_TIMEOUT_SECONDS
        )
        require(
            record["kind"] == "SECONDARY_CODEC_CONTROL"
            and record["lengthLevelId"] == level_id
            and record["prefillTokens"] == prefill
            and record["resultPath"] == f"secondary/{level_id}/result.json",
            f"replay secondary record {level_id} identity differs",
        )
        result_path = _safe_relative(
            run_root,
            record["resultPath"],
            f"secondary/{level_id}/result.json",
            f"replay secondary result {level_id}",
        )
        require(
            _verify_sidecar(result_path) == record["resultSHA256"],
            f"replay secondary result {level_id} digest differs",
        )
        _, attempt_started = _verify_attempt(
            path=run_root / f"secondary/{level_id}/attempt.json",
            status="SECONDARY_STARTED",
            run_id=run["runId"],
            level_id=level_id,
            prefill=prefill,
            source=source,
            codec=codec,
            asset_digest=asset_digest,
            preflight_digest=preflight_digest,
            input_manifest_digest=preflight["inputManifest"]["sha256"],
            input_token_digest=preflight["inputManifest"]["tokenIdsSHA256"],
            extra={
                "directResultSHA256": direct_digests[level_id],
                "anchorDirectResultSHA256": direct_digests[LEVEL_IDS[-1]],
            },
            expected_timeout=SECONDARY_TIMEOUT_SECONDS,
        )
        require(attempt_started <= started, f"replay secondary attempt {level_id} began after its process")
        secondary_intervals.append((started, completed))
    require(
        direct_intervals[-1][1] <= secondary_intervals[0][0],
        "replay secondary controls began before direct completion",
    )
    for left, right in zip(secondary_intervals, secondary_intervals[1:]):
        require(left[1] <= right[0], "replay secondary records overlap or violate order")
    backend = BASEV._load_codec(codec_root.resolve(strict=True))
    return {
        **structural,
        "structuralVerificationSHA256": structural_digest,
        "_internal": {
            "source": source,
            "codec": codec,
            "cacheRoot": cache_root,
            "preflight": preflight,
            "preflightCells": preflight_cells,
            "inputTokenRaw": input_token_raw,
            "run": run,
            "runRoot": run_root,
            "structuralRows": structural_rows,
            "directResultDigests": direct_digests,
            "directAttemptStarts": direct_attempt_starts,
            "directProcessIntervals": dict(zip(EXECUTION_LEVEL_IDS, direct_intervals)),
            "backend": backend,
            "assetDigest": asset_digest,
        },
    }


def replay_cell(
    *,
    codec_root: Path,
    cache: Path,
    assets_path: Path,
    preflight_path: Path,
    run_dir: Path,
    structural_path: Path,
    level_id: str,
) -> dict[str, Any]:
    verification = _load_structural_context(
        codec_root=codec_root,
        cache=cache,
        assets_path=assets_path,
        preflight_path=preflight_path,
        run_dir=run_dir,
        structural_path=structural_path,
    )
    internal = verification["_internal"]
    require(level_id in LEVEL_IDS, "replay length is not registered")
    prefill = dict(zip(LEVEL_IDS, PREFILL_LEVELS))[level_id]
    profile = profile_for_length(prefill)
    records = internal["run"]["cells"]
    record = records[list(EXECUTION_LEVEL_IDS).index(level_id)]
    record_started, record_completed = internal["directProcessIntervals"][level_id]
    attempt_started = internal["directAttemptStarts"][level_id]
    require(
        record["kind"] == "LENGTH_CELL"
        and record["lengthLevelId"] == level_id
        and record["prefillTokens"] == prefill
        and record["resultPath"] == f"cells/{level_id}/result.json",
        "selected replay record identity differs",
    )
    result_path = internal["runRoot"] / f"cells/{level_id}/result.json"
    result = _bounded_json(result_path, "selected replay result")
    require_exact_keys(result, DIRECT_RESULT_KEYS, "selected replay result")
    result_digest = _verify_sidecar(result_path)
    require(
        result_digest == record["resultSHA256"] == internal["directResultDigests"][level_id]
        and result.get("schemaVersion") == RESULT_SCHEMA_VERSION_LENGTH
        and result.get("status") == "COMPLETE"
        and result.get("classification") == LENGTH_CLASSIFICATION
        and result.get("countsTowardScientificVerdict") is False
        and result.get("lengthLevelId") == level_id
        and result.get("prefillTokens") == prefill
        and result.get("codecSource") == internal["codec"]
        and result.get("assetReceiptSHA256") == internal["assetDigest"]
        and result.get("inputManifestSHA256")
        == internal["preflight"]["inputManifest"]["sha256"]
        and result.get("inputTokenMasterSHA256")
        == internal["preflight"]["inputManifest"]["tokenIdsSHA256"],
        "selected replay result binding differs",
    )
    _require_source_bindings(result, internal["source"], "selected replay result")
    selected_profile_value = selected_profile()
    require(
        result["model"]
        == {
            "modelId": LENGTH_MODEL_ID,
            "adapterId": LENGTH_ADAPTER_ID,
            "profileId": LENGTH_PROFILE_ID,
            "repository": selected_profile_value["repository"],
            "revision": selected_profile_value["revision"],
            "geometry": selected_profile_value["geometry"],
        },
        "selected replay model identity differs",
    )
    expected_workload = dict(internal["preflightCells"][level_id])
    expected_workload.pop("lengthLevelId")
    require(result["workload"] == expected_workload, "selected replay workload differs")
    runtime_started = _timestamp(result["runtime"]["startedAt"], "selected runtime start")
    runtime_completed = _timestamp(
        result["runtime"]["completedAt"], "selected runtime completion"
    )
    require(
        attempt_started
        <= record_started
        <= runtime_started
        <= runtime_completed
        <= record_completed,
        "selected replay process interval nesting differs",
    )
    row = internal["structuralRows"][level_id]
    encoding = result["directEncoding"]
    behavior = result["directBehavior"]
    require(
        row["directResultSHA256"] == result_digest
        and row["directCanonicalCacheBF16SHA256"]
        == result["directCanonicalCacheBF16SHA256"]
        and row["directDenseBF16Bytes"] == encoding["denseBF16Bytes"]
        and row["directContainerBytes"] == encoding["containerBytes"]
        and row["directPayloadBytes"] == encoding["payloadBytes"]
        and row["controlledTop1AgreementCount"]
        == behavior["controlledTop1AgreementCount"]
        and row["predictionTokens"] == behavior["predictionTokens"]
        and row["meanKLDivergenceNat"] == behavior["meanKLDivergenceNat"]
        and row["meanBaselineSelectedTokenSurprisalDeltaNat"]
        == behavior["meanBaselineSelectedTokenSurprisalDeltaNat"]
        and row["freeRunExact"] == behavior["freeRunExact"]
        and row["freeRunSamePositionCount"]
        == behavior["freeRunSamePositionCount"]
        and row["freeRunLongestCommonPrefixTokens"]
        == behavior["freeRunLongestCommonPrefixTokens"],
        "selected replay structural row differs from current result",
    )
    _, _, retained_raws, _, _ = _read_direct_raw_fast(
        result_path=result_path, result=result, profile=profile
    )
    torch_module = BASEV._configure_torch()
    BASEV.np = np
    torch_module.cuda.reset_peak_memory_stats()
    model, tokenizer, _ = BASEV._load_model_and_tokenizer(
        profile,
        internal["cacheRoot"],
        torch_module,
        None,
    )
    text, inventory = workload_text(selected_workload())
    require(inventory == result["workload"]["sourceFiles"], "replay inventory differs")
    ids = _tokenizer_ids(tokenizer, text)
    selected = ids[: prefill + 1]
    selected_raw = _token_bytes(selected)
    require(
        selected_raw == internal["inputTokenRaw"][: len(selected_raw)]
        and sha256_bytes(selected_raw) == result["selectedTokenIds"]["sha256"],
        "replay token prefix differs",
    )
    prefix = torch_module.tensor(
        [selected[:prefill]], dtype=torch_module.long, device="cuda:0"
    )
    from transformers import DynamicCache

    with torch_module.inference_mode():
        output = model(
            prefix,
            past_key_values=DynamicCache(config=model.config),
            use_cache=True,
            return_dict=True,
        )
    native_cache = output.past_key_values
    require(int(native_cache.get_seq_length()) == prefill, "replay cache length differs")
    canonical, raw_layers = BASEV._extract_canonical_layers(
        native_cache, profile, prefill, torch_module
    )
    require(
        raw_layers == retained_raws
        and _cache_digest(raw_layers) == result["directCanonicalCacheBF16SHA256"],
        "replay raw canonical cache bytes differ",
    )
    token = torch_module.tensor(
        [[int(selected[prefill])]], dtype=torch_module.long, device="cuda:0"
    )
    direct_logits, advanced = BASEV._model_step(
        model, token, native_cache, torch_module
    )
    rebuilt = BASEV._dynamic_cache_from_layers(
        model, canonical, profile, torch_module
    )
    rebuilt_logits, rebuilt_advanced = BASEV._model_step(
        model, token, rebuilt, torch_module
    )
    structural_difference = float((direct_logits - rebuilt_logits).abs().max().item())
    structural_top1 = bool(
        torch_module.equal(
            direct_logits.argmax(dim=-1), rebuilt_logits.argmax(dim=-1)
        )
    )
    require(
        result["directStructuralReplay"]
        == {
            "maxAbsLogitDifference": structural_difference,
            "top1Identical": structural_top1,
        }
        == {"maxAbsLogitDifference": 0.0, "top1Identical": True},
        "replay structural equality differs",
    )
    del native_cache, output, advanced, rebuilt, rebuilt_advanced, direct_logits, rebuilt_logits
    torch_module.cuda.empty_cache()
    direct_root = internal["runRoot"] / "cells" / level_id / "direct"
    _, reconstructed = BASEV._decode_containers(
        cell_root=direct_root,
        result={"encoding": result["directEncoding"]},
        profile=profile,
        backend=internal["backend"],
        retain_layers=True,
    )
    observed_behavior = BASEV._controlled_metrics(
        model,
        tokenizer,
        canonical,
        reconstructed,
        profile,
        int(selected[prefill]),
        torch_module,
    )
    BASEV._compare_behavior(observed_behavior, result["directBehavior"])
    runtime = result["runtime"]
    report = {
        "schemaVersion": REPLAY_SCHEMA_VERSION_LENGTH,
        "status": "MODEL_REPLAY_VERIFIED",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "lengthLevelId": level_id,
        "prefillTokens": prefill,
        "modelId": LENGTH_MODEL_ID,
        "adapterId": LENGTH_ADAPTER_ID,
        "workloadId": LENGTH_WORKLOAD_ID,
        "resultSHA256": sha256_file(
            internal["runRoot"] / "cells" / level_id / "result.json"
        ),
        "runSHA256": verification["runSHA256"],
        "preflightSHA256": verification["preflightSHA256"],
        "inputManifestSHA256": verification["inputManifestSHA256"],
        "inputTokenMasterSHA256": verification["inputTokenMasterSHA256"],
        "assetReceiptSHA256": verification["assetReceiptSHA256"],
        "structuralVerificationSHA256": verification[
            "structuralVerificationSHA256"
        ],
        "canonicalCacheBF16SHA256": result[
            "directCanonicalCacheBF16SHA256"
        ],
        "rawCanonicalCacheBitwiseIdentical": True,
        "structuralReplayExact": True,
        "behaviorReplayVerified": True,
        "predictionTokens": HORIZON,
        "controlledTop1Agreement": observed_behavior[
            "controlledTop1Agreement"
        ],
        "gpuName": torch_module.cuda.get_device_name(0),
        "gpuDriverVersion": BASEV._gpu_driver_version(),
        "gpuTotalBytes": int(torch_module.cuda.get_device_properties(0).total_memory),
        "peakAllocatedBytes": int(torch_module.cuda.max_memory_allocated()),
    }
    require(
        report["gpuName"] == runtime["gpuName"]
        and report["gpuDriverVersion"] == runtime["gpuDriverVersion"]
        and report["gpuTotalBytes"] == runtime["gpuTotalBytes"],
        "replay hardware identity differs from producing attempt",
    )
    del model, tokenizer, canonical, reconstructed
    gc.collect()
    torch_module.cuda.empty_cache()
    return report


def _public(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "_internal"}


def render_results(structural_path: Path, output: Path) -> int:
    structural = _bounded_json(structural_path, "structural verification receipt")
    structural_digest = _verify_sidecar(structural_path)
    _structural_boundary(structural)
    direct = structural["directPrimaryAnalysis"]
    secondary = structural["masterSliceSecondaryAnalysis"]
    direct_payload = structural["directPayloadOnlyDiagnostic"]
    secondary_payload = structural["masterSlicePayloadOnlyDiagnostic"]
    lines = [
        "# RunPod length ladder v1 verified raw results",
        "",
        f"Classification: `{LENGTH_CLASSIFICATION}`. Scientific evidence: `false`. Counts toward scientific verdict: `false`.",
        f"Model/adapter: `{LENGTH_MODEL_ID}` / `{LENGTH_ADAPTER_ID}`. Workload: `{LENGTH_WORKLOAD_ID}`.",
        f"Run SHA-256: `{structural['runSHA256']}`. Structural receipt SHA-256: `{structural_digest}`.",
        f"Preflight SHA-256: `{structural['preflightSHA256']}`.",
        f"Source commit/tree: `{structural['source']['commit']}` / `{structural['source']['tree']}`.",
        "This is a same-attempt public preregistered regression, not an independent or blind replication. Nested prefixes confound length with the particular added tokens.",
        "This structural report does not establish model-replay completion; publication requires six separate `MODEL_REPLAY_VERIFIED` receipts, one for every registered P.",
        "",
        f"Support decision: `{structural['supportDecision']}`.",
        f"Endpoint gain at least 1%: `{str(direct['endpointRelativeIncreaseAtLeastOnePercent']).lower()}`.",
        f"Endpoint exact numerator: `{direct['endpointExactCrossProductNumeratorDecimal']}`. One-percent materiality numerator: `{direct['endpointOnePercentMaterialityNumeratorDecimal']}`.",
        "",
        "| P | Direct dense | Direct container | Direct payload | Overhead | Container/token | Saving | Direct R | Top-1 | Mean KL | Mean surprisal Δ | Free exact | Free same | Free LCP | Master identical | Master container |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|---:|---:|:---:|---:|",
    ]
    for index in range(6):
        d = direct["points"][index]
        row = structural["rows"][index]
        lines.append(
            f"| {d['prefillTokens']} | {row['directDenseBF16Bytes']} | {row['directContainerBytes']} | {row['directPayloadBytes']} | {row['directContainerOverheadBytes']} | {row['directContainerBytesPerPrefillToken']:.12g} | {row['directSpaceSavingFraction']:.12g} | {d['compressionRatio']:.12g} | {row['controlledTop1AgreementCount']}/{row['predictionTokens']} | {row['meanKLDivergenceNat']:.12g} | {row['meanBaselineSelectedTokenSurprisalDeltaNat']:.12g} | {str(row['freeRunExact']).lower()} | {row['freeRunSamePositionCount']} | {row['freeRunLongestCommonPrefixTokens']} | {str(row['directVersusMasterSliceBitwiseIdentical']).lower()} | {row['secondaryContainerBytes']} |"
        )
    lines.extend(
        [
            "",
            "| Adjacent P | Exact direct cross-product numerator | Strict increase |",
            "|---|---:|:---:|",
            *[
                f"| {item['fromLengthLevelId']} → {item['toLengthLevelId']} | {item['exactCrossProductNumeratorDecimal']} | {str(item['strictlyIncreasing']).lower()} |"
                for item in direct["adjacentComparisons"]
            ],
            "",
            "No averages, p-values, confidence intervals, or cross-model aggregates are reported.",
            "The support class uses only complete-container direct-prefill exact integer comparisons; payload and master-slice columns are secondary diagnostics.",
            "",
        ]
    )
    raw = "\n".join(lines).encode("utf-8")
    from common import exclusive_write

    exclusive_write(output, raw)
    exclusive_write(
        output.with_suffix(output.suffix + ".sha256"),
        f"{sha256_bytes(raw)}  {output.name}\n".encode("ascii"),
    )
    print(raw.decode("utf-8"), end="", flush=True)
    return 0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "replay-cell"):
        command = commands.add_parser(name)
        command.add_argument("--codec-root", type=Path, required=True)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--assets", type=Path, required=True)
        command.add_argument("--preflight", type=Path, required=True)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name == "replay-cell":
            command.add_argument("--structural", type=Path, required=True)
            command.add_argument("--length-level", choices=LEVEL_IDS, required=True)
    render = commands.add_parser("render-results")
    render.add_argument("--structural", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    global np
    arguments = parse_arguments()
    import numpy as numpy_module

    np = numpy_module
    BASEV.np = numpy_module
    if arguments.command == "render-results":
        return render_results(arguments.structural, arguments.output)
    common = {
        "codec_root": arguments.codec_root,
        "cache": arguments.cache,
        "assets_path": arguments.assets,
        "preflight_path": arguments.preflight,
        "run_dir": arguments.run_dir,
    }
    if arguments.command == "verify":
        value = _public(verify_run(**common))
    else:
        value = replay_cell(
            **common,
            structural_path=arguments.structural,
            level_id=arguments.length_level,
        )
    write_canonical_json(arguments.output, value)
    print(canonical_json_bytes(value).decode("utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"LENGTH LADDER VERIFICATION FAIL: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
