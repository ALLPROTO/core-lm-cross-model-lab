#!/usr/bin/env python3
"""Execute the six-point direct-prefill RunPod length ladder."""

from __future__ import annotations

import argparse
import gc
import importlib.util
import math
import os
import platform
import resource
import shutil
import sys
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


os.umask(0o077)
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
    LENGTH_SUITE_ROOT,
    LENGTH_WORKLOAD_ID,
    LEVEL_IDS,
    PREFILL_LEVELS,
    PREFLIGHT_SCHEMA_VERSION_LENGTH,
    PROFILES_PATH,
    RESULT_SCHEMA_VERSION_LENGTH,
    RUN_SCHEMA_VERSION_LENGTH,
    SECONDARY_SCHEMA_VERSION_LENGTH,
    SECONDARY_TIMEOUT_SECONDS,
    TORCH_LOCK_PATH,
    WORKLOADS_PATH,
    canonical_json_bytes,
    exclusive_write,
    length_analysis,
    level_prefill,
    load_ladder,
    profile_for_length,
    profile_object_sha256,
    payload_analysis,
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
    support_decision,
    validate_codec_root,
    verify_digest_sidecar,
    verify_length_assets,
    write_canonical_json,
)


def _load_adapter_runner() -> Any:
    if str(ADAPTER_SUITE_ROOT) not in sys.path:
        sys.path.insert(1, str(ADAPTER_SUITE_ROOT))
    path = ADAPTER_SUITE_ROOT / "run_adapter_sweep.py"
    spec = importlib.util.spec_from_file_location(
        "_corelm_runpod_adapter_runner_v1", path
    )
    require(spec is not None and spec.loader is not None, "cannot load adapter runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_adapter_runner()
np: Any = None


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def source_bindings() -> dict[str, Any]:
    source = BASE.git_source_identity()
    profile = selected_profile()
    return {
        "source": source,
        "ladderSHA256": sha256_file(LADDER_PATH),
        "lengthProtocolSHA256": sha256_file(LENGTH_PROTOCOL_PATH),
        "sourceProfilesSHA256": sha256_file(PROFILES_PATH),
        "sourceWorkloadsSHA256": sha256_file(WORKLOADS_PATH),
        "selectedProfileObjectSHA256": profile_object_sha256(profile),
    }


def _workload_material(profile: dict[str, Any], tokenizer: Any) -> tuple[list[int], dict[str, Any]]:
    selected, material = BASE.source_material(
        profile, selected_workload(), tokenizer
    )
    require(material["workloadId"] == LENGTH_WORKLOAD_ID, "workload ID differs")
    require(material["category"] == LENGTH_CONTENT_CLASS, "workload class differs")
    return selected, material


def _preflight_cell(value: dict[str, Any], level_id: str) -> dict[str, Any]:
    matches = [entry for entry in value["cells"] if entry.get("lengthLevelId") == level_id]
    require(len(matches) == 1, "preflight length cell is absent or duplicated")
    return matches[0]


def preflight(arguments: argparse.Namespace) -> int:
    load_ladder()
    codec = validate_codec_root(arguments.codec_root)
    cache = BASE.safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_digest = verify_length_assets(arguments.assets, cache)
    from transformers import AutoConfig, AutoTokenizer

    profile = selected_profile()
    snapshot = BASE.asset_snapshot(cache, profile)
    config = AutoConfig.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False
    )
    BASE.validate_geometry(BASE.configuration_geometry(config), profile)
    tokenizer = AutoTokenizer.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False
    )
    cells: list[dict[str, Any]] = []
    previous_selected: list[int] | None = None
    complete_available: int | None = None
    for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS):
        selected, material = _workload_material(profile_for_length(prefill), tokenizer)
        if complete_available is None:
            complete_available = material["availableTokens"]
        require(
            material["availableTokens"] == complete_available,
            "tokenizer available-token count changed across levels",
        )
        if previous_selected is not None:
            require(
                selected[: len(previous_selected)] == previous_selected,
                "selected token vectors are not exact nested prefixes",
            )
        previous_selected = selected
        cells.append({"lengthLevelId": level_id, **material})
    require(previous_selected is not None, "preflight produced no token master")
    token_master_raw = np.asarray(previous_selected, dtype="<u4").tobytes()
    token_master_path = arguments.output.with_name("input-token-ids.u32le")
    input_manifest_path = arguments.output.with_name("input.json")
    require(
        token_master_path.parent == arguments.output.parent
        and input_manifest_path.parent == arguments.output.parent,
        "preflight input paths escaped output parent",
    )
    exclusive_write(token_master_path, token_master_raw)
    exclusive_write(
        token_master_path.with_suffix(token_master_path.suffix + ".sha256"),
        f"{sha256_bytes(token_master_raw)}  {token_master_path.name}\n".encode("ascii"),
    )
    input_manifest = {
        "schemaVersion": INPUT_SCHEMA_VERSION_LENGTH,
        "status": "INPUT_TOKEN_MASTER_MATERIALIZED_NO_MODEL_INFERENCE",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        **source_bindings(),
        "codecSource": codec,
        "assetReceiptSHA256": asset_digest,
        "modelId": LENGTH_MODEL_ID,
        "adapterId": LENGTH_ADAPTER_ID,
        "workloadId": LENGTH_WORKLOAD_ID,
        "workload": cells[-1] | {"lengthLevelId": LEVEL_IDS[-1]},
        "tokenIds": {
            "bytes": len(token_master_raw),
            "count": len(previous_selected),
            "dtype": "uint32-little-endian",
            "path": token_master_path.name,
            "sha256": sha256_bytes(token_master_raw),
        },
    }
    input_manifest_digest = write_canonical_json(input_manifest_path, input_manifest)
    result = {
        "schemaVersion": PREFLIGHT_SCHEMA_VERSION_LENGTH,
        "status": "TOKENIZER_ONLY_NO_MODEL_INFERENCE",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        **source_bindings(),
        "codecSource": codec,
        "assetReceiptSHA256": asset_digest,
        "modelId": LENGTH_MODEL_ID,
        "adapterId": LENGTH_ADAPTER_ID,
        "workloadId": LENGTH_WORKLOAD_ID,
        "lengthOrder": list(LEVEL_IDS),
        "executionOrder": list(EXECUTION_LEVEL_IDS),
        "prefillOrder": list(PREFILL_LEVELS),
        "horizon": HORIZON,
        "inputManifest": {
            "path": input_manifest_path.name,
            "sha256": input_manifest_digest,
            "tokenIdsPath": token_master_path.name,
            "tokenIdsSHA256": sha256_bytes(token_master_raw),
        },
        "cells": cells,
    }
    write_canonical_json(arguments.output, result)
    print(canonical_json_bytes(result).decode("utf-8"), flush=True)
    return 0


def load_preflight(path: Path) -> dict[str, Any]:
    value = strict_json_file(path, "length-ladder preflight")
    verify_digest_sidecar(path)
    require(
        value.get("schemaVersion") == PREFLIGHT_SCHEMA_VERSION_LENGTH
        and value.get("status") == "TOKENIZER_ONLY_NO_MODEL_INFERENCE"
        and value.get("classification") == LENGTH_CLASSIFICATION
        and value.get("countsTowardScientificVerdict") is False,
        "length-ladder preflight boundary differs",
    )
    require(value.get("lengthOrder") == list(LEVEL_IDS), "preflight length order differs")
    require(
        value.get("executionOrder") == list(EXECUTION_LEVEL_IDS),
        "preflight execution order differs",
    )
    require(
        value.get("prefillOrder") == list(PREFILL_LEVELS),
        "preflight prefill order differs",
    )
    require(value.get("horizon") == HORIZON, "preflight horizon differs")
    for name, expected in source_bindings().items():
        require(value.get(name) == expected, f"preflight {name} differs")
    _load_input_manifest(path, value)
    return value


def _load_input_manifest(
    preflight_path: Path, preflight_value: dict[str, Any]
) -> tuple[dict[str, Any], bytes, str]:
    binding = preflight_value.get("inputManifest")
    require_exact_keys(
        binding,
        {"path", "sha256", "tokenIdsPath", "tokenIdsSHA256"},
        "preflight input-manifest binding",
    )
    require(
        binding["path"] == "input.json"
        and binding["tokenIdsPath"] == "input-token-ids.u32le",
        "preflight input paths differ",
    )
    manifest_path = preflight_path.parent / binding["path"]
    manifest = strict_json_file(manifest_path, "input token master manifest")
    digest = verify_digest_sidecar(manifest_path)
    require(
        digest == binding["sha256"]
        and manifest.get("schemaVersion") == INPUT_SCHEMA_VERSION_LENGTH
        and manifest.get("status")
        == "INPUT_TOKEN_MASTER_MATERIALIZED_NO_MODEL_INFERENCE"
        and manifest.get("classification") == LENGTH_CLASSIFICATION
        and manifest.get("countsTowardScientificVerdict") is False,
        "input token master manifest boundary differs",
    )
    require(
        manifest.get("codecSource") == preflight_value.get("codecSource")
        and manifest.get("assetReceiptSHA256")
        == preflight_value.get("assetReceiptSHA256"),
        "input token master codec or asset binding differs",
    )
    for name, expected in source_bindings().items():
        require(manifest.get(name) == expected, f"input manifest {name} differs")
    require(
        manifest.get("modelId") == LENGTH_MODEL_ID
        and manifest.get("adapterId") == LENGTH_ADAPTER_ID
        and manifest.get("workloadId") == LENGTH_WORKLOAD_ID,
        "input token master identity differs",
    )
    token_binding = manifest.get("tokenIds")
    require_exact_keys(
        token_binding,
        {"bytes", "count", "dtype", "path", "sha256"},
        "input token master file binding",
    )
    require(
        token_binding["path"] == binding["tokenIdsPath"]
        and token_binding["dtype"] == "uint32-little-endian"
        and token_binding["count"] == PREFILL_LEVELS[-1] + 1
        and token_binding["bytes"] == (PREFILL_LEVELS[-1] + 1) * 4
        and token_binding["sha256"] == binding["tokenIdsSHA256"],
        "input token master geometry differs",
    )
    token_path = preflight_path.parent / token_binding["path"]
    token_status = require_regular(token_path, "input token master file")
    token_raw = token_path.read_bytes()
    require(
        token_status.st_size == token_binding["bytes"]
        and sha256_bytes(token_raw) == token_binding["sha256"]
        and verify_digest_sidecar(token_path) == token_binding["sha256"],
        "input token master bytes differ",
    )
    return manifest, token_raw, digest


def _attempt_bindings(
    attempt: dict[str, Any],
    *,
    expected_status: str,
    preflight_path: Path,
    asset_digest: str,
    codec: dict[str, Any],
) -> None:
    preflight_value = strict_json_file(preflight_path, "attempt-bound preflight")
    input_binding = preflight_value.get("inputManifest")
    require(
        attempt.get("schemaVersion") == ATTEMPT_SCHEMA_VERSION_LENGTH
        and attempt.get("status") == expected_status
        and attempt.get("classification") == LENGTH_CLASSIFICATION
        and attempt.get("countsTowardScientificVerdict") is False
        and attempt.get("preflightSHA256") == sha256_file(preflight_path)
        and attempt.get("assetReceiptSHA256") == asset_digest
        and attempt.get("codecSource") == codec,
        "length-ladder attempt binding differs",
    )
    require_exact_keys(
        input_binding,
        {"path", "sha256", "tokenIdsPath", "tokenIdsSHA256"},
        "attempt-bound input manifest",
    )
    require(
        attempt.get("inputManifestSHA256") == input_binding["sha256"]
        and attempt.get("inputTokenMasterSHA256")
        == input_binding["tokenIdsSHA256"],
        "length-ladder attempt input-token master binding differs",
    )
    for name, expected in source_bindings().items():
        require(attempt.get(name) == expected, f"attempt {name} differs")


def _runtime(
    *,
    started_at: str,
    torch_module: Any,
    free_bytes: int,
    total_bytes: int,
    estimate: int,
    disk_free_bytes: int,
    disk_required_bytes: int,
    codec_manifest: dict[str, Any],
) -> dict[str, Any]:
    cgroup = BASE.cgroup_memory_observation()
    return {
        "startedAt": started_at,
        "completedAt": utc_now(),
        "python": platform.python_version(),
        "torch": torch_module.__version__,
        "cuda": torch_module.version.cuda,
        "gpuName": torch_module.cuda.get_device_name(0),
        "gpuDriverVersion": BASE.gpu_driver_version(),
        "gpuTotalBytes": total_bytes,
        "gpuFreeBytesBeforeCell": free_bytes,
        "memoryEstimateBytes": estimate,
        "peakAllocatedBytes": int(torch_module.cuda.max_memory_allocated()),
        "peakReservedBytes": int(torch_module.cuda.max_memory_reserved()),
        "peakRssBytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        * 1024,
        "diskFreeBytesBeforeCell": disk_free_bytes,
        "diskRequiredBytes": disk_required_bytes,
        "modelRequirementsLockSHA256": codec_manifest["files"][
            "RealLLM/requirements.lock"
        ]["sha256"],
        "pipBootstrapLockSHA256": codec_manifest["files"][
            ".github/locks/pip-bootstrap.txt"
        ]["sha256"],
        "portableRuntimeLockSHA256": codec_manifest["files"][
            ".github/locks/real-llm-linux-cpu-py312.txt"
        ]["sha256"],
        "cudaRuntimeLockSHA256": sha256_file(TORCH_LOCK_PATH),
        "packages": BASE.runtime_package_versions(),
        **cgroup,
        "dtype": "bfloat16",
        "attentionImplementation": "eager",
        "deterministicAlgorithms": True,
    }


def _resource_admission(
    cell_root: Path, profile: dict[str, Any], torch_module: Any
) -> tuple[int, int, int, int, int, int]:
    prefill = int(profile["maxPrefillTokens"])
    dense = (
        prefill
        * 2
        * int(profile["geometry"]["kvHeads"])
        * int(profile["geometry"]["headDimension"])
        * int(profile["geometry"]["layers"])
        * 2
    )
    weight = sum(
        int(asset["bytes"])
        for asset in profile["files"]
        if asset["path"].endswith((".safetensors", ".bin"))
    )
    estimate = weight + 6 * dense + 4 * 1024**3
    disk_required = max(8 * 1024**3, 12 * dense)
    disk_free = shutil.disk_usage(cell_root).free
    require(disk_free >= disk_required, "cell disk admission failed")
    free, total = torch_module.cuda.mem_get_info()
    hard = int(profile["gpuAdmission"]["maxGpuMemoryBytes"])
    require(
        estimate <= hard
        and estimate <= int(total * 0.80)
        and estimate <= int(free * 0.80),
        "cell GPU admission failed",
    )
    return dense, estimate, disk_required, disk_free, free, total


def _write_direct_evidence(
    cell_root: Path,
    profile: dict[str, Any],
    selected: list[int],
    material: dict[str, Any],
    raw_layers: list[bytes],
) -> tuple[dict[str, Any], dict[str, Any]]:
    token_raw = np.asarray(selected, dtype="<u4").tobytes()
    require(
        len(selected) == int(profile["maxPrefillTokens"]) + 1
        and sha256_bytes(token_raw) == material["tokenIdsU32LESHA256"],
        "selected-token byte binding differs",
    )
    token_path = cell_root / "selected-token-ids.u32le"
    exclusive_write(token_path, token_raw)
    raw_root = cell_root / "direct-raw"
    raw_root.mkdir(mode=0o700)
    prefill = int(profile["maxPrefillTokens"])
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_layers):
        require(len(raw) == prefill * columns * 2, "direct raw layer size differs")
        path = raw_root / f"layer-{index:03d}.bf16le"
        exclusive_write(path, raw)
        entries.append(
            {
                "layerIndex": index,
                "rows": prefill,
                "columns": columns,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "path": str(path.relative_to(cell_root)),
            }
        )
    return (
        {
            "bytes": len(token_raw),
            "count": len(selected),
            "dtype": "uint32-little-endian",
            "path": token_path.name,
            "sha256": sha256_bytes(token_raw),
        },
        {
            "canonicalCacheBF16SHA256": BASE.cache_digest(raw_layers),
            "layers": entries,
        },
    )


def _read_direct_raw(
    run_root: Path,
    level_id: str,
    profile: dict[str, Any],
    torch_module: Any,
    *,
    codec: dict[str, Any],
    asset_digest: str,
    expected_preflight: dict[str, Any],
    preflight_value: dict[str, Any],
) -> tuple[dict[str, Any], list[Any], list[bytes], bytes, str]:
    result_path = run_root / "cells" / level_id / "result.json"
    result = strict_json_file(result_path, f"direct result {level_id}")
    result_digest = verify_digest_sidecar(result_path)
    require(
        result.get("schemaVersion") == RESULT_SCHEMA_VERSION_LENGTH
        and result.get("status") == "COMPLETE"
        and result.get("lengthLevelId") == level_id
        and result.get("prefillTokens") == int(profile["maxPrefillTokens"]),
        "direct result identity differs",
    )
    require(
        result.get("classification") == LENGTH_CLASSIFICATION
        and result.get("countsTowardScientificVerdict") is False
        and result.get("codecSource") == codec
        and result.get("assetReceiptSHA256") == asset_digest,
        "direct result claim, codec, or asset binding differs",
    )
    require(
        result.get("inputManifestSHA256")
        == preflight_value["inputManifest"]["sha256"]
        and result.get("inputTokenMasterSHA256")
        == preflight_value["inputManifest"]["tokenIdsSHA256"],
        "direct result input-token master binding differs",
    )
    for name, expected_value in source_bindings().items():
        require(result.get(name) == expected_value, f"direct result {name} differs")
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
        "direct result model binding differs",
    )
    expected_workload = dict(expected_preflight)
    expected_workload.pop("lengthLevelId")
    require(result.get("workload") == expected_workload, "direct result workload differs")
    token_manifest = result.get("selectedTokenIds")
    require_exact_keys(
        token_manifest,
        {"bytes", "count", "dtype", "path", "sha256"},
        "direct selected token IDs",
    )
    token_path = result_path.parent / token_manifest["path"]
    require(
        token_manifest["path"] == "selected-token-ids.u32le"
        and token_manifest["count"] == int(profile["maxPrefillTokens"]) + 1
        and token_manifest["bytes"]
        == (int(profile["maxPrefillTokens"]) + 1) * 4
        and token_path.parent == result_path.parent
        and token_path.resolve(strict=True).is_relative_to(result_path.parent),
        "direct selected-token path or geometry differs",
    )
    token_status = require_regular(token_path, "direct selected token IDs")
    token_raw = token_path.read_bytes()
    require(
        token_manifest["dtype"] == "uint32-little-endian"
        and token_manifest["count"] == int(profile["maxPrefillTokens"]) + 1
        and token_manifest["bytes"] == len(token_raw) == token_status.st_size
        and token_manifest["sha256"] == sha256_bytes(token_raw)
        and token_manifest["sha256"]
        == result["workload"]["tokenIdsU32LESHA256"],
        "direct selected-token file differs",
    )
    raw_manifest = result.get("directRawEvidence")
    require_exact_keys(
        raw_manifest,
        {"canonicalCacheBF16SHA256", "layers"},
        "direct raw evidence",
    )
    entries = raw_manifest["layers"]
    require(
        isinstance(entries, list)
        and len(entries) == int(profile["geometry"]["layers"]),
        "direct raw layer count differs",
    )
    prefill = int(profile["maxPrefillTokens"])
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    matrices: list[Any] = []
    raws: list[bytes] = []
    for index, entry in enumerate(entries):
        require_exact_keys(
            entry,
            {"bytes", "columns", "layerIndex", "path", "rows", "sha256"},
            f"direct raw layer {index}",
        )
        require(
            entry["layerIndex"] == index
            and entry["rows"] == prefill
            and entry["columns"] == columns
            and entry["path"] == f"direct-raw/layer-{index:03d}.bf16le",
            "direct raw layer geometry differs",
        )
        path = result_path.parent / entry["path"]
        status = require_regular(path, f"direct raw layer {index}")
        raw = path.read_bytes()
        require(
            len(raw) == status.st_size == entry["bytes"] == prefill * columns * 2
            and sha256_bytes(raw) == entry["sha256"],
            "direct raw layer bytes differ",
        )
        words = np.frombuffer(raw, dtype="<u2").copy()
        matrix = (
            torch_module.from_numpy(words)
            .view(torch_module.bfloat16)
            .float()
            .reshape(prefill, columns)
            .numpy()
        )
        matrices.append(np.ascontiguousarray(matrix, dtype=np.float32))
        raws.append(raw)
    require(
        BASE.cache_digest(raws)
        == raw_manifest["canonicalCacheBF16SHA256"]
        == result["directCanonicalCacheBF16SHA256"],
        "direct raw whole-cache digest differs",
    )
    return result, matrices, raws, token_raw, result_digest


def run_cell(arguments: argparse.Namespace) -> int:
    started_at = utc_now()
    level_id = arguments.length_level
    prefill = level_prefill(level_id)
    profile = profile_for_length(prefill)
    preflight_value = load_preflight(arguments.preflight)
    expected = _preflight_cell(preflight_value, level_id)
    codec = validate_codec_root(arguments.codec_root)
    cache = BASE.safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_digest = verify_length_assets(arguments.assets, cache)
    run_root = BASE.safe_directory(arguments.run_dir, "run directory", create=False)
    cell_root = run_root / "cells" / level_id
    require(cell_root.is_dir() and cell_root == cell_root.resolve(), "cell root is unsafe")
    attempt = strict_json_file(cell_root / "attempt.json", "length cell attempt")
    verify_digest_sidecar(cell_root / "attempt.json")
    _attempt_bindings(
        attempt,
        expected_status="CELL_STARTED",
        preflight_path=arguments.preflight,
        asset_digest=asset_digest,
        codec=codec,
    )
    require(
        attempt.get("lengthLevelId") == level_id
        and attempt.get("prefillTokens") == prefill,
        "length cell attempt identity differs",
    )
    tokenizer, config, snapshot = BASE.load_tokenizer_and_config(profile, cache)
    selected, material = _workload_material(profile, tokenizer)
    expected_material = dict(expected)
    expected_material.pop("lengthLevelId")
    require(material == expected_material, "cell workload differs from preflight")
    _, input_token_raw, input_manifest_digest = _load_input_manifest(
        arguments.preflight, preflight_value
    )
    selected_raw = np.asarray(selected, dtype="<u4").tobytes()
    require(
        input_token_raw[: len(selected_raw)] == selected_raw,
        "cell selected tokens differ from materialized input-token master prefix",
    )
    sys.path.insert(0, str(arguments.codec_root.resolve()))
    torch_module = BASE.configure_torch()
    torch_module.cuda.reset_peak_memory_stats()
    dense_expected, estimate, disk_required, disk_free, free, total = _resource_admission(
        cell_root, profile, torch_module
    )
    model = BASE.load_model(profile, snapshot, config, torch_module)
    from transformers import DynamicCache

    prefix = torch_module.tensor(
        [selected[:prefill]], dtype=torch_module.long, device="cuda:0"
    )
    with torch_module.inference_mode():
        output = model(
            prefix,
            past_key_values=DynamicCache(config=model.config),
            use_cache=True,
            return_dict=True,
        )
    direct_cache = output.past_key_values
    require(int(direct_cache.get_seq_length()) == prefill, "direct prefill length differs")
    observation = BASE.cache_observation(direct_cache, profile, prefill)
    direct_matrices, direct_raws = BASE.extract_canonical_layers(
        direct_cache, profile, prefill, torch_module
    )
    last_prompt_token = int(selected[prefill])
    prompt = torch_module.tensor([[last_prompt_token]], dtype=torch_module.long, device="cuda:0")
    direct_logits, advanced = BASE.model_step(
        model, prompt, direct_cache, torch_module
    )
    rebuilt = BASE.dynamic_cache_from_layers(model, direct_matrices, profile, torch_module)
    rebuilt_logits, rebuilt_advanced = BASE.model_step(
        model, prompt, rebuilt, torch_module
    )
    structural_difference = float((direct_logits - rebuilt_logits).abs().max().item())
    structural_top1 = bool(
        torch_module.equal(direct_logits.argmax(dim=-1), rebuilt_logits.argmax(dim=-1))
    )
    require(
        structural_difference == 0.0 and structural_top1,
        "direct cache flatten/rebuild changed continuation",
    )
    del direct_cache, output, direct_logits, advanced, rebuilt, rebuilt_logits, rebuilt_advanced
    torch_module.cuda.empty_cache()
    selected_token_evidence, direct_raw_evidence = _write_direct_evidence(
        cell_root, profile, selected, material, direct_raws
    )
    direct_root = cell_root / "direct"
    direct_root.mkdir(mode=0o700)
    direct_reconstructed, direct_encoding = BASE.encode_layers(
        direct_matrices, profile, direct_root
    )
    require(
        direct_encoding["denseBF16Bytes"] == dense_expected,
        "length cell dense byte accounting differs",
    )
    behavior = BASE.controlled_metrics(
        model,
        tokenizer,
        direct_matrices,
        direct_reconstructed,
        profile,
        last_prompt_token,
        torch_module,
    )
    hard = int(profile["gpuAdmission"]["maxGpuMemoryBytes"])
    require(
        int(torch_module.cuda.max_memory_allocated()) <= hard
        and int(torch_module.cuda.max_memory_reserved()) <= hard,
        "length cell exceeded hard GPU limit",
    )
    result = {
        "schemaVersion": RESULT_SCHEMA_VERSION_LENGTH,
        "status": "COMPLETE",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "lengthLevelId": level_id,
        "prefillTokens": prefill,
        **source_bindings(),
        "codecSource": codec,
        "assetReceiptSHA256": asset_digest,
        "model": {
            "modelId": LENGTH_MODEL_ID,
            "adapterId": LENGTH_ADAPTER_ID,
            "profileId": LENGTH_PROFILE_ID,
            "repository": profile["repository"],
            "revision": profile["revision"],
            "geometry": profile["geometry"],
        },
        "workload": material,
        "inputManifestSHA256": input_manifest_digest,
        "inputTokenMasterSHA256": preflight_value["inputManifest"][
            "tokenIdsSHA256"
        ],
        "selectedTokenIds": selected_token_evidence,
        "cacheObservation": observation,
        "directCanonicalCacheBF16SHA256": BASE.cache_digest(direct_raws),
        "directRawEvidence": direct_raw_evidence,
        "directStructuralReplay": {
            "maxAbsLogitDifference": structural_difference,
            "top1Identical": structural_top1,
        },
        "directEncoding": direct_encoding,
        "directBehavior": behavior,
        "runtime": _runtime(
            started_at=started_at,
            torch_module=torch_module,
            free_bytes=free,
            total_bytes=total,
            estimate=estimate,
            disk_free_bytes=disk_free,
            disk_required_bytes=disk_required,
            codec_manifest=codec,
        ),
    }
    path = cell_root / "result.json"
    write_canonical_json(path, result)
    print(canonical_json_bytes({"status": "COMPLETE", "lengthLevelId": level_id, "resultSHA256": sha256_file(path)}).decode("utf-8"), flush=True)
    return 0


def run_secondary(arguments: argparse.Namespace) -> int:
    """Encode an exact P-row slice of the direct P=8192 cache without inference."""

    started_at = utc_now()
    level_id = arguments.length_level
    prefill = level_prefill(level_id)
    profile = profile_for_length(prefill)
    anchor_profile = profile_for_length(PREFILL_LEVELS[-1])
    preflight_value = load_preflight(arguments.preflight)
    codec = validate_codec_root(arguments.codec_root)
    cache = BASE.safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_digest = verify_length_assets(arguments.assets, cache)
    run_root = BASE.safe_directory(arguments.run_dir, "run directory", create=False)
    secondary_root = run_root / "secondary" / level_id
    require(
        secondary_root.is_dir() and secondary_root == secondary_root.resolve(),
        "secondary root is unsafe",
    )
    attempt = strict_json_file(secondary_root / "attempt.json", "secondary attempt")
    verify_digest_sidecar(secondary_root / "attempt.json")
    _attempt_bindings(
        attempt,
        expected_status="SECONDARY_STARTED",
        preflight_path=arguments.preflight,
        asset_digest=asset_digest,
        codec=codec,
    )
    require(
        attempt.get("lengthLevelId") == level_id
        and attempt.get("prefillTokens") == prefill,
        "secondary attempt identity differs",
    )
    sys.path.insert(0, str(arguments.codec_root.resolve()))
    import torch as torch_module

    target_result, target_matrices, target_raws, target_tokens, target_digest = (
        _read_direct_raw(
            run_root,
            level_id,
            profile,
            torch_module,
            codec=codec,
            asset_digest=asset_digest,
            expected_preflight=_preflight_cell(preflight_value, level_id),
            preflight_value=preflight_value,
        )
    )
    anchor_result, anchor_matrices, anchor_raws, anchor_tokens, anchor_digest = (
        _read_direct_raw(
            run_root,
            LEVEL_IDS[-1],
            anchor_profile,
            torch_module,
            codec=codec,
            asset_digest=asset_digest,
            expected_preflight=_preflight_cell(preflight_value, LEVEL_IDS[-1]),
            preflight_value=preflight_value,
        )
    )
    require(
        attempt.get("directResultSHA256") == target_digest
        and attempt.get("anchorDirectResultSHA256") == anchor_digest,
        "secondary attempt direct-result binding differs",
    )
    require(
        target_tokens == anchor_tokens[: len(target_tokens)],
        "direct selected-token file is not a prefix of the P=8192 token file",
    )
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    slice_layer_bytes = prefill * columns * 2
    master_matrices: list[Any] = []
    master_raws: list[bytes] = []
    slices: list[dict[str, Any]] = []
    differing_words = 0
    maximum_difference = 0.0
    for index, (anchor_matrix, anchor_raw, target_matrix, target_raw) in enumerate(
        zip(anchor_matrices, anchor_raws, target_matrices, target_raws)
    ):
        master_matrix = np.ascontiguousarray(anchor_matrix[:prefill], dtype=np.float32)
        master_raw = anchor_raw[:slice_layer_bytes]
        require(
            len(master_raw) == slice_layer_bytes,
            "P=8192 master raw layer slice is truncated",
        )
        master_matrices.append(master_matrix)
        master_raws.append(master_raw)
        direct_words = np.frombuffer(target_raw, dtype="<u2")
        master_words = np.frombuffer(master_raw, dtype="<u2")
        differing_words += int(np.count_nonzero(direct_words != master_words))
        maximum_difference = max(
            maximum_difference,
            float(np.max(np.abs(target_matrix - master_matrix), initial=0.0)),
        )
        slices.append(
            {
                "layerIndex": index,
                "bytes": len(master_raw),
                "sha256": sha256_bytes(master_raw),
                "anchorPath": anchor_result["directRawEvidence"]["layers"][index][
                    "path"
                ],
                "anchorSHA256": anchor_result["directRawEvidence"]["layers"][
                    index
                ]["sha256"],
            }
        )
    _, encoding = BASE.encode_layers(master_matrices, profile, secondary_root)
    dense_expected = prefill * columns * 2 * int(profile["geometry"]["layers"])
    require(
        encoding["denseBF16Bytes"] == dense_expected,
        "secondary dense byte accounting differs",
    )
    result = {
        "schemaVersion": SECONDARY_SCHEMA_VERSION_LENGTH,
        "status": "SECONDARY_COMPLETE",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "lengthLevelId": level_id,
        "prefillTokens": prefill,
        **source_bindings(),
        "codecSource": codec,
        "assetReceiptSHA256": asset_digest,
        "inputManifestSHA256": preflight_value["inputManifest"]["sha256"],
        "inputTokenMasterSHA256": preflight_value["inputManifest"][
            "tokenIdsSHA256"
        ],
        "directResultSHA256": target_digest,
        "anchorDirectResultSHA256": anchor_digest,
        "anchorLengthLevelId": LEVEL_IDS[-1],
        "anchorDirectCanonicalCacheBF16SHA256": anchor_result[
            "directCanonicalCacheBF16SHA256"
        ],
        "masterSliceCanonicalCacheBF16SHA256": BASE.cache_digest(master_raws),
        "sliceBindings": slices,
        "masterSliceEncoding": encoding,
        "directVersusMasterSlice": {
            "bitwiseIdentical": differing_words == 0,
            "differingBF16Words": differing_words,
            "totalBF16Words": dense_expected // 2,
            "maxAbsElementDifference": maximum_difference,
            "directCanonicalCacheBF16SHA256": target_result[
                "directCanonicalCacheBF16SHA256"
            ],
            "masterSliceCanonicalCacheBF16SHA256": BASE.cache_digest(master_raws),
        },
        "runtime": {
            "startedAt": started_at,
            "completedAt": utc_now(),
            "python": platform.python_version(),
            "torch": torch_module.__version__,
            "packages": BASE.runtime_package_versions(),
            "peakRssBytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            * 1024,
            "modelInferencePerformed": False,
            "gpuRequired": False,
        },
    }
    path = secondary_root / "result.json"
    write_canonical_json(path, result)
    print(
        canonical_json_bytes(
            {
                "status": "SECONDARY_COMPLETE",
                "lengthLevelId": level_id,
                "resultSHA256": sha256_file(path),
            }
        ).decode("utf-8"),
        flush=True,
    )
    return 0


def _record_process(
    *,
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_limit: int,
    result_path: Path,
    identity: dict[str, Any],
) -> dict[str, Any]:
    started = utc_now()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        returncode, timed_out = BASE.run_process_group(
            command,
            stdout=stdout,
            stderr=stderr,
            timeout_seconds=timeout_limit,
        )
    digest = sha256_file(result_path) if result_path.is_file() else None
    complete = returncode == 0 and digest is not None
    if timed_out:
        reason = "timeout"
    elif returncode == 125:
        reason = "process-group-residue"
    elif returncode < 0:
        reason = "signal"
    elif returncode != 0:
        reason = "nonzero-exit"
    elif digest is None:
        reason = "missing-result"
    else:
        reason = "completed"
    return {
        **identity,
        "startedAt": started,
        "completedAt": utc_now(),
        "returnCode": returncode,
        "exitSignal": -returncode if returncode < 0 else None,
        "timedOut": timed_out,
        "timeoutLimitSeconds": timeout_limit,
        "terminationReason": reason,
        "status": "COMPLETE" if complete else "EXECUTION_ERROR",
        "resultPath": str(result_path) if digest is not None else None,
        "resultSHA256": digest,
        "stdoutSHA256": sha256_file(stdout_path),
        "stderrSHA256": sha256_file(stderr_path),
    }


def orchestrate(arguments: argparse.Namespace) -> int:
    load_ladder()
    preflight_value = load_preflight(arguments.preflight)
    codec = validate_codec_root(arguments.codec_root)
    cache = BASE.safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_digest = verify_length_assets(arguments.assets, cache)
    require(preflight_value["codecSource"] == codec, "preflight codec differs")
    require(preflight_value["assetReceiptSHA256"] == asset_digest, "preflight assets differ")
    run_root = BASE.safe_directory(arguments.run_dir, "run directory", create=True)
    (run_root / "cells").mkdir(mode=0o700)
    (run_root / "secondary").mkdir(mode=0o700)
    (run_root / "logs").mkdir(mode=0o700)
    run_id = str(uuid.uuid4())
    python = str(Path(sys.executable).resolve())
    timeout_limit = int(selected_profile()["gpuAdmission"]["executionTimeoutSeconds"])
    require(
        timeout_limit == max(DIRECT_TIMEOUT_BY_LEVEL.values()),
        "direct timeout differs from selected profile",
    )
    common_attempt = {
        "schemaVersion": ATTEMPT_SCHEMA_VERSION_LENGTH,
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "adapterId": LENGTH_ADAPTER_ID,
        "runId": run_id,
        "codecSource": codec,
        "preflightSHA256": sha256_file(arguments.preflight),
        "assetReceiptSHA256": asset_digest,
        "inputManifestSHA256": preflight_value["inputManifest"]["sha256"],
        "inputTokenMasterSHA256": preflight_value["inputManifest"][
            "tokenIdsSHA256"
        ],
        **source_bindings(),
    }
    fixed_arguments = [
        "--codec-root", str(arguments.codec_root.resolve()),
        "--cache", str(arguments.cache.resolve()),
        "--assets", str(arguments.assets.resolve()),
        "--preflight", str(arguments.preflight.resolve()),
        "--run-dir", str(run_root),
    ]
    records: list[dict[str, Any]] = []
    for level_id in EXECUTION_LEVEL_IDS:
        prefill = level_prefill(level_id)
        direct_timeout = DIRECT_TIMEOUT_BY_LEVEL[level_id]
        cell_root = run_root / "cells" / level_id
        cell_root.mkdir(mode=0o700)
        write_canonical_json(
            cell_root / "attempt.json",
            {
                **common_attempt,
                "status": "CELL_STARTED",
                "attemptId": str(uuid.uuid4()),
                "startedAt": utc_now(),
                "lengthLevelId": level_id,
                "prefillTokens": prefill,
                "timeoutLimitSeconds": direct_timeout,
            },
        )
        record = _record_process(
            command=[python, "-E", "-s", "-B", str(Path(__file__).resolve()), "run-cell", *fixed_arguments, "--length-level", level_id],
            stdout_path=run_root / "logs" / f"{level_id}.stdout.log",
            stderr_path=run_root / "logs" / f"{level_id}.stderr.log",
            timeout_limit=direct_timeout,
            result_path=cell_root / "result.json",
            identity={"kind": "LENGTH_CELL", "lengthLevelId": level_id, "prefillTokens": prefill},
        )
        if record["resultPath"] is not None:
            record["resultPath"] = f"cells/{level_id}/result.json"
        records.append(record)
        print(f"CELL {level_id} {record['status']}", flush=True)
        gc.collect()
    direct_complete = all(record["status"] == "COMPLETE" for record in records)
    secondary_records: list[dict[str, Any]] = []
    if direct_complete:
        indexed_direct = {record["lengthLevelId"]: record for record in records}
        anchor_digest = indexed_direct[LEVEL_IDS[-1]]["resultSHA256"]
        require_digest(anchor_digest, "P=8192 direct result digest")
        for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS):
            secondary_root = run_root / "secondary" / level_id
            secondary_root.mkdir(mode=0o700)
            write_canonical_json(
                secondary_root / "attempt.json",
                {
                    **common_attempt,
                    "status": "SECONDARY_STARTED",
                    "attemptId": str(uuid.uuid4()),
                    "startedAt": utc_now(),
                    "lengthLevelId": level_id,
                    "prefillTokens": prefill,
                    "timeoutLimitSeconds": SECONDARY_TIMEOUT_SECONDS,
                    "anchorDirectResultSHA256": anchor_digest,
                    "directResultSHA256": indexed_direct[level_id]["resultSHA256"],
                },
            )
            secondary_record = _record_process(
                command=[
                    python,
                    "-E",
                    "-s",
                    "-B",
                    str(Path(__file__).resolve()),
                    "run-secondary",
                    *fixed_arguments,
                    "--length-level",
                    level_id,
                ],
                stdout_path=run_root / "logs" / f"secondary-{level_id}.stdout.log",
                stderr_path=run_root / "logs" / f"secondary-{level_id}.stderr.log",
                timeout_limit=SECONDARY_TIMEOUT_SECONDS,
                result_path=secondary_root / "result.json",
                identity={
                    "kind": "SECONDARY_CODEC_CONTROL",
                    "lengthLevelId": level_id,
                    "prefillTokens": prefill,
                },
            )
            if secondary_record["resultPath"] is not None:
                secondary_record["resultPath"] = (
                    f"secondary/{level_id}/result.json"
                )
            secondary_records.append(secondary_record)
            print(
                f"SECONDARY {level_id} {secondary_record['status']}", flush=True
            )
    secondary_complete = (
        len(secondary_records) == len(LEVEL_IDS)
        and all(record["status"] == "COMPLETE" for record in secondary_records)
    )
    complete = direct_complete and secondary_complete
    direct_points: list[dict[str, Any]] = []
    master_points: list[dict[str, Any]] = []
    if direct_complete:
        indexed_records = {record["lengthLevelId"]: record for record in records}
        require(set(indexed_records) == set(LEVEL_IDS), "completed cell identities differ")
        for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS):
            record = indexed_records[level_id]
            result_path = run_root / str(record["resultPath"])
            result = strict_json_file(result_path, "completed length result")
            require(
                verify_digest_sidecar(result_path) == record["resultSHA256"]
                and result.get("schemaVersion") == RESULT_SCHEMA_VERSION_LENGTH
                and result.get("status") == "COMPLETE"
                and result.get("lengthLevelId") == level_id
                and result.get("prefillTokens") == prefill,
                "completed direct result changed or has wrong identity",
            )
            identity = {
                "lengthLevelId": level_id,
                "prefillTokens": prefill,
            }
            direct_points.append(
                {
                    **identity,
                    "denseBF16Bytes": result["directEncoding"]["denseBF16Bytes"],
                    "containerBytes": result["directEncoding"]["containerBytes"],
                }
            )
    if secondary_complete:
        indexed_secondary = {
            record["lengthLevelId"]: record for record in secondary_records
        }
        for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS):
            record = indexed_secondary[level_id]
            result_path = run_root / str(record["resultPath"])
            result = strict_json_file(result_path, "completed secondary result")
            require(
                verify_digest_sidecar(result_path) == record["resultSHA256"]
                and result.get("schemaVersion") == SECONDARY_SCHEMA_VERSION_LENGTH
                and result.get("status") == "SECONDARY_COMPLETE"
                and result.get("lengthLevelId") == level_id
                and result.get("prefillTokens") == prefill,
                "completed secondary result changed or has wrong identity",
            )
            master_points.append(
                {
                    "lengthLevelId": level_id,
                    "prefillTokens": prefill,
                    "denseBF16Bytes": result["masterSliceEncoding"][
                        "denseBF16Bytes"
                    ],
                    "containerBytes": result["masterSliceEncoding"][
                        "containerBytes"
                    ],
                }
            )
    direct_analysis = length_analysis(direct_points) if direct_complete else None
    master_analysis = (
        length_analysis(master_points) if secondary_complete else None
    )
    direct_payload_points = [
        {
            "lengthLevelId": point["lengthLevelId"],
            "prefillTokens": point["prefillTokens"],
            "denseBF16Bytes": point["denseBF16Bytes"],
            "containerBytes": point["containerBytes"],
            "payloadBytes": strict_json_file(
                run_root / f"cells/{point['lengthLevelId']}/result.json",
                "direct payload source",
            )["directEncoding"]["payloadBytes"],
        }
        for point in direct_points
    ] if direct_complete else []
    secondary_payload_points = [
        {
            "lengthLevelId": point["lengthLevelId"],
            "prefillTokens": point["prefillTokens"],
            "denseBF16Bytes": point["denseBF16Bytes"],
            "containerBytes": point["containerBytes"],
            "payloadBytes": strict_json_file(
                run_root / f"secondary/{point['lengthLevelId']}/result.json",
                "secondary payload source",
            )["masterSliceEncoding"]["payloadBytes"],
        }
        for point in master_points
    ] if secondary_complete else []
    run = {
        "schemaVersion": RUN_SCHEMA_VERSION_LENGTH,
        "runId": run_id,
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "classification": LENGTH_CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        **source_bindings(),
        "codecSource": codec,
        "preflightSHA256": sha256_file(arguments.preflight),
        "assetReceiptSHA256": asset_digest,
        "expectedCells": 6,
        "completeCells": sum(record["status"] == "COMPLETE" for record in records),
        "expectedSecondaryControls": 6,
        "completeSecondaryControls": sum(
            record["status"] == "COMPLETE" for record in secondary_records
        ),
        "cells": records,
        "secondaryControls": secondary_records,
        "executionOrder": list(EXECUTION_LEVEL_IDS),
        "analysisOrder": list(LEVEL_IDS),
        "directPrimaryAnalysis": direct_analysis,
        "masterSliceSecondaryAnalysis": master_analysis,
        "directPayloadOnlyDiagnostic": payload_analysis(direct_payload_points)
        if direct_complete
        else None,
        "masterSlicePayloadOnlyDiagnostic": payload_analysis(
            secondary_payload_points
        )
        if secondary_complete
        else None,
        "supportDecision": support_decision(
            complete=complete, primary_analysis=direct_analysis
        ),
    }
    write_canonical_json(run_root / "run.json", run)
    print(canonical_json_bytes(run).decode("utf-8"), flush=True)
    return 0 if complete else 1


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--codec-root", type=Path, required=True)
    preflight_parser.add_argument("--cache", type=Path, required=True)
    preflight_parser.add_argument("--assets", type=Path, required=True)
    preflight_parser.add_argument("--output", type=Path, required=True)
    for name in ("orchestrate", "run-cell", "run-secondary"):
        command = commands.add_parser(name)
        command.add_argument("--codec-root", type=Path, required=True)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--assets", type=Path, required=True)
        command.add_argument("--preflight", type=Path, required=True)
        command.add_argument("--run-dir", type=Path, required=True)
        if name in {"run-cell", "run-secondary"}:
            command.add_argument("--length-level", choices=LEVEL_IDS, required=True)
    return parser.parse_args()


def main() -> int:
    global np
    arguments = parse_arguments()
    import numpy as numpy_module

    np = numpy_module
    BASE.np = numpy_module
    if arguments.command == "preflight":
        return preflight(arguments)
    if arguments.command == "orchestrate":
        return orchestrate(arguments)
    if arguments.command == "run-cell":
        return run_cell(arguments)
    if arguments.command == "run-secondary":
        return run_secondary(arguments)
    raise AssertionError(arguments.command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"LENGTH LADDER FAIL: {error}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        raise SystemExit(1)
