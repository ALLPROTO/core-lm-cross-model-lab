#!/usr/bin/env python3
"""Fail-closed primitives for the single-model RunPod length ladder."""

from __future__ import annotations

import copy
import importlib.util
import math
import os
import stat
import sys
from pathlib import Path
from typing import Any


LENGTH_SUITE_ROOT = Path(__file__).resolve().parent
ADAPTER_SUITE_ROOT = LENGTH_SUITE_ROOT.parent / "runpod-adapter-sweep-v1"
_BASE_COMMON_PATH = ADAPTER_SUITE_ROOT / "common.py"
_SPEC = importlib.util.spec_from_file_location(
    "_corelm_runpod_adapter_common_v1", _BASE_COMMON_PATH
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load the pinned adapter-sweep common module")
_BASE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BASE
_SPEC.loader.exec_module(_BASE)

# Re-export the already reviewed source/asset/codec/JSON primitives. Keep their
# own SUITE_ROOT and manifest paths: this contour binds to, rather than copies,
# the selected adapter-sweep profile and workload.
for _NAME in dir(_BASE):
    if not _NAME.startswith("__"):
        globals()[_NAME] = getattr(_BASE, _NAME)


LADDER_PATH = LENGTH_SUITE_ROOT / "ladder.json"
LENGTH_PROTOCOL_PATH = LENGTH_SUITE_ROOT / "PROTOCOL.md"

REGISTRATION_SCHEMA_VERSION = "corelm-runpod-length-ladder-registration-v1"
ASSET_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-assets-v1"
PREFLIGHT_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-preflight-v1"
INPUT_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-input-v1"
ATTEMPT_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-cell-attempt-v1"
RESULT_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-cell-v1"
SECONDARY_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-secondary-v1"
RUN_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-run-v1"
VERIFY_SCHEMA_VERSION_LENGTH = (
    "corelm-runpod-length-ladder-structural-verification-v1"
)
REPLAY_SCHEMA_VERSION_LENGTH = "corelm-runpod-length-ladder-cell-replay-v1"

LENGTH_CLASSIFICATION = "PREREGISTERED_PUBLIC_LENGTH_LADDER_ONLY"
LENGTH_MODEL_ID = "qwen2.5-0.5b"
LENGTH_ADAPTER_ID = "qwen2-dynamic-cache-v1"
LENGTH_PROFILE_ID = "qwen2.5-0.5b-runpod-sweep-v1"
LENGTH_WORKLOAD_ID = "tracked-technical-prose-v1"
LENGTH_CONTENT_CLASS = "technical-prose"
PREFILL_LEVELS = (256, 512, 1024, 2048, 4096, 8192)
LEVEL_IDS = tuple(f"p{value:06d}" for value in PREFILL_LEVELS)
LEVEL_BY_ID = dict(zip(LEVEL_IDS, PREFILL_LEVELS))
EXECUTION_LEVEL_IDS = (
    "p004096",
    "p000512",
    "p008192",
    "p000256",
    "p001024",
    "p002048",
)
DIRECT_TIMEOUT_BY_LEVEL = {
    "p000256": 600,
    "p000512": 600,
    "p001024": 600,
    "p002048": 600,
    "p004096": 900,
    "p008192": 1350,
}
SECONDARY_TIMEOUT_SECONDS = 300


def profile_object_sha256(profile: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(profile))


def selected_profile() -> dict[str, Any]:
    profile = profile_by_id(LENGTH_MODEL_ID)
    require(
        profile["profileId"] == LENGTH_PROFILE_ID
        and profile["adapterId"] == LENGTH_ADAPTER_ID
        and profile["maxPrefillTokens"] == PREFILL_LEVELS[-1],
        "selected upstream profile identity or maximum prefill differs",
    )
    require(
        profile["cachePolicy"]
        == {"kind": "full-context-dynamic-cache", "slidingWindowEnabled": False},
        "selected profile is not a full-context dynamic cache",
    )
    return profile


def profile_for_length(prefill_tokens: int) -> dict[str, Any]:
    require(
        type(prefill_tokens) is int and prefill_tokens in PREFILL_LEVELS,
        "prefill length is not registered",
    )
    profile = copy.deepcopy(selected_profile())
    profile["maxPrefillTokens"] = prefill_tokens
    return profile


def selected_workload() -> dict[str, Any]:
    matches = [
        entry
        for entry in load_workloads()["workloads"]
        if entry["workloadId"] == LENGTH_WORKLOAD_ID
    ]
    require(len(matches) == 1, "selected upstream workload is absent or duplicated")
    workload = matches[0]
    require(
        workload["contentClass"] == LENGTH_CONTENT_CLASS,
        "selected upstream workload content class differs",
    )
    return workload


def load_ladder() -> dict[str, Any]:
    value = strict_json_file(LADDER_PATH, "length ladder registration", canonical=False)
    require_exact_keys(
        value,
        {
            "analysis",
            "classification",
            "codecConfiguration",
            "executionOrder",
            "horizonTokens",
            "hardwarePolicy",
            "isolation",
            "lengths",
            "masterCache",
            "model",
            "priorKnowledge",
            "scientificEvidence",
            "schemaVersion",
            "selection",
            "series",
            "sourceBinding",
            "supportDecision",
            "timeoutPolicy",
            "workload",
        },
        "length ladder registration",
    )
    require(
        value["schemaVersion"] == REGISTRATION_SCHEMA_VERSION,
        "length ladder registration schema differs",
    )
    require(
        value["classification"] == LENGTH_CLASSIFICATION
        and value["scientificEvidence"] is False,
        "length ladder claim boundary differs",
    )
    require(value["horizonTokens"] == HORIZON, "length ladder horizon differs")
    require(
        value["hardwarePolicy"]
        == {
            "cpuLogicalMinimum": 8,
            "gpuCount": 1,
            "gpuMemoryMiBMinimum": 40960,
            "gpuRuntime": "nvidia-cuda-bf16",
            "hostMemoryGiBMinimum": 32,
            "identityRequirement": "exact-device-and-driver-fixed-and-recorded-within-attempt",
            "scope": "suite-specific-single-qwen-operational-envelope",
            "upstreamMatrixWideExecutionPolicyApplies": False,
        },
        "length ladder hardware policy differs",
    )
    require(
        value["codecConfiguration"]
        == "normalized-layer-0-and-one-third-9bit-rest-8bit-v1",
        "length ladder codec schedule differs",
    )
    require(
        value["model"]
        == {
            "adapterId": LENGTH_ADAPTER_ID,
            "modelId": LENGTH_MODEL_ID,
            "profileId": LENGTH_PROFILE_ID,
        },
        "length ladder model identity differs",
    )
    require(
        value["priorKnowledge"]
        == {
            "artifactPath": "runpod-adapter-sweep-v1/recorded-runs/2026-08-12-attempt-04",
            "recordSHA256": "5d1d65f310387d0e438ba6ff000646c966e08528ab21b2e55076355dd71a89a7",
            "selectedResultSHA256": "a15c73d5e868b60da11d363481ad14eafe089ec4434448ca28eb7fd622e78802",
            "priorPromptAndTokenIdsDifferFromCurrentSourceTree": True,
            "sameModelWorkloadDefinitionAndLengthOutcomeKnownBeforeDesign": True,
            "selectedTuplePrefillTokens": 8192,
            "usePolicy": "disclose-only-current-source-tree-six-points-unknown-fresh-recompute-no-imported-result-bytes-or-metrics",
        },
        "length ladder prior-knowledge disclosure differs",
    )
    prior_record = (
        LAB_ROOT
        / value["priorKnowledge"]["artifactPath"]
        / "record.json"
    )
    require_regular(prior_record, "prior public recorded-run manifest")
    require(
        sha256_file(prior_record) == value["priorKnowledge"]["recordSHA256"],
        "prior public recorded-run digest differs",
    )
    prior_value = strict_json_file(prior_record, "prior public recorded-run manifest")
    prior_rows = prior_value.get("matrix", {}).get("rows")
    require(isinstance(prior_rows, list), "prior public recorded-run rows are absent")
    matching_prior = [
        row
        for row in prior_rows
        if isinstance(row, dict)
        and row.get("modelId") == LENGTH_MODEL_ID
        and row.get("workloadId") == LENGTH_WORKLOAD_ID
        and row.get("prefillTokens") == PREFILL_LEVELS[-1]
    ]
    require(
        len(matching_prior) == 1
        and matching_prior[0].get("resultSHA256")
        == value["priorKnowledge"]["selectedResultSHA256"],
        "prior public selected-result binding differs",
    )
    require(
        value["workload"]
        == {
            "contentClass": LENGTH_CONTENT_CLASS,
            "workloadId": LENGTH_WORKLOAD_ID,
        },
        "length ladder workload identity differs",
    )
    require(
        value["lengths"]
        == [
            {"levelId": level_id, "prefillTokens": prefill}
            for level_id, prefill in zip(LEVEL_IDS, PREFILL_LEVELS)
        ],
        "length ladder must contain exactly the six registered levels",
    )
    require(
        value["executionOrder"] == list(EXECUTION_LEVEL_IDS),
        "length ladder execution order differs",
    )
    require(
        value["selection"]
        == {
            "addSpecialTokens": False,
            "nestedPrefixes": True,
            "promptFinalInputTokens": 1,
            "selectedTokenRange": "first-prefillTokens-plus-one",
            "truncation": False,
        },
        "length ladder token selection differs",
    )
    require(
        value["sourceBinding"]
        == {
            "allowWorkingTreeBytes": False,
            "requireCleanCheckout": True,
            "revision": "HEAD",
            "trackedBlobSource": "git-object-database",
            "tree": "HEAD^{tree}",
        },
        "length ladder source binding differs",
    )
    require(
        value["isolation"]
        == {
            "freshModelLoadPerCell": True,
            "freshOperatingSystemProcessPerCell": True,
            "masterCacheSource": "registered-primary-direct-cell-p008192",
            "primaryStateReuseAcrossLengths": False,
            "secondaryControlProcesses": "post-direct-codec-only-fresh-process-per-length",
            "secondaryControlStateReuseAcrossLengths": "verified-immutable-p008192-direct-bf16-prefix-bytes-only",
        },
        "length ladder isolation differs",
    )
    require(
        value["masterCache"]
        == {
            "canonicalDtype": "bfloat16-little-endian",
            "masterPrefillTokens": 8192,
            "role": "secondary-codec-length-control-and-direct-prefix-diagnostic",
            "sliceRule": "first-P-rows-of-every-canonical-master-layer",
            "sourceLevelId": "p008192",
            "sourceSeries": "primary-direct",
        },
        "length ladder master-cache contract differs",
    )
    require(
        value["series"]
        == {
            "primary": "fresh-direct-prefill-cache-at-each-P",
            "secondary": "exact-prefix-slices-of-one-8192-token-master-cache",
        },
        "length ladder series roles differ",
    )
    require(
        value["supportDecision"]
        == {
            "indeterminatePrecedence": True,
            "noPositiveSupport": "complete-and-endpoint-direct-ratio-does-not-increase-with-equal-or-decrease-subtype",
            "onePercentMaterialityRole": "reported-separately-never-changes-support-class",
            "strongDirectionalSupport": "complete-and-all-five-adjacent-direct-ratios-strictly-increase",
            "weakDirectionalSupport": "complete-and-endpoint-direct-ratio-increases-but-at-least-one-adjacent-direct-ratio-does-not-strictly-increase",
        },
        "length ladder support decision differs",
    )
    require(
        value["timeoutPolicy"]
        == {
            "directSecondsByLevel": DIRECT_TIMEOUT_BY_LEVEL,
            "failurePolicy": "visible-incomplete-no-silent-retry-within-attempt",
            "profileExecutionTimeoutSecondsIsMaximum": 1350,
            "secondarySecondsPerLevel": SECONDARY_TIMEOUT_SECONDS,
        },
        "length ladder timeout policy differs",
    )
    require(
        value["analysis"]
        == {
            "aggregation": "within-exact-model-workload-codec-only",
            "decisionArithmetic": "exact-integer-cross-products",
            "endpointCriterion": "directDense8192*directContainer256-directDense256*directContainer8192>0",
            "primaryCriterion": "all-five-adjacent-direct-prefill-exact-cross-product-numerators-are-strictly-positive",
            "ratioDefinition": "complete-dense-bf16-cache-bytes-divided-by-complete-container-bytes",
            "statisticalInference": "none-deterministic-single-execution-per-registered-length",
            "trendClaimScope": "registered-nested-prefixes-only",
        },
        "length ladder analysis contract differs",
    )
    selected_profile()
    selected_workload()
    return value


def level_prefill(level_id: str) -> int:
    require(
        isinstance(level_id, str) and level_id in LEVEL_BY_ID,
        "unknown length level ID",
    )
    return LEVEL_BY_ID[level_id]


def _private_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    require(
        absolute.is_dir() and not absolute.is_symlink(), f"{label} is not a directory"
    )
    require(absolute == absolute.resolve(), f"{label} traverses a symlink")
    status = absolute.stat()
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is not private")
    return absolute


def verify_length_assets(
    receipt_path: Path, cache_root: Path
) -> tuple[dict[str, Any], str]:
    """Verify the closed Qwen-only cache and its canonical receipt."""

    profile = selected_profile()
    cache = _private_directory(cache_root, "length-ladder asset cache")
    receipt = strict_json_file(receipt_path, "length-ladder asset receipt")
    require_exact_keys(
        receipt,
        {
            "files",
            "modelId",
            "profileObjectSHA256",
            "repository",
            "revision",
            "schemaVersion",
            "sourceProfilesSHA256",
            "status",
        },
        "length-ladder asset receipt",
    )
    require(
        receipt["schemaVersion"] == ASSET_SCHEMA_VERSION_LENGTH
        and receipt["status"] == "ASSETS_VERIFIED",
        "length-ladder asset receipt status or schema differs",
    )
    require(
        (
            receipt["modelId"],
            receipt["repository"],
            receipt["revision"],
        )
        == (profile["modelId"], profile["repository"], profile["revision"]),
        "length-ladder asset identity differs",
    )
    require(
        receipt["sourceProfilesSHA256"] == sha256_file(PROFILES_PATH)
        and receipt["profileObjectSHA256"] == profile_object_sha256(profile),
        "length-ladder asset profile binding differs",
    )
    snapshot = cache / LENGTH_MODEL_ID
    require(
        snapshot.parent == cache
        and snapshot.is_dir()
        and not snapshot.is_symlink()
        and snapshot == snapshot.resolve(),
        "length-ladder asset snapshot is unsafe",
    )
    snapshot_status = snapshot.stat()
    require(
        snapshot_status.st_uid == os.getuid()
        and snapshot_status.st_mode & 0o077 == 0,
        "length-ladder asset snapshot is not private and owner controlled",
    )
    recorded_files = receipt["files"]
    require(
        isinstance(recorded_files, list)
        and len(recorded_files) == len(profile["files"]),
        "length-ladder asset receipt file count differs",
    )
    expected_paths: set[str] = set()
    for asset, recorded in zip(profile["files"], recorded_files):
        require_exact_keys(
            recorded, {"bytes", "path", "sha256"}, "length-ladder asset file"
        )
        relative = asset["path"]
        expected_paths.add(relative)
        path = snapshot / relative
        status = require_regular(path, f"length-ladder asset {relative}")
        require(
            path.resolve(strict=True).is_relative_to(snapshot)
            and status.st_uid == os.getuid()
            and status.st_nlink == 1
            and status.st_mode & 0o022 == 0,
            f"length-ladder asset is unsafe: {relative}",
        )
        observed_sha256 = sha256_file(path)
        require(
            recorded
            == {
                "bytes": int(asset["bytes"]),
                "path": relative,
                "sha256": observed_sha256,
            }
            and status.st_size == int(asset["bytes"])
            and observed_sha256 == asset["sha256"],
            f"length-ladder asset binding differs: {relative}",
        )
    actual_paths: set[str] = set()
    for candidate in snapshot.rglob("*"):
        status = candidate.lstat()
        require(not stat.S_ISLNK(status.st_mode), "asset snapshot contains a symlink")
        require(status.st_uid == os.getuid(), "asset snapshot has foreign ownership")
        if stat.S_ISDIR(status.st_mode):
            require(status.st_mode & 0o077 == 0, "asset directory is not private")
        elif stat.S_ISREG(status.st_mode):
            require(
                status.st_nlink == 1 and status.st_mode & 0o022 == 0,
                "asset file is linked or writable by another user",
            )
            actual_paths.add(candidate.relative_to(snapshot).as_posix())
        else:
            fail("asset snapshot contains a special file")
    require(actual_paths == expected_paths, "asset snapshot has missing or extra files")
    root_entries = {entry.name for entry in cache.iterdir()}
    require(
        root_entries == {LENGTH_MODEL_ID},
        "length-ladder cache must contain only the selected model snapshot",
    )
    return receipt, verify_digest_sidecar(receipt_path)


def length_analysis(points: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute the registered descriptive ladder analysis."""

    require(isinstance(points, list) and len(points) == 6, "analysis needs six points")
    normalized: list[dict[str, Any]] = []
    for position, (point, level_id, prefill) in enumerate(
        zip(points, LEVEL_IDS, PREFILL_LEVELS)
    ):
        require_exact_keys(
            point,
            {
                "containerBytes",
                "denseBF16Bytes",
                "lengthLevelId",
                "prefillTokens",
            },
            f"analysis point {position}",
        )
        dense = require_int(point["denseBF16Bytes"], "analysis dense bytes", 1)
        container = require_int(
            point["containerBytes"], "analysis container bytes", 1
        )
        require(
            point["lengthLevelId"] == level_id
            and point["prefillTokens"] == prefill,
            f"analysis point {position} identity differs",
        )
        ratio = dense / container
        require(math.isfinite(ratio) and ratio > 0, "analysis ratio is invalid")
        normalized.append(
            {
                "lengthLevelId": level_id,
                "prefillTokens": prefill,
                "denseBF16Bytes": dense,
                "containerBytes": container,
                "compressionRatio": ratio,
            }
        )
    adjacent: list[dict[str, Any]] = []
    for left, right in zip(normalized, normalized[1:]):
        delta = right["compressionRatio"] - left["compressionRatio"]
        exact_numerator = (
            right["denseBF16Bytes"] * left["containerBytes"]
            - left["denseBF16Bytes"] * right["containerBytes"]
        )
        adjacent.append(
            {
                "fromLengthLevelId": left["lengthLevelId"],
                "toLengthLevelId": right["lengthLevelId"],
                "deltaPrefillTokens": right["prefillTokens"]
                - left["prefillTokens"],
                "descriptiveDeltaCompressionRatio": delta,
                "exactCrossProductNumeratorDecimal": str(exact_numerator),
                "strictlyIncreasing": exact_numerator > 0,
                "nondecreasing": exact_numerator >= 0,
            }
        )
    endpoint_delta = (
        normalized[-1]["compressionRatio"] - normalized[0]["compressionRatio"]
    )
    endpoint_numerator = (
        normalized[-1]["denseBF16Bytes"] * normalized[0]["containerBytes"]
        - normalized[0]["denseBF16Bytes"] * normalized[-1]["containerBytes"]
    )
    endpoint_one_percent_numerator = (
        100
        * normalized[-1]["denseBF16Bytes"]
        * normalized[0]["containerBytes"]
        - 101
        * normalized[0]["denseBF16Bytes"]
        * normalized[-1]["containerBytes"]
    )
    return {
        "ratioDefinition": "complete-dense-bf16-cache-bytes-divided-by-complete-container-bytes",
        "decisionArithmetic": "exact-integer-cross-products",
        "points": normalized,
        "adjacentComparisons": adjacent,
        "primaryAllAdjacentStrictlyIncreasing": all(
            entry["strictlyIncreasing"] for entry in adjacent
        ),
        "allAdjacentNondecreasing": all(
            entry["nondecreasing"] for entry in adjacent
        ),
        "endpointDescriptiveDeltaCompressionRatio": endpoint_delta,
        "endpointExactCrossProductNumeratorDecimal": str(endpoint_numerator),
        "endpointIncreasing": endpoint_numerator > 0,
        "endpointOnePercentMaterialityNumeratorDecimal": str(
            endpoint_one_percent_numerator
        ),
        "endpointRelativeIncreaseAtLeastOnePercent": endpoint_one_percent_numerator
        >= 0,
        "statisticalInferencePerformed": False,
    }


def support_decision(*, complete: bool, primary_analysis: dict[str, Any] | None) -> str:
    """Apply the registered four-state decision with indeterminate precedence."""

    if not complete or primary_analysis is None:
        return "INDETERMINATE"
    endpoint = primary_analysis.get("endpointIncreasing")
    monotone = primary_analysis.get("primaryAllAdjacentStrictlyIncreasing")
    require(type(endpoint) is bool and type(monotone) is bool, "analysis decision fields differ")
    if monotone:
        return "STRONG_DIRECTIONAL_SUPPORT"
    if endpoint:
        return "WEAK_DIRECTIONAL_SUPPORT"
    numerator = int(primary_analysis["endpointExactCrossProductNumeratorDecimal"])
    return "NO_POSITIVE_SUPPORT_EQUAL" if numerator == 0 else "NO_POSITIVE_SUPPORT_DECREASE"


def payload_analysis(points: list[dict[str, Any]]) -> dict[str, Any]:
    """Secondary payload-only diagnostic; never controls the support class."""

    require(isinstance(points, list) and len(points) == 6, "payload analysis needs six points")
    normalized: list[dict[str, Any]] = []
    for point, level_id, prefill in zip(points, LEVEL_IDS, PREFILL_LEVELS):
        require_exact_keys(
            point,
            {"containerBytes", "denseBF16Bytes", "lengthLevelId", "payloadBytes", "prefillTokens"},
            "payload analysis point",
        )
        dense = require_int(point["denseBF16Bytes"], "payload dense bytes", 1)
        payload = require_int(point["payloadBytes"], "payload bytes", 1)
        container = require_int(point["containerBytes"], "container bytes", payload)
        require(point["lengthLevelId"] == level_id and point["prefillTokens"] == prefill, "payload point identity differs")
        normalized.append({
            "lengthLevelId": level_id, "prefillTokens": prefill,
            "denseBF16Bytes": dense, "payloadBytes": payload, "containerBytes": container,
            "containerOverheadBytes": container - payload,
            "containerBytesPerPrefillToken": container / prefill,
            "payloadBytesPerPrefillToken": payload / prefill,
            "payloadOnlyCompressionRatio": dense / payload,
        })
    comparisons: list[dict[str, Any]] = []
    for left, right in zip(normalized, normalized[1:]):
        numerator = right["denseBF16Bytes"] * left["payloadBytes"] - left["denseBF16Bytes"] * right["payloadBytes"]
        comparisons.append({
            "fromLengthLevelId": left["lengthLevelId"], "toLengthLevelId": right["lengthLevelId"],
            "exactPayloadCrossProductNumeratorDecimal": str(numerator),
            "payloadRatioStrictlyIncreasing": numerator > 0,
        })
    first, last = normalized[0], normalized[-1]
    endpoint = last["denseBF16Bytes"] * first["payloadBytes"] - first["denseBF16Bytes"] * last["payloadBytes"]
    material = 100 * last["denseBF16Bytes"] * first["payloadBytes"] - 101 * first["denseBF16Bytes"] * last["payloadBytes"]
    return {
        "role": "secondary-payload-only-header-amortization-diagnostic-never-controls-support-decision",
        "points": normalized, "adjacentComparisons": comparisons,
        "endpointExactPayloadCrossProductNumeratorDecimal": str(endpoint),
        "endpointPayloadRatioIncreasing": endpoint > 0,
        "endpointOnePercentPayloadMaterialityNumeratorDecimal": str(material),
        "endpointPayloadRelativeIncreaseAtLeastOnePercent": material >= 0,
    }
