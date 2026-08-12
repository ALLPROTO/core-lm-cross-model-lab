#!/usr/bin/env python3
"""Independently verify and replay the RunPod adapter sweep evidence."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn


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
    ATTEMPT_SCHEMA_VERSION,
    CLASSIFICATION,
    EXPECTED_CODEC_FILES,
    HORIZON,
    LAB_ROOT,
    MODEL_ORDER,
    PROFILES_PATH,
    PROTOCOL_PATH,
    RESULT_SCHEMA_VERSION,
    RUN_SCHEMA_VERSION,
    TORCH_LOCK_PATH,
    WORKLOADS_PATH,
    canonical_json_bytes,
    command_output,
    configuration_for_profile,
    configuration_sha256,
    git_blob_sha1,
    load_profiles,
    load_workloads,
    profile_by_id,
    require,
    require_digest,
    require_int,
    require_number,
    require_regular,
    sha256_bytes,
    sha256_file,
    strict_json_file,
    validate_codec_root,
    verify_asset_receipt,
    write_canonical_json,
    workload_text,
)


np: Any = None


PREFLIGHT_SCHEMA = "corelm-runpod-adapter-preflight-v1"
VERIFY_SCHEMA = "corelm-runpod-adapter-structural-verification-v1"
REPLAY_SCHEMA = "corelm-runpod-adapter-cell-replay-v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_CONTAINER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_CONTAINER_BYTES = 16 * 1024 * 1024 * 1024
MAX_CONTINUATION_CHARACTERS = 4 * 1024 * 1024
FLOAT_ABSOLUTE_TOLERANCE = 2e-5
FLOAT_RELATIVE_TOLERANCE = 2e-6
UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON number is forbidden: {value}")


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    observed = set(value)
    if observed != keys:
        _fail(
            f"{label} keys differ: missing={sorted(keys-observed)}, "
            f"extra={sorted(observed-keys)}"
        )
    return value


def _bounded_json(path: Path, label: str) -> dict[str, Any]:
    status = require_regular(path, label)
    require(0 < status.st_size <= MAX_JSON_BYTES, f"{label} exceeds its bound")
    value = strict_json_file(path, label)
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def _safe_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    require(absolute.is_dir(), f"{label} is not a directory")
    require(not absolute.is_symlink(), f"{label} is a symlink")
    require(absolute == absolute.resolve(), f"{label} traverses a symlink")
    status = absolute.stat()
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is not private")
    return absolute


def _safe_descendant(root: Path, relative: str, label: str) -> Path:
    pure = PurePosixPath(relative)
    require(
        relative == pure.as_posix()
        and not pure.is_absolute()
        and relative not in {"", "."}
        and ".." not in pure.parts,
        f"{label} path is unsafe",
    )
    current = root
    for component in pure.parts[:-1]:
        current = current / component
        require(current.is_dir() and not current.is_symlink(), f"{label} parent is unsafe")
    candidate = root.joinpath(*pure.parts)
    require_regular(candidate, label)
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} escapes its root") from error
    return candidate


def _verify_sidecar(path: Path) -> str:
    require_regular(path, path.name)
    digest = sha256_file(path)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    status = require_regular(sidecar, f"{path.name} digest sidecar")
    require(status.st_size < 1024, "digest sidecar exceeds its bound")
    expected = f"{digest}  {path.name}\n".encode("ascii")
    require(sidecar.read_bytes() == expected, f"{path.name} digest sidecar differs")
    return digest


def _timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value), f"{label} is not canonical UTC")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is not a valid UTC timestamp") from error


def _finite(value: Any, label: str) -> float:
    result = require_number(value, label)
    require(math.isfinite(result), f"{label} is not finite")
    return result


def _close(observed: Any, expected: Any, label: str) -> None:
    left = _finite(observed, f"observed {label}")
    right = _finite(expected, f"recorded {label}")
    require(
        math.isclose(
            left,
            right,
            rel_tol=FLOAT_RELATIVE_TOLERANCE,
            abs_tol=FLOAT_ABSOLUTE_TOLERANCE,
        ),
        f"{label} differs: observed={left!r}, recorded={right!r}",
    )


def _source_identity() -> dict[str, Any]:
    root = LAB_ROOT.resolve()
    require(root == LAB_ROOT.absolute(), "lab root traverses a symlink")
    require(
        command_output(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
            ],
            root,
        )
        == "",
        "lab checkout must be completely clean for verification",
    )
    require(
        command_output(["git", "rev-parse", "--is-shallow-repository"], root)
        == "false",
        "lab checkout is shallow",
    )
    require(not (root / ".git/shallow").exists(), "lab checkout has shallow metadata")
    require(not (root / ".git/info/grafts").exists(), "lab checkout has grafts")
    require(
        command_output(
            ["git", "for-each-ref", "--format=%(refname)", "refs/replace"],
            root,
        )
        == "",
        "lab checkout has replace refs",
    )
    return {
        "commit": command_output(["git", "rev-parse", "HEAD"], root),
        "tree": command_output(["git", "rev-parse", "HEAD^{tree}"], root),
        "branch": command_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], root
        ),
    }


def _asset_snapshot(
    cache_root: Path,
    profile: dict[str, Any],
    converted_receipt: dict[str, Any] | None = None,
) -> Path:
    snapshot = cache_root / profile["modelId"]
    require(snapshot.parent == cache_root, "asset snapshot escaped cache root")
    require(
        snapshot.is_dir()
        and not snapshot.is_symlink()
        and snapshot == snapshot.resolve(),
        "asset snapshot is unsafe",
    )
    status = snapshot.stat()
    require(status.st_uid == os.getuid(), "asset snapshot is not owner controlled")
    require(status.st_mode & 0o077 == 0, "asset snapshot is not private")
    expected_files = {asset["path"] for asset in profile["files"]}
    for asset in profile["files"]:
        path = _safe_descendant(
            snapshot,
            asset["path"],
            f"asset {profile['modelId']}/{asset['path']}",
        )
        file_status = path.stat()
        require(file_status.st_uid == os.getuid(), "asset is not owner controlled")
        require(file_status.st_mode & 0o022 == 0, "asset is group/world writable")
        require(file_status.st_size == int(asset["bytes"]), "asset size differs")
        if asset.get("sha256") is None:
            require(
                git_blob_sha1(path.read_bytes()) == asset["hfGitOidSha1"],
                "gated Git asset OID differs",
            )
        else:
            require(sha256_file(path) == asset["sha256"], "asset digest differs")
    if profile.get("weightConversion") is not None:
        converted = _safe_descendant(
            snapshot, "model.safetensors", "converted OPT safetensors"
        )
        require(converted.stat().st_size > 8, "converted OPT safetensors is empty")
        require(converted.stat().st_mode & 0o022 == 0, "converted weights are writable")
        if converted_receipt is not None:
            require(
                converted_receipt["bytes"] == converted.stat().st_size
                and converted_receipt["sha256"] == sha256_file(converted),
                "converted OPT safetensors differs from the bound asset receipt",
            )
        expected_files.add("model.safetensors")
    expected_directories = {
        parent.as_posix()
        for relative in expected_files
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for artifact in snapshot.rglob("*"):
        require(not artifact.is_symlink(), "asset snapshot contains a symlink")
        relative = artifact.relative_to(snapshot).as_posix()
        if artifact.is_file():
            observed_files.add(relative)
        elif artifact.is_dir():
            observed_directories.add(relative)
        else:
            _fail("asset snapshot contains a special file")
    require(observed_files == expected_files, "asset snapshot has missing or extra files")
    require(
        observed_directories == expected_directories,
        "asset snapshot has missing or extra directories",
    )
    return snapshot


def _load_codec(codec_root: Path) -> Any:
    root = codec_root.resolve(strict=True)
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    module = importlib.import_module("RealLLM.voidtoken_v5")
    module_path = Path(module.__file__).resolve(strict=True)
    try:
        module_path.relative_to(root)
    except ValueError as error:
        raise ValueError("VoidToken parser was imported outside the pinned codec root") from error
    return module.VoidTokenV5Backend


def _workload_bindings(workloads: dict[str, Any]) -> dict[str, dict[str, Any]]:
    bindings: dict[str, dict[str, Any]] = {}
    for workload in workloads["workloads"]:
        text, inventory = workload_text(workload)
        identifier = workload["workloadId"]
        bindings[identifier] = {
            "category": workload["contentClass"],
            "promptUTF8SHA256": sha256_bytes(text.encode("utf-8")),
            "framedUTF8Bytes": len(text.encode("utf-8")),
            "sourceFiles": inventory,
        }
    return bindings


def _verify_preflight(
    path: Path,
    *,
    profiles: dict[str, Any],
    workloads: dict[str, Any],
    source: dict[str, Any],
    codec: dict[str, Any],
    asset_receipt_digest: str,
) -> tuple[dict[str, Any], str, dict[tuple[str, str], dict[str, Any]]]:
    preflight = _bounded_json(path, "preflight")
    digest = _verify_sidecar(path)
    _exact_object(
        preflight,
        {
            "schemaVersion",
            "status",
            "countsTowardScientificVerdict",
            "source",
            "codecSource",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
            "modelOrder",
            "workloadOrder",
            "horizon",
            "cells",
        },
        "preflight",
    )
    require(preflight["schemaVersion"] == PREFLIGHT_SCHEMA, "preflight schema differs")
    require(
        preflight["status"] == "TOKENIZER_ONLY_NO_MODEL_INFERENCE",
        "preflight status differs",
    )
    require(
        preflight["countsTowardScientificVerdict"] is False,
        "preflight makes a scientific claim",
    )
    require(preflight["source"] == source, "preflight source identity differs")
    require(preflight["codecSource"] == codec, "preflight codec identity differs")
    require(
        preflight["assetReceiptSHA256"] == asset_receipt_digest,
        "preflight asset receipt differs",
    )
    require(
        preflight["profilesSHA256"] == sha256_file(PROFILES_PATH),
        "preflight profile binding differs",
    )
    require(
        preflight["workloadsSHA256"] == sha256_file(WORKLOADS_PATH),
        "preflight workload binding differs",
    )
    require(
        preflight["protocolSHA256"] == sha256_file(PROTOCOL_PATH),
        "preflight protocol binding differs",
    )
    workload_order = [entry["workloadId"] for entry in workloads["workloads"]]
    require(preflight["modelOrder"] == list(MODEL_ORDER), "preflight model order differs")
    require(preflight["workloadOrder"] == workload_order, "preflight workload order differs")
    require(preflight["horizon"] == HORIZON, "preflight horizon differs")

    expected_pairs = [
        (model_id, workload_id)
        for model_id in MODEL_ORDER
        for workload_id in workload_order
    ]
    cells = preflight["cells"]
    require(isinstance(cells, list) and len(cells) == len(expected_pairs), "preflight must contain exactly 28 cells")
    bindings = _workload_bindings(workloads)
    profile_map = {entry["modelId"]: entry for entry in profiles["profiles"]}
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for position, (cell, expected_pair) in enumerate(zip(cells, expected_pairs)):
        label = f"preflight cell {position}"
        _exact_object(
            cell,
            {
                "modelId",
                "workloadId",
                "category",
                "promptUTF8SHA256",
                "framedUTF8Bytes",
                "availableTokens",
                "selectedTokens",
                "prefillTokens",
                "tokenIdsU32LESHA256",
                "sourceFiles",
            },
            label,
        )
        pair = (cell["modelId"], cell["workloadId"])
        require(pair == expected_pair, f"{label} order differs")
        require(pair not in indexed, f"{label} is duplicated")
        profile = profile_map[pair[0]]
        workload_binding = bindings[pair[1]]
        prefill = int(profile["maxPrefillTokens"])
        require(cell["category"] == workload_binding["category"], f"{label} category differs")
        require(
            cell["promptUTF8SHA256"] == workload_binding["promptUTF8SHA256"],
            f"{label} prompt digest differs",
        )
        require(
            cell["framedUTF8Bytes"] == workload_binding["framedUTF8Bytes"],
            f"{label} framed UTF-8 byte count differs",
        )
        require(cell["sourceFiles"] == workload_binding["sourceFiles"], f"{label} source inventory differs")
        require(cell["prefillTokens"] == prefill, f"{label} prefill differs")
        require(cell["selectedTokens"] == prefill + 1, f"{label} selected-token count differs")
        require_int(cell["availableTokens"], f"{label} available tokens", prefill + 1)
        require_digest(cell["tokenIdsU32LESHA256"], f"{label} token digest")
        indexed[pair] = cell
    return preflight, digest, indexed


def _parse_container_header(raw: bytes, label: str) -> tuple[dict[str, Any], bytes]:
    require(8 <= len(raw) <= MAX_CONTAINER_BYTES, f"{label} size exceeds its bound")
    magic, metadata_length = struct.unpack_from("<4sI", raw)
    require(magic == b"VTL5", f"{label} magic differs")
    require(0 < metadata_length <= 1024 * 1024, f"{label} metadata length is invalid")
    metadata_end = 8 + metadata_length
    require(metadata_end <= len(raw), f"{label} metadata is truncated")
    metadata_raw = raw[8:metadata_end]
    try:
        metadata = json.loads(
            metadata_raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} metadata is invalid JSON") from error
    require(isinstance(metadata, dict), f"{label} metadata must be an object")
    require(canonical_json_bytes(metadata) == metadata_raw, f"{label} metadata is not canonical JSON")
    return metadata, raw[metadata_end:]


def _decode_containers(
    *,
    cell_root: Path,
    result: dict[str, Any],
    profile: dict[str, Any],
    backend: Any,
    retain_layers: bool,
) -> tuple[dict[str, int | float], list[np.ndarray]]:
    encoding = _exact_object(
        result["encoding"],
        {
            "configuration",
            "configurationSHA256",
            "denseBF16Bytes",
            "containerBytes",
            "payloadBytes",
            "compressionRatio",
            "encodingNanoseconds",
            "containers",
        },
        "cell encoding",
    )
    configuration = configuration_for_profile(profile)
    require(encoding["configuration"] == configuration, "codec configuration differs")
    require(
        encoding["configurationSHA256"] == configuration_sha256(profile),
        "codec configuration digest differs",
    )
    require_int(encoding["encodingNanoseconds"], "encoding nanoseconds", 0)
    layers = int(profile["geometry"]["layers"])
    rows = int(profile["maxPrefillTokens"])
    columns = 2 * int(profile["geometry"]["kvHeads"]) * int(
        profile["geometry"]["headDimension"]
    )
    expected_dense = layers * rows * columns * 2
    require(
        encoding["denseBF16Bytes"] == expected_dense,
        "cell dense BF16 byte total differs",
    )
    manifests = encoding["containers"]
    require(
        isinstance(manifests, list) and len(manifests) == layers,
        "container manifest layer count differs",
    )
    schedule = configuration["bitsByLayer"]
    total_container = 0
    total_payload = 0
    total_dense = 0
    reconstructed: list[np.ndarray] = []
    for index, entry in enumerate(manifests):
        label = f"container layer {index}"
        _exact_object(
            entry,
            {
                "layerIndex",
                "bits",
                "rows",
                "columns",
                "denseBF16Bytes",
                "containerBytes",
                "payloadBytes",
                "containerSHA256",
                "payloadSHA256",
                "path",
            },
            f"{label} manifest",
        )
        require_int(entry["layerIndex"], f"{label} layer index", 0)
        require_int(entry["bits"], f"{label} bit width", 1)
        require_int(entry["rows"], f"{label} rows", 1)
        require_int(entry["columns"], f"{label} columns", 1)
        require_int(entry["denseBF16Bytes"], f"{label} dense bytes", 1)
        require_int(entry["containerBytes"], f"{label} container bytes", 1)
        require_int(entry["payloadBytes"], f"{label} payload bytes", 1)
        expected_path = f"containers/layer-{index:03d}.vtl5"
        require(
            entry["layerIndex"] == index
            and entry["bits"] == schedule[index]
            and entry["rows"] == rows
            and entry["columns"] == columns
            and entry["path"] == expected_path,
            f"{label} geometry, schedule, or path differs",
        )
        dense = rows * columns * 2
        require(entry["denseBF16Bytes"] == dense, f"{label} dense bytes differ")
        require_digest(entry["containerSHA256"], f"{label} container digest")
        require_digest(entry["payloadSHA256"], f"{label} payload digest")
        path = _safe_descendant(cell_root, expected_path, label)
        status = path.stat()
        require(0 < status.st_size <= MAX_CONTAINER_BYTES, f"{label} file size is invalid")
        raw = path.read_bytes()
        require(entry["containerBytes"] == len(raw), f"{label} byte count differs")
        require(entry["containerSHA256"] == sha256_bytes(raw), f"{label} SHA-256 differs")
        metadata, payload = _parse_container_header(raw, label)
        require(entry["payloadBytes"] == len(payload), f"{label} payload byte count differs")
        require(entry["payloadSHA256"] == sha256_bytes(payload), f"{label} payload SHA-256 differs")
        require(
            metadata.get("format") == "voidtoken-rotated-entropy-v5"
            and metadata.get("shape") == [rows, columns]
            and metadata.get("layerIndex") == index
            and metadata.get("bits") == schedule[index]
            and metadata.get("groupSize") == 128
            and metadata.get("transformBlockSize") == 128
            and metadata.get("scaleCompression") == "zlib-9"
            and metadata.get("codeCompression") == "zlib-9"
            and metadata.get("signMode") == "none"
            and metadata.get("payloadBytes") == len(payload)
            and metadata.get("payloadSha256") == sha256_bytes(payload),
            f"{label} metadata differs from the registered codec",
        )
        for digest_name in ("inputSha256", "payloadSha256", "reconstructionSha256"):
            require_digest(metadata.get(digest_name), f"{label} {digest_name}")
        parsed = backend.from_bytes(raw)
        require(parsed.to_bytes() == raw, f"{label} parser changed canonical bytes")
        require(parsed.metadata == metadata, f"{label} parser metadata differs")
        require(bytes(parsed.payload) == payload, f"{label} parser payload differs")
        matrix = np.asarray(parsed.reconstructed)
        require(matrix.dtype == np.float32, f"{label} reconstruction is not float32")
        require(matrix.shape == (rows, columns), f"{label} reconstruction shape differs")
        require(np.isfinite(matrix).all(), f"{label} reconstruction is non-finite")
        if retain_layers:
            reconstructed.append(np.ascontiguousarray(matrix, dtype=np.float32))
        total_container += len(raw)
        total_payload += len(payload)
        total_dense += dense
        require(
            total_container <= MAX_TOTAL_CONTAINER_BYTES,
            "cell container evidence exceeds its total bound",
        )
    require(total_dense == expected_dense, "container dense byte sum differs")
    require(encoding["containerBytes"] == total_container, "cell container byte total differs")
    require(encoding["payloadBytes"] == total_payload, "cell payload byte total differs")
    require(total_container > 0, "cell has zero container bytes")
    ratio = expected_dense / total_container
    require(
        math.isclose(
            _finite(encoding["compressionRatio"], "compression ratio"),
            ratio,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ),
        "compression ratio does not recompute from complete container bytes",
    )
    return {
        "layers": layers,
        "denseBF16Bytes": expected_dense,
        "containerBytes": total_container,
        "payloadBytes": total_payload,
        "compressionRatio": ratio,
    }, reconstructed


def _verify_behavior(value: Any, profile: dict[str, Any]) -> dict[str, Any]:
    behavior = _exact_object(
        value,
        {
            "predictionTokens",
            "controlledTop1AgreementCount",
            "controlledTop1Agreement",
            "meanKLDivergenceNat",
            "meanBaselineSelectedTokenSurprisalDeltaNat",
            "maxAbsLogitDifference",
            "perTokenKLDivergenceNat",
            "perTokenBaselineSelectedTokenSurprisalDeltaNat",
            "perTokenMaxAbsLogitDifference",
            "baselineTokenIds",
            "controlledCandidateTop1TokenIds",
            "candidateFreeRunTokenIds",
            "freeRunExact",
            "freeRunSamePositionCount",
            "freeRunLongestCommonPrefixTokens",
            "baselineContinuation",
            "candidateFreeRunContinuation",
        },
        "cell behavior",
    )
    require(behavior["predictionTokens"] == HORIZON, "behavior horizon differs")
    vocabulary = int(profile["geometry"]["vocabularySize"])
    arrays: list[list[int]] = []
    for name in (
        "baselineTokenIds",
        "controlledCandidateTop1TokenIds",
        "candidateFreeRunTokenIds",
    ):
        values = behavior[name]
        require(isinstance(values, list) and len(values) == HORIZON, f"{name} length differs")
        require(
            all(type(item) is int and 0 <= item < vocabulary for item in values),
            f"{name} contains an invalid token ID",
        )
        arrays.append(values)
    baseline, controlled, free_run = arrays
    agreement = sum(left == right for left, right in zip(baseline, controlled))
    recorded_agreement = require_int(
        behavior["controlledTop1AgreementCount"],
        "controlled agreement count",
        0,
    )
    require(recorded_agreement <= HORIZON, "controlled agreement count exceeds horizon")
    require(
        recorded_agreement == agreement,
        "controlled agreement count differs",
    )
    require(
        math.isclose(
            _finite(behavior["controlledTop1Agreement"], "controlled top-1 agreement"),
            agreement / HORIZON,
            rel_tol=0.0,
            abs_tol=1e-15,
        ),
        "controlled top-1 agreement differs",
    )
    per_token_metrics: dict[str, list[float]] = {}
    for name in (
        "perTokenKLDivergenceNat",
        "perTokenBaselineSelectedTokenSurprisalDeltaNat",
        "perTokenMaxAbsLogitDifference",
    ):
        values = behavior[name]
        require(
            isinstance(values, list) and len(values) == HORIZON,
            f"{name} length differs",
        )
        per_token_metrics[name] = [
            _finite(item, f"{name}[{index}]")
            for index, item in enumerate(values)
        ]
    require(
        all(value >= -1e-4 for value in per_token_metrics["perTokenKLDivergenceNat"]),
        "per-token KL divergence is materially negative",
    )
    require(
        all(value >= 0 for value in per_token_metrics["perTokenMaxAbsLogitDifference"]),
        "per-token maximum logit difference is negative",
    )
    mean_kl = _finite(behavior["meanKLDivergenceNat"], "mean KL divergence")
    require(mean_kl >= -1e-4, "mean KL divergence is materially negative")
    mean_surprisal = _finite(
        behavior["meanBaselineSelectedTokenSurprisalDeltaNat"],
        "mean selected-token surprisal delta",
    )
    maximum_difference = _finite(
        behavior["maxAbsLogitDifference"], "maximum logit difference"
    )
    require(maximum_difference >= 0, "maximum logit difference is negative")
    _close(
        mean_kl,
        sum(per_token_metrics["perTokenKLDivergenceNat"]) / HORIZON,
        "mean KL divergence from per-token values",
    )
    _close(
        mean_surprisal,
        sum(per_token_metrics["perTokenBaselineSelectedTokenSurprisalDeltaNat"])
        / HORIZON,
        "mean surprisal delta from per-token values",
    )
    _close(
        maximum_difference,
        max(per_token_metrics["perTokenMaxAbsLogitDifference"]),
        "maximum logit difference from per-token values",
    )
    require(type(behavior["freeRunExact"]) is bool, "free-run exactness is not boolean")
    require(behavior["freeRunExact"] == (baseline == free_run), "free-run exactness differs")
    same_positions = sum(left == right for left, right in zip(baseline, free_run))
    recorded_same_positions = require_int(
        behavior["freeRunSamePositionCount"], "free-run same-position count", 0
    )
    require(
        recorded_same_positions <= HORIZON,
        "free-run same-position count exceeds horizon",
    )
    require(
        recorded_same_positions == same_positions,
        "free-run same-position count differs",
    )
    prefix = 0
    for left, right in zip(baseline, free_run):
        if left != right:
            break
        prefix += 1
    recorded_prefix = require_int(
        behavior["freeRunLongestCommonPrefixTokens"],
        "free-run common-prefix length",
        0,
    )
    require(recorded_prefix <= HORIZON, "free-run common-prefix exceeds horizon")
    require(
        recorded_prefix == prefix,
        "free-run common-prefix length differs",
    )
    for name in ("baselineContinuation", "candidateFreeRunContinuation"):
        text = behavior[name]
        require(
            isinstance(text, str) and len(text) <= MAX_CONTINUATION_CHARACTERS,
            f"{name} is invalid or oversized",
        )
    return behavior


def _verify_cache_observation(value: Any, profile: dict[str, Any]) -> dict[str, Any]:
    observation = _exact_object(
        value,
        {
            "cacheClass",
            "layerClass",
            "tensorLayout",
            "batchSize",
            "layers",
            "kvHeads",
            "headDimension",
            "dtype",
            "targetContextTokens",
            "prefillTokens",
            "finalPromptTokens",
            "continuationTokens",
            "effectiveCacheTokens",
            "evictedTokens",
        },
        "cell cache observation",
    )
    expected_layer_suffix = (
        ".DynamicSlidingWindowLayer"
        if profile["modelId"] == "mistral-7b-v0.1"
        else ".DynamicLayer"
    )
    require(
        isinstance(observation["cacheClass"], str)
        and observation["cacheClass"].endswith(".DynamicCache"),
        "observed cache class differs",
    )
    require(
        isinstance(observation["layerClass"], str)
        and observation["layerClass"].endswith(expected_layer_suffix),
        "observed cache layer class differs",
    )
    expected = {
        "tensorLayout": "batch,kv_head,token,head_dimension",
        "batchSize": 1,
        "layers": int(profile["geometry"]["layers"]),
        "kvHeads": int(profile["geometry"]["kvHeads"]),
        "headDimension": int(profile["geometry"]["headDimension"]),
        "dtype": "bfloat16",
        "targetContextTokens": int(profile["gpuAdmission"]["maxInputTokens"]),
        "prefillTokens": int(profile["maxPrefillTokens"]),
        "finalPromptTokens": 1,
        "continuationTokens": HORIZON,
        "effectiveCacheTokens": int(profile["maxPrefillTokens"]),
        "evictedTokens": 0,
    }
    for name, expected_value in expected.items():
        require(observation[name] == expected_value, f"cache observation {name} differs")
    return observation


def _verify_runtime(
    value: Any,
    profile: dict[str, Any],
    dense_bytes: int,
    runtime_lock_sha256: str,
) -> tuple[datetime, datetime]:
    runtime = _exact_object(
        value,
        {
            "startedAt",
            "completedAt",
            "python",
            "torch",
            "cuda",
            "gpuName",
            "gpuDriverVersion",
            "gpuTotalBytes",
            "gpuFreeBytesBeforeCell",
            "memoryEstimateBytes",
            "peakAllocatedBytes",
            "peakReservedBytes",
            "peakRssBytes",
            "diskFreeBytesBeforeCell",
            "diskRequiredBytes",
            "modelRequirementsLockSHA256",
            "pipBootstrapLockSHA256",
            "portableRuntimeLockSHA256",
            "cudaRuntimeLockSHA256",
            "packages",
            "cgroupMemoryCurrentBytesAtCompletion",
            "cgroupMemoryPeakBytesAtCompletion",
            "cgroupMemoryLimitBytes",
            "dtype",
            "attentionImplementation",
            "deterministicAlgorithms",
        },
        "cell runtime",
    )
    started = _timestamp(runtime["startedAt"], "cell start")
    completed = _timestamp(runtime["completedAt"], "cell completion")
    require(completed >= started, "cell completion precedes its start")
    for name in ("python", "torch", "cuda", "gpuName"):
        require(isinstance(runtime[name], str) and runtime[name], f"runtime {name} is empty")
    require(
        isinstance(runtime["gpuDriverVersion"], str)
        and re.fullmatch(
            r"[0-9]+(?:[.][0-9]+){1,3}", runtime["gpuDriverVersion"]
        )
        is not None,
        "runtime NVIDIA driver version is invalid",
    )
    total = require_int(runtime["gpuTotalBytes"], "GPU total bytes", 1)
    free = require_int(runtime["gpuFreeBytesBeforeCell"], "GPU free bytes", 0)
    allocated = require_int(runtime["peakAllocatedBytes"], "peak allocated bytes", 0)
    reserved = require_int(runtime["peakReservedBytes"], "peak reserved bytes", 0)
    require(free <= total and allocated <= total and reserved <= total, "GPU memory accounting exceeds total memory")
    peak_rss = require_int(runtime["peakRssBytes"], "peak RSS bytes", 1)
    require(peak_rss > 0, "peak RSS is empty")
    disk_free = require_int(runtime["diskFreeBytesBeforeCell"], "free disk bytes", 1)
    disk_required = require_int(runtime["diskRequiredBytes"], "required disk bytes", 1)
    require(disk_free >= disk_required, "cell disk admission was insufficient")
    require(
        runtime["modelRequirementsLockSHA256"]
        == runtime_lock_sha256,
        "model requirements lock digest differs",
    )
    require(
        runtime["pipBootstrapLockSHA256"]
        == EXPECTED_CODEC_FILES[".github/locks/pip-bootstrap.txt"],
        "pip bootstrap lock digest differs",
    )
    require(
        runtime["portableRuntimeLockSHA256"]
        == EXPECTED_CODEC_FILES[
            ".github/locks/real-llm-linux-cpu-py312.txt"
        ],
        "portable runtime lock digest differs",
    )
    require(
        runtime["cudaRuntimeLockSHA256"] == sha256_file(TORCH_LOCK_PATH),
        "CUDA runtime lock digest differs",
    )
    require(
        runtime["packages"]
        == {
            "huggingface-hub": "1.25.1",
            "numpy": "2.5.1",
            "safetensors": "0.8.0",
            "tokenizers": "0.22.2",
            "torch": "2.13.0+cu130",
            "transformers": "5.14.1",
        },
        "runtime package identity differs",
    )
    cgroup_current = require_int(
        runtime["cgroupMemoryCurrentBytesAtCompletion"],
        "cgroup memory at completion",
        0,
    )
    cgroup_peak = require_int(
        runtime["cgroupMemoryPeakBytesAtCompletion"],
        "cgroup peak at completion",
        cgroup_current,
    )
    cgroup_limit = runtime["cgroupMemoryLimitBytes"]
    require(
        cgroup_limit is None
        or (type(cgroup_limit) is int and cgroup_limit >= cgroup_peak),
        "cgroup memory limit differs",
    )
    weight_bytes = sum(
        int(asset["bytes"])
        for asset in profile["files"]
        if asset["path"].endswith((".safetensors", ".bin"))
    )
    expected_estimate = weight_bytes + 6 * dense_bytes + 4 * 1024**3
    require(
        runtime["memoryEstimateBytes"] == expected_estimate,
        "cell memory estimate does not recompute",
    )
    require(
        runtime["memoryEstimateBytes"] <= int(total * 0.80),
        "cell memory estimate exceeds the admitted 80% GPU-memory ceiling",
    )
    require(
        runtime["memoryEstimateBytes"] <= int(free * 0.80),
        "cell memory estimate exceeds 80% of the recorded free GPU memory",
    )
    require(
        runtime["memoryEstimateBytes"]
        <= int(profile["gpuAdmission"]["maxGpuMemoryBytes"]),
        "cell memory estimate exceeds the registered per-profile hard cap",
    )
    require(
        allocated <= int(profile["gpuAdmission"]["maxGpuMemoryBytes"])
        and reserved <= int(profile["gpuAdmission"]["maxGpuMemoryBytes"]),
        "actual CUDA peak exceeds the registered per-profile hard cap",
    )
    require(runtime["dtype"] == "bfloat16", "runtime dtype differs")
    require(runtime["attentionImplementation"] == "eager", "attention implementation differs")
    require(runtime["deterministicAlgorithms"] is True, "deterministic algorithms were not recorded")
    return started, completed


def _verify_cell(
    *,
    run_root: Path,
    record: dict[str, Any],
    profile: dict[str, Any],
    expected_preflight: dict[str, Any],
    codec: dict[str, Any],
    source: dict[str, Any],
    run_id: str,
    preflight_digest: str,
    asset_receipt_digest: str,
    backend: Any,
) -> tuple[dict[str, Any], dict[str, Any], set[str], set[str]]:
    model_id = profile["modelId"]
    workload_id = expected_preflight["workloadId"]
    label = f"cell {model_id}/{workload_id}"
    expected_result_path = f"cells/{model_id}/{workload_id}/result.json"
    expected_stdout = f"logs/{model_id}--{workload_id}.stdout.log"
    expected_stderr = f"logs/{model_id}--{workload_id}.stderr.log"
    _exact_object(
        record,
        {
            "modelId",
            "workloadId",
            "startedAt",
            "completedAt",
            "returnCode",
            "exitSignal",
            "timedOut",
            "timeoutLimitSeconds",
            "terminationReason",
            "status",
            "resultPath",
            "resultSHA256",
            "stdoutSHA256",
            "stderrSHA256",
        },
        f"{label} run record",
    )
    require(
        record["modelId"] == model_id and record["workloadId"] == workload_id,
        f"{label} identity differs",
    )
    require(
        type(record["returnCode"]) is int and record["returnCode"] == 0,
        f"{label} process did not exit zero",
    )
    require(record["timedOut"] is False, f"{label} timed out")
    require(record["exitSignal"] is None, f"{label} exited by signal")
    require(
        record["terminationReason"] == "completed",
        f"{label} termination reason differs",
    )
    require(
        record["timeoutLimitSeconds"]
        == int(profile["gpuAdmission"]["executionTimeoutSeconds"]),
        f"{label} timeout limit differs",
    )
    require(record["status"] == "COMPLETE", f"{label} is incomplete")
    require(record["resultPath"] == expected_result_path, f"{label} result path differs")
    require_digest(record["resultSHA256"], f"{label} result digest")
    require_digest(record["stdoutSHA256"], f"{label} stdout digest")
    require_digest(record["stderrSHA256"], f"{label} stderr digest")
    started = _timestamp(record["startedAt"], f"{label} process start")
    completed = _timestamp(record["completedAt"], f"{label} process completion")
    require(completed >= started, f"{label} completion precedes its start")
    attempt_path = _safe_descendant(
        run_root,
        f"cells/{model_id}/{workload_id}/attempt.json",
        f"{label} attempt",
    )
    attempt = _bounded_json(attempt_path, f"{label} attempt")
    _verify_sidecar(attempt_path)
    _exact_object(
        attempt,
        {
            "schemaVersion",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "attemptId",
            "runId",
            "startedAt",
            "modelId",
            "adapterId",
            "workloadId",
            "timeoutLimitSeconds",
            "source",
            "codecSource",
            "preflightSHA256",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
        },
        f"{label} attempt",
    )
    try:
        attempt_uuid = uuid.UUID(attempt["attemptId"])
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(f"{label} attempt ID is invalid") from error
    require(str(attempt_uuid) == attempt["attemptId"], f"{label} attempt ID is not canonical")
    attempt_started = _timestamp(attempt["startedAt"], f"{label} attempt start")
    require(started <= attempt_started <= completed, f"{label} attempt time is outside the process interval")
    require(
        attempt
        | {}
        == {
            **attempt,
            "schemaVersion": ATTEMPT_SCHEMA_VERSION,
            "status": "STARTED",
            "classification": CLASSIFICATION,
            "countsTowardScientificVerdict": False,
            "runId": run_id,
            "modelId": model_id,
            "adapterId": profile["adapterId"],
            "workloadId": workload_id,
            "timeoutLimitSeconds": int(
                profile["gpuAdmission"]["executionTimeoutSeconds"]
            ),
            "source": source,
            "codecSource": codec,
            "preflightSHA256": preflight_digest,
            "assetReceiptSHA256": asset_receipt_digest,
            "profilesSHA256": sha256_file(PROFILES_PATH),
            "workloadsSHA256": sha256_file(WORKLOADS_PATH),
            "protocolSHA256": sha256_file(PROTOCOL_PATH),
        },
        f"{label} attempt binding differs",
    )
    result_path = _safe_descendant(run_root, expected_result_path, f"{label} result")
    result = _bounded_json(result_path, f"{label} result")
    result_digest = _verify_sidecar(result_path)
    require(record["resultSHA256"] == result_digest, f"{label} result digest differs")
    for log_relative, digest_name in (
        (expected_stdout, "stdoutSHA256"),
        (expected_stderr, "stderrSHA256"),
    ):
        log = _safe_descendant(run_root, log_relative, f"{label} log")
        require(log.stat().st_size <= MAX_LOG_BYTES, f"{label} log exceeds its bound")
        require(sha256_file(log) == record[digest_name], f"{label} log digest differs")

    _exact_object(
        result,
        {
            "schemaVersion",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "model",
            "workload",
            "codecSource",
            "assetReceiptSHA256",
            "canonicalCacheBF16SHA256",
            "cacheObservation",
            "structuralReplay",
            "encoding",
            "behavior",
            "runtime",
        },
        f"{label} result",
    )
    require(result["schemaVersion"] == RESULT_SCHEMA_VERSION, f"{label} result schema differs")
    require(result["status"] == "COMPLETE", f"{label} result status differs")
    require(result["classification"] == CLASSIFICATION, f"{label} classification differs")
    require(result["countsTowardScientificVerdict"] is False, f"{label} makes a scientific claim")
    model = _exact_object(
        result["model"],
        {
            "modelId",
            "adapterId",
            "repository",
            "revision",
            "geometry",
            "assetRootName",
        },
        f"{label} model",
    )
    require(
        model
        == {
            "modelId": profile["modelId"],
            "adapterId": profile["adapterId"],
            "repository": profile["repository"],
            "revision": profile["revision"],
            "geometry": profile["geometry"],
            "assetRootName": profile["modelId"],
        },
        f"{label} model binding differs",
    )
    expected_workload = dict(expected_preflight)
    expected_workload.pop("modelId")
    require(result["workload"] == expected_workload, f"{label} preflight workload binding differs")
    require(result["codecSource"] == codec, f"{label} codec source differs")
    require(
        result["assetReceiptSHA256"] == asset_receipt_digest,
        f"{label} asset receipt differs",
    )
    require_digest(result["canonicalCacheBF16SHA256"], f"{label} canonical cache digest")
    _verify_cache_observation(result["cacheObservation"], profile)
    structural = _exact_object(
        result["structuralReplay"],
        {"maxAbsLogitDifference", "top1Identical"},
        f"{label} structural replay",
    )
    require(
        _finite(
            structural["maxAbsLogitDifference"],
            f"{label} structural maximum logit difference",
        )
        == 0.0,
        f"{label} structural logit replay is not exact",
    )
    require(structural["top1Identical"] is True, f"{label} structural top-1 replay differs")
    cell_root = result_path.parent
    encoding_summary, _ = _decode_containers(
        cell_root=cell_root,
        result=result,
        profile=profile,
        backend=backend,
        retain_layers=False,
    )
    _verify_behavior(result["behavior"], profile)
    runtime_started, runtime_completed = _verify_runtime(
        result["runtime"],
        profile,
        int(encoding_summary["denseBF16Bytes"]),
        codec["files"]["RealLLM/requirements.lock"]["sha256"],
    )
    require(
        attempt_started <= runtime_started <= runtime_completed <= completed,
        f"{label} runtime interval is outside its attempt/process interval",
    )
    expected_files = {
        expected_result_path,
        expected_result_path + ".sha256",
        f"cells/{model_id}/{workload_id}/attempt.json",
        f"cells/{model_id}/{workload_id}/attempt.json.sha256",
        expected_stdout,
        expected_stderr,
        *{
            f"cells/{model_id}/{workload_id}/containers/layer-{index:03d}.vtl5"
            for index in range(int(profile["geometry"]["layers"]))
        },
    }
    expected_directories = {
        f"cells/{model_id}",
        f"cells/{model_id}/{workload_id}",
        f"cells/{model_id}/{workload_id}/containers",
    }
    return result, encoding_summary, expected_files, expected_directories


def verify_run(
    *,
    codec_root: Path,
    cache: Path,
    assets_path: Path,
    preflight_path: Path,
    run_dir: Path,
) -> dict[str, Any]:
    codec_root = codec_root.resolve(strict=True)
    codec = validate_codec_root(codec_root)
    source = _source_identity()
    profiles = load_profiles()
    workloads = load_workloads()
    cache_root = _safe_directory(cache, "asset cache")
    _, asset_receipt_digest = verify_asset_receipt(assets_path, cache_root)
    for profile in profiles["profiles"]:
        _asset_snapshot(cache_root, profile)
    preflight, preflight_digest, preflight_cells = _verify_preflight(
        preflight_path,
        profiles=profiles,
        workloads=workloads,
        source=source,
        codec=codec,
        asset_receipt_digest=asset_receipt_digest,
    )
    run_root = _safe_directory(run_dir, "run directory")
    run_path = run_root / "run.json"
    run = _bounded_json(run_path, "run manifest")
    run_digest = _verify_sidecar(run_path)
    _exact_object(
        run,
        {
            "schemaVersion",
            "runId",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "source",
            "preflightSHA256",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
            "expectedCells",
            "completeCells",
            "cells",
        },
        "run manifest",
    )
    require(run["schemaVersion"] == RUN_SCHEMA_VERSION, "run schema differs")
    try:
        parsed_uuid = uuid.UUID(run["runId"])
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("run ID is not a UUID") from error
    require(str(parsed_uuid) == run["runId"], "run ID is not canonical")
    require(run["status"] == "COMPLETE", "run is not complete")
    require(run["classification"] == CLASSIFICATION, "run classification differs")
    require(run["countsTowardScientificVerdict"] is False, "run makes a scientific claim")
    require(run["source"] == source == preflight["source"], "run source identity differs")
    require(run["preflightSHA256"] == preflight_digest, "run preflight digest differs")
    require(run["assetReceiptSHA256"] == asset_receipt_digest, "run asset receipt differs")
    require(run["profilesSHA256"] == sha256_file(PROFILES_PATH), "run profile digest differs")
    require(run["workloadsSHA256"] == sha256_file(WORKLOADS_PATH), "run workload digest differs")
    require(run["protocolSHA256"] == sha256_file(PROTOCOL_PATH), "run protocol digest differs")
    workload_order = [entry["workloadId"] for entry in workloads["workloads"]]
    expected_pairs = [
        (model_id, workload_id)
        for model_id in MODEL_ORDER
        for workload_id in workload_order
    ]
    require(run["expectedCells"] == len(expected_pairs) == 28, "run expected-cell count differs")
    require(run["completeCells"] == len(expected_pairs), "run complete-cell count differs")
    records = run["cells"]
    require(isinstance(records, list) and len(records) == len(expected_pairs), "run must contain exactly 28 cell records")
    profile_map = {entry["modelId"]: entry for entry in profiles["profiles"]}
    backend = _load_codec(codec_root)
    expected_files = {"run.json", "run.json.sha256"}
    expected_directories = {"cells", "logs"}
    cell_results: dict[tuple[str, str], dict[str, Any]] = {}
    total_containers = 0
    total_container_bytes = 0
    for position, (record, pair) in enumerate(zip(records, expected_pairs)):
        require(
            (record.get("modelId"), record.get("workloadId")) == pair,
            f"run cell {position} order differs",
        )
        result, encoding, files, directories = _verify_cell(
            run_root=run_root,
            record=record,
            profile=profile_map[pair[0]],
            expected_preflight=preflight_cells[pair],
            codec=codec,
            source=source,
            run_id=run["runId"],
            preflight_digest=preflight_digest,
            asset_receipt_digest=asset_receipt_digest,
            backend=backend,
        )
        require(pair not in cell_results, "run contains a duplicate cell")
        cell_results[pair] = result
        expected_files.update(files)
        expected_directories.update(directories)
        total_containers += int(encoding["layers"])
        total_container_bytes += int(encoding["containerBytes"])
        require(
            total_container_bytes <= MAX_TOTAL_CONTAINER_BYTES,
            "run container evidence exceeds its total bound",
        )

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for artifact in run_root.rglob("*"):
        require(not artifact.is_symlink(), "run tree contains a symlink")
        relative = artifact.relative_to(run_root).as_posix()
        status = artifact.lstat()
        require(status.st_uid == os.getuid(), "run tree contains a foreign-owned path")
        require(status.st_mode & 0o077 == 0, "run tree contains a non-private path")
        if artifact.is_dir():
            actual_directories.add(relative)
        elif artifact.is_file():
            actual_files.add(relative)
        else:
            _fail("run tree contains a special file")
    require(actual_files == expected_files, "run tree contains missing or extra files")
    require(actual_directories == expected_directories, "run tree contains missing or extra directories")
    return {
        "schemaVersion": VERIFY_SCHEMA,
        "status": "STRUCTURALLY_VERIFIED",
        "classification": CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "modelReplayPerformed": False,
        "runId": run["runId"],
        "runSHA256": run_digest,
        "preflightSHA256": preflight_digest,
        "assetReceiptSHA256": asset_receipt_digest,
        "cells": len(cell_results),
        "containers": total_containers,
        "containerBytes": total_container_bytes,
        "_internal": {
            "run": run,
            "preflight": preflight,
            "preflightCells": preflight_cells,
            "profiles": profiles,
            "workloads": workloads,
            "cellResults": cell_results,
            "codec": codec,
            "codecRoot": codec_root,
            "cacheRoot": cache_root,
            "runRoot": run_root,
            "backend": backend,
        },
    }


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
        and all(type(item) is int and 0 <= item <= 0xFFFFFFFF for item in values),
        "tokenizer produced invalid token IDs",
    )
    return values


def _token_digest(values: list[int]) -> str:
    return sha256_bytes(np.asarray(values, dtype="<u4").tobytes())


def _model_geometry(model: Any) -> dict[str, Any]:
    config = model.config
    model_type = str(config.model_type)
    if model_type == "gpt2":
        layers = int(config.n_layer)
        heads = int(config.n_head)
        hidden = int(config.n_embd)
        kv_heads = heads
    elif model_type == "opt":
        layers = int(config.num_hidden_layers)
        heads = int(config.num_attention_heads)
        hidden = int(config.hidden_size)
        kv_heads = heads
    else:
        layers = int(config.num_hidden_layers)
        heads = int(config.num_attention_heads)
        hidden = int(config.hidden_size)
        kv_heads = int(getattr(config, "num_key_value_heads", heads))
    head_dimension = int(getattr(config, "head_dim", hidden // heads))
    context = 0
    for name in ("max_position_embeddings", "n_positions", "n_ctx", "seq_length"):
        value = getattr(config, name, None)
        if isinstance(value, int) and value > 0:
            context = value
            break
    return {
        "modelType": model_type,
        "architecture": str(config.architectures[0]),
        "layers": layers,
        "hiddenSize": hidden,
        "attentionHeads": heads,
        "kvHeads": kv_heads,
        "headDimension": head_dimension,
        "contextTokens": context,
    }


def _configure_torch() -> Any:
    import torch

    require(torch.cuda.is_available(), "CUDA is required for model replay")
    require(torch.cuda.device_count() == 1, "exactly one visible CUDA device is required")
    torch.manual_seed(20260812)
    torch.cuda.manual_seed_all(20260812)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    torch.use_deterministic_algorithms(True)
    return torch


def _gpu_driver_version() -> str:
    process = subprocess.run(
        [
            "/usr/bin/nvidia-smi",
            "--query-gpu=driver_version",
            "--format=csv,noheader,nounits",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )
    value = process.stdout.strip()
    require(
        process.returncode == 0
        and re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,3}", value) is not None,
        "cannot establish the replay NVIDIA driver version",
    )
    return value


def _discard_validated_distilgpt2_attention_biases(
    state: dict[str, Any], profile: dict[str, Any], torch_module: Any
) -> None:
    """Independently validate and remove the pinned legacy causal masks."""

    require(
        profile.get("modelId") == "distilgpt2",
        "legacy GPT-2 attention-bias compatibility is DistilGPT2-only",
    )
    require(
        profile.get("geometry", {}).get("layers") == 6
        and profile.get("geometry", {}).get("contextTokens") == 1024,
        "DistilGPT2 legacy attention-bias geometry differs",
    )
    expected_keys = {
        f"transformer.h.{layer}.attn.bias" for layer in range(6)
    }
    observed_keys = {
        key
        for key in state
        if isinstance(key, str) and key.endswith(".attn.bias")
    }
    require(
        observed_keys == expected_keys,
        "DistilGPT2 legacy attention-bias key set differs",
    )

    expected_shape = (1, 1, 1024, 1024)
    expected_mask = torch_module.tril(
        torch_module.ones(
            expected_shape,
            dtype=torch_module.float32,
            device="cpu",
        )
    )
    for key in sorted(expected_keys):
        tensor = state[key]
        require(
            isinstance(tensor, torch_module.Tensor),
            f"DistilGPT2 legacy attention-bias tensor {key} is invalid",
        )
        require(
            tensor.dtype == torch_module.float32
            and tuple(tensor.shape) == expected_shape
            and tensor.device.type == "cpu"
            and tensor.layout == torch_module.strided
            and bool(tensor.is_contiguous()),
            f"DistilGPT2 legacy attention-bias tensor {key} metadata differs",
        )
        require(
            bool(torch_module.equal(tensor, expected_mask)),
            f"DistilGPT2 legacy attention-bias tensor {key} is not the causal mask",
        )

    for key in sorted(expected_keys):
        del state[key]


def _load_model_and_tokenizer(
    profile: dict[str, Any],
    cache_root: Path,
    torch_module: Any,
    converted_receipt: dict[str, Any] | None,
) -> tuple[Any, Any, Path]:
    from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

    snapshot = _asset_snapshot(cache_root, profile, converted_receipt)
    tokenizer = AutoTokenizer.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False
    )
    if profile.get("weightConversion") is not None:
        require(
            profile["weightConversion"]
            == "torch-weights-only-to-safetensors-v1",
            "unknown model weight conversion",
        )
    if profile["weights"].get("disableMmap") is True:
        from safetensors.torch import load as load_safetensors_bytes

        config = AutoConfig.from_pretrained(
            snapshot, local_files_only=True, trust_remote_code=False
        )
        model = AutoModelForCausalLM.from_config(
            config,
            trust_remote_code=False,
            dtype=torch_module.bfloat16,
            attn_implementation="eager",
        )
        state = load_safetensors_bytes(
            (snapshot / "model.safetensors").read_bytes()
        )
        if profile["modelType"] == "gpt2":
            require(
                "transformer.wte.weight" in state,
                "GPT-2 safetensors omit the input embedding tensor",
            )
            require(
                "lm_head.weight" not in state,
                "pinned GPT-2 safetensors unexpectedly duplicate tied weights",
            )
            _discard_validated_distilgpt2_attention_biases(
                state, profile, torch_module
            )
            state["lm_head.weight"] = state["transformer.wte.weight"]
        incompatible = model.load_state_dict(state, strict=True, assign=False)
        require(
            not incompatible.missing_keys and not incompatible.unexpected_keys,
            "non-mmap safetensors keys differ from the model",
        )
        if profile["modelType"] == "gpt2":
            model.tie_weights()
            require(
                model.get_input_embeddings().weight.data_ptr()
                == model.get_output_embeddings().weight.data_ptr(),
                "GPT-2 input/output embeddings are not tied after strict load",
            )
        del state
    else:
        model = AutoModelForCausalLM.from_pretrained(
            snapshot,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            dtype=torch_module.bfloat16,
            attn_implementation="eager",
            low_cpu_mem_usage=True,
        )
    model.train(False).to("cuda:0")
    require(next(model.parameters()).dtype == torch_module.bfloat16, "model is not BF16")
    observed_geometry = _model_geometry(model)
    for field, observed in observed_geometry.items():
        require(
            observed == profile["geometry"][field],
            f"loaded model geometry field {field} differs",
        )
    require(
        int(model.config.vocab_size) == int(profile["geometry"]["vocabularySize"]),
        "loaded model vocabulary size differs",
    )
    return model, tokenizer, snapshot


def _cache_layer_tensors(layer: Any) -> tuple[Any, Any]:
    keys = getattr(layer, "keys", None)
    values = getattr(layer, "values", None)
    require(keys is not None and values is not None, "cache layer lacks key/value tensors")
    return keys, values


def _extract_canonical_layers(
    cache: Any,
    profile: dict[str, Any],
    expected_tokens: int,
    torch_module: Any,
) -> tuple[list[np.ndarray], list[bytes]]:
    cache_layers = getattr(cache, "layers", None)
    require(
        isinstance(cache_layers, (list, tuple))
        and len(cache_layers) == int(profile["geometry"]["layers"]),
        "cache layer count differs",
    )
    kv_heads = int(profile["geometry"]["kvHeads"])
    head_dimension = int(profile["geometry"]["headDimension"])
    matrices: list[np.ndarray] = []
    raw_layers: list[bytes] = []
    for index, layer in enumerate(cache_layers):
        keys, values = _cache_layer_tensors(layer)
        expected = (1, kv_heads, expected_tokens, head_dimension)
        require(
            tuple(keys.shape) == expected and tuple(values.shape) == expected,
            f"cache layer {index} shape differs",
        )
        require(
            keys.dtype == torch_module.bfloat16
            and values.dtype == torch_module.bfloat16,
            f"cache layer {index} is not BF16",
        )
        require(
            bool(torch_module.isfinite(keys).all())
            and bool(torch_module.isfinite(values).all()),
            f"cache layer {index} contains non-finite values",
        )
        key_rows = (
            keys[0]
            .permute(1, 0, 2)
            .contiguous()
            .reshape(expected_tokens, kv_heads * head_dimension)
        )
        value_rows = (
            values[0]
            .permute(1, 0, 2)
            .contiguous()
            .reshape(expected_tokens, kv_heads * head_dimension)
        )
        joined = torch_module.cat((key_rows, value_rows), dim=1).contiguous().cpu()
        raw_layers.append(
            joined.view(torch_module.uint16)
            .numpy()
            .astype("<u2", copy=False)
            .tobytes()
        )
        matrices.append(np.ascontiguousarray(joined.float().numpy(), dtype=np.float32))
    return matrices, raw_layers


def _cache_digest(raw_layers: list[bytes]) -> str:
    digest = hashlib.sha256()
    for index, raw in enumerate(raw_layers):
        digest.update(index.to_bytes(4, "little"))
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def _dynamic_cache_from_layers(
    model: Any, layers: list[np.ndarray], profile: dict[str, Any], torch_module: Any
) -> Any:
    from transformers import DynamicCache

    expected_tokens = int(profile["maxPrefillTokens"])
    kv_heads = int(profile["geometry"]["kvHeads"])
    head_dimension = int(profile["geometry"]["headDimension"])
    key_width = kv_heads * head_dimension
    require(len(layers) == int(profile["geometry"]["layers"]), "replay cache layer count differs")
    cache = DynamicCache(config=model.config)
    for index, matrix in enumerate(layers):
        require(
            matrix.dtype == np.float32
            and matrix.shape == (expected_tokens, 2 * key_width)
            and np.isfinite(matrix).all(),
            f"replay cache layer {index} matrix differs",
        )
        keys = (
            torch_module.from_numpy(np.ascontiguousarray(matrix[:, :key_width]))
            .to(device="cuda:0", dtype=torch_module.bfloat16)
            .reshape(expected_tokens, kv_heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .contiguous()
        )
        values = (
            torch_module.from_numpy(np.ascontiguousarray(matrix[:, key_width:]))
            .to(device="cuda:0", dtype=torch_module.bfloat16)
            .reshape(expected_tokens, kv_heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .contiguous()
        )
        cache.update(keys, values, index)
    require(int(cache.get_seq_length()) == expected_tokens, "rebuilt cache length differs")
    return cache


def _forward_kwargs(
    model: Any,
    cache: Any,
    input_tokens: int,
    torch_module: Any,
    *,
    use_cache: bool,
) -> dict[str, Any]:
    cached = int(cache.get_seq_length())
    positions = torch_module.arange(
        cached,
        cached + input_tokens,
        dtype=torch_module.long,
        device="cuda:0",
    )
    kwargs: dict[str, Any] = {
        "past_key_values": cache,
        "attention_mask": torch_module.ones(
            (1, cached + input_tokens), dtype=torch_module.long, device="cuda:0"
        ),
        "use_cache": use_cache,
        "return_dict": True,
    }
    if model.config.model_type in {
        "qwen2",
        "llama",
        "mistral",
        "gpt_neox",
        "gpt2",
        "gemma",
    }:
        kwargs["position_ids"] = positions.unsqueeze(0)
    if model.config.model_type in {"qwen2", "llama", "mistral", "gemma"}:
        kwargs["cache_position"] = positions
    return kwargs


def _model_step(model: Any, token: Any, cache: Any, torch_module: Any) -> tuple[Any, Any]:
    before = int(cache.get_seq_length())
    with torch_module.inference_mode():
        output = model(
            token,
            **_forward_kwargs(
                model,
                cache,
                int(token.shape[1]),
                torch_module,
                use_cache=True,
            ),
        )
    updated = output.past_key_values
    require(
        int(updated.get_seq_length()) == before + int(token.shape[1]),
        "replay cache did not advance exactly",
    )
    logits = output.logits[:, -1, :].float()
    require(bool(torch_module.isfinite(logits).all()), "model produced non-finite logits")
    return logits, updated


def _controlled_metrics(
    model: Any,
    tokenizer: Any,
    canonical: list[np.ndarray],
    reconstructed: list[np.ndarray],
    profile: dict[str, Any],
    last_prompt_token: int,
    torch_module: Any,
) -> dict[str, Any]:
    baseline_cache = _dynamic_cache_from_layers(model, canonical, profile, torch_module)
    candidate_cache = _dynamic_cache_from_layers(
        model, reconstructed, profile, torch_module
    )
    current = torch_module.tensor(
        [[last_prompt_token]], dtype=torch_module.long, device="cuda:0"
    )
    baseline_tokens: list[int] = []
    controlled_candidate: list[int] = []
    agreements = 0
    kl_sum = 0.0
    surprisal_sum = 0.0
    maximum_difference = 0.0
    per_token_kl: list[float] = []
    per_token_surprisal: list[float] = []
    per_token_max_difference: list[float] = []
    for _ in range(HORIZON):
        baseline_logits, baseline_cache = _model_step(
            model, current, baseline_cache, torch_module
        )
        candidate_logits, candidate_cache = _model_step(
            model, current, candidate_cache, torch_module
        )
        baseline_logp = torch_module.log_softmax(baseline_logits, dim=-1)
        candidate_logp = torch_module.log_softmax(candidate_logits, dim=-1)
        baseline_top = int(torch_module.argmax(baseline_logits, dim=-1).item())
        candidate_top = int(torch_module.argmax(candidate_logits, dim=-1).item())
        baseline_tokens.append(baseline_top)
        controlled_candidate.append(candidate_top)
        agreements += int(baseline_top == candidate_top)
        token_kl = float(
            (baseline_logp.exp() * (baseline_logp - candidate_logp)).sum().item()
        )
        token_surprisal = float(
            (-candidate_logp[0, baseline_top] + baseline_logp[0, baseline_top]).item()
        )
        token_max_difference = float(
            (baseline_logits - candidate_logits).abs().max().item()
        )
        require(
            math.isfinite(token_kl)
            and math.isfinite(token_surprisal)
            and math.isfinite(token_max_difference),
            "replay behavior metric is non-finite",
        )
        per_token_kl.append(token_kl)
        per_token_surprisal.append(token_surprisal)
        per_token_max_difference.append(token_max_difference)
        kl_sum += token_kl
        surprisal_sum += token_surprisal
        maximum_difference = max(maximum_difference, token_max_difference)
        current = torch_module.tensor(
            [[baseline_top]], dtype=torch_module.long, device="cuda:0"
        )
    del baseline_cache, candidate_cache

    candidate_free_cache = _dynamic_cache_from_layers(
        model, reconstructed, profile, torch_module
    )
    current = torch_module.tensor(
        [[last_prompt_token]], dtype=torch_module.long, device="cuda:0"
    )
    candidate_free: list[int] = []
    for _ in range(HORIZON):
        logits, candidate_free_cache = _model_step(
            model, current, candidate_free_cache, torch_module
        )
        token = int(torch_module.argmax(logits, dim=-1).item())
        candidate_free.append(token)
        current = torch_module.tensor([[token]], dtype=torch_module.long, device="cuda:0")
    common_prefix = 0
    for baseline_token, candidate_token in zip(baseline_tokens, candidate_free):
        if baseline_token != candidate_token:
            break
        common_prefix += 1
    return {
        "predictionTokens": HORIZON,
        "controlledTop1AgreementCount": agreements,
        "controlledTop1Agreement": agreements / HORIZON,
        "meanKLDivergenceNat": kl_sum / HORIZON,
        "meanBaselineSelectedTokenSurprisalDeltaNat": surprisal_sum / HORIZON,
        "maxAbsLogitDifference": maximum_difference,
        "perTokenKLDivergenceNat": per_token_kl,
        "perTokenBaselineSelectedTokenSurprisalDeltaNat": per_token_surprisal,
        "perTokenMaxAbsLogitDifference": per_token_max_difference,
        "baselineTokenIds": baseline_tokens,
        "controlledCandidateTop1TokenIds": controlled_candidate,
        "candidateFreeRunTokenIds": candidate_free,
        "freeRunExact": baseline_tokens == candidate_free,
        "freeRunSamePositionCount": sum(
            left == right for left, right in zip(baseline_tokens, candidate_free)
        ),
        "freeRunLongestCommonPrefixTokens": common_prefix,
        "baselineContinuation": tokenizer.decode(
            baseline_tokens, clean_up_tokenization_spaces=False
        ),
        "candidateFreeRunContinuation": tokenizer.decode(
            candidate_free, clean_up_tokenization_spaces=False
        ),
    }


def _compare_behavior(observed: dict[str, Any], recorded: dict[str, Any]) -> None:
    for name in (
        "predictionTokens",
        "controlledTop1AgreementCount",
        "baselineTokenIds",
        "controlledCandidateTop1TokenIds",
        "candidateFreeRunTokenIds",
        "freeRunExact",
        "freeRunSamePositionCount",
        "freeRunLongestCommonPrefixTokens",
        "baselineContinuation",
        "candidateFreeRunContinuation",
    ):
        require(observed[name] == recorded[name], f"replayed {name} differs")
    for name in (
        "controlledTop1Agreement",
        "meanKLDivergenceNat",
        "meanBaselineSelectedTokenSurprisalDeltaNat",
        "maxAbsLogitDifference",
    ):
        _close(observed[name], recorded[name], f"replayed {name}")
    for name in (
        "perTokenKLDivergenceNat",
        "perTokenBaselineSelectedTokenSurprisalDeltaNat",
        "perTokenMaxAbsLogitDifference",
    ):
        require(
            len(observed[name]) == len(recorded[name]) == HORIZON,
            f"replayed {name} length differs",
        )
        for index, (left, right) in enumerate(
            zip(observed[name], recorded[name])
        ):
            _close(left, right, f"replayed {name}[{index}]")


def _selected_converted_receipt(
    path: Path, profile: dict[str, Any]
) -> dict[str, Any] | None:
    receipt = _bounded_json(path, "asset verification receipt")
    _exact_object(
        receipt,
        {"schemaVersion", "status", "modelOrder", "profilesSHA256", "profiles"},
        "asset verification receipt",
    )
    require(receipt["status"] == "ASSETS_VERIFIED", "asset receipt status differs")
    require(receipt["modelOrder"] == list(MODEL_ORDER), "asset receipt model order differs")
    require(
        receipt["profilesSHA256"] == sha256_file(PROFILES_PATH),
        "asset receipt profile digest differs",
    )
    entries = receipt["profiles"]
    require(isinstance(entries, list) and len(entries) == len(MODEL_ORDER), "asset receipt profile count differs")
    position = list(MODEL_ORDER).index(profile["modelId"])
    entry = entries[position]
    _exact_object(
        entry,
        {"modelId", "repository", "revision", "files", "convertedWeights"},
        "selected asset receipt profile",
    )
    require(
        (entry["modelId"], entry["repository"], entry["revision"])
        == (profile["modelId"], profile["repository"], profile["revision"]),
        "selected asset receipt identity differs",
    )
    converted = entry["convertedWeights"]
    if profile.get("weightConversion") is None:
        require(converted is None, "selected asset receipt has unexpected converted weights")
        return None
    _exact_object(
        converted,
        {
            "bytes",
            "conversion",
            "environment",
            "path",
            "sha256",
            "sourcePath",
            "sourceSha256",
            "sourceTensorEqualityVerified",
        },
        "selected converted weight receipt",
    )
    require(converted["conversion"] == profile["weightConversion"], "selected conversion contract differs")
    require(converted["path"] == "model.safetensors", "selected converted weight path differs")
    require_int(converted["bytes"], "selected converted weight bytes", 9)
    require_digest(converted["sha256"], "selected converted weight SHA-256")
    require(converted["sourceTensorEqualityVerified"] is True, "selected conversion equality proof is absent")
    return converted


def _selected_replay_context(
    *,
    codec_root: Path,
    cache: Path,
    assets_path: Path,
    preflight_path: Path,
    run_dir: Path,
    structural_path: Path,
    model_id: str,
    workload_id: str,
) -> dict[str, Any]:
    """Bind one replay to the prior full structural receipt without decoding 28 cells again."""

    codec_root = codec_root.resolve(strict=True)
    codec = validate_codec_root(codec_root)
    source = _source_identity()
    profiles = load_profiles()
    workloads = load_workloads()
    cache_root = _safe_directory(cache, "asset cache")
    asset_receipt_digest = _verify_sidecar(assets_path)
    preflight, preflight_digest, preflight_cells = _verify_preflight(
        preflight_path,
        profiles=profiles,
        workloads=workloads,
        source=source,
        codec=codec,
        asset_receipt_digest=asset_receipt_digest,
    )
    run_root = _safe_directory(run_dir, "run directory")
    run_path = run_root / "run.json"
    run = _bounded_json(run_path, "run manifest")
    run_digest = _verify_sidecar(run_path)
    _exact_object(
        run,
        {
            "schemaVersion",
            "runId",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "source",
            "preflightSHA256",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
            "expectedCells",
            "completeCells",
            "cells",
        },
        "run manifest",
    )
    require(run["schemaVersion"] == RUN_SCHEMA_VERSION, "run schema differs")
    require(run["status"] == "COMPLETE", "run is not complete")
    require(run["classification"] == CLASSIFICATION, "run classification differs")
    require(run["countsTowardScientificVerdict"] is False, "run makes a scientific claim")
    require(run["source"] == source == preflight["source"], "run source identity differs")
    require(run["preflightSHA256"] == preflight_digest, "run preflight digest differs")
    require(run["assetReceiptSHA256"] == asset_receipt_digest, "run asset receipt differs")
    require(run["profilesSHA256"] == sha256_file(PROFILES_PATH), "run profile digest differs")
    require(run["workloadsSHA256"] == sha256_file(WORKLOADS_PATH), "run workload digest differs")
    require(run["protocolSHA256"] == sha256_file(PROTOCOL_PATH), "run protocol digest differs")
    workload_order = [entry["workloadId"] for entry in workloads["workloads"]]
    expected_pairs = [
        (registered_model, registered_workload)
        for registered_model in MODEL_ORDER
        for registered_workload in workload_order
    ]
    require(run["expectedCells"] == run["completeCells"] == len(expected_pairs) == 28, "run cell counts differ")
    records = run["cells"]
    require(isinstance(records, list) and len(records) == 28, "run cell records differ")
    for position, (record, pair) in enumerate(zip(records, expected_pairs)):
        require(
            (record.get("modelId"), record.get("workloadId")) == pair,
            f"run cell {position} order differs",
        )

    structural = _bounded_json(structural_path, "structural verification receipt")
    structural_digest = _verify_sidecar(structural_path)
    _exact_object(
        structural,
        {
            "schemaVersion",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "modelReplayPerformed",
            "runId",
            "runSHA256",
            "preflightSHA256",
            "assetReceiptSHA256",
            "cells",
            "containers",
            "containerBytes",
        },
        "structural verification receipt",
    )
    require(structural["schemaVersion"] == VERIFY_SCHEMA, "structural receipt schema differs")
    require(structural["status"] == "STRUCTURALLY_VERIFIED", "structural receipt status differs")
    require(structural["classification"] == CLASSIFICATION, "structural receipt classification differs")
    require(structural["countsTowardScientificVerdict"] is False, "structural receipt makes a scientific claim")
    require(structural["modelReplayPerformed"] is False, "structural receipt falsely records model replay")
    require(structural["runId"] == run["runId"], "structural receipt run ID differs")
    require(structural["runSHA256"] == run_digest, "structural receipt run digest differs")
    require(structural["preflightSHA256"] == preflight_digest, "structural receipt preflight digest differs")
    require(structural["assetReceiptSHA256"] == asset_receipt_digest, "structural receipt asset digest differs")
    require(structural["cells"] == 28, "structural receipt cell count differs")
    require_int(structural["containers"], "structural receipt containers", 1)
    require_int(structural["containerBytes"], "structural receipt bytes", 1)

    pair = (model_id, workload_id)
    require(pair in expected_pairs, "selected replay cell is not registered")
    position = expected_pairs.index(pair)
    profile = profile_by_id(model_id)
    converted_receipt = _selected_converted_receipt(assets_path, profile)
    backend = _load_codec(codec_root)
    result, _, _, _ = _verify_cell(
        run_root=run_root,
        record=records[position],
        profile=profile,
        expected_preflight=preflight_cells[pair],
        codec=codec,
        source=source,
        run_id=run["runId"],
        preflight_digest=preflight_digest,
        asset_receipt_digest=asset_receipt_digest,
        backend=backend,
    )
    return {
        "preflightSHA256": preflight_digest,
        "assetReceiptSHA256": asset_receipt_digest,
        "runSHA256": run_digest,
        "structuralVerificationSHA256": structural_digest,
        "_internal": {
            "workloads": workloads,
            "preflightCells": preflight_cells,
            "cellResults": {pair: result},
            "cacheRoot": cache_root,
            "runRoot": run_root,
            "backend": backend,
            "convertedWeights": converted_receipt,
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
    model_id: str,
    workload_id: str,
) -> dict[str, Any]:
    verification = _selected_replay_context(
        codec_root=codec_root,
        cache=cache,
        assets_path=assets_path,
        preflight_path=preflight_path,
        run_dir=run_dir,
        structural_path=structural_path,
        model_id=model_id,
        workload_id=workload_id,
    )
    internal = verification["_internal"]
    pair = (model_id, workload_id)
    require(pair in internal["cellResults"], "selected replay cell is not registered")
    profile = profile_by_id(model_id)
    workload_matches = [
        entry
        for entry in internal["workloads"]["workloads"]
        if entry["workloadId"] == workload_id
    ]
    require(len(workload_matches) == 1, "selected workload is absent or duplicated")
    workload = workload_matches[0]
    result = internal["cellResults"][pair]
    preflight_cell = internal["preflightCells"][pair]
    torch_module = _configure_torch()
    torch_module.cuda.reset_peak_memory_stats()
    model, tokenizer, _ = _load_model_and_tokenizer(
        profile,
        internal["cacheRoot"],
        torch_module,
        internal["convertedWeights"],
    )
    text, inventory = workload_text(workload)
    require(inventory == result["workload"]["sourceFiles"], "replay source inventory differs")
    require(
        sha256_bytes(text.encode("utf-8")) == result["workload"]["promptUTF8SHA256"],
        "replay prompt digest differs",
    )
    token_ids = _tokenizer_ids(tokenizer, text)
    prefill_tokens = int(profile["maxPrefillTokens"])
    required = prefill_tokens + 1
    require(len(token_ids) == preflight_cell["availableTokens"], "replay tokenizer length differs")
    require(len(token_ids) >= required, "replay workload is too short")
    selected = token_ids[:required]
    require(
        _token_digest(selected) == preflight_cell["tokenIdsU32LESHA256"],
        "replay selected-token digest differs",
    )
    prefix = torch_module.tensor(
        [selected[:prefill_tokens]], dtype=torch_module.long, device="cuda:0"
    )
    last_prompt_token = int(selected[prefill_tokens])
    from transformers import DynamicCache

    with torch_module.inference_mode():
        prefill = model(
            prefix,
            past_key_values=DynamicCache(config=model.config),
            use_cache=True,
            return_dict=True,
        )
    native_cache = prefill.past_key_values
    require(int(native_cache.get_seq_length()) == prefill_tokens, "replay prefill cache length differs")
    native_layers = getattr(native_cache, "layers", None)
    require(
        isinstance(native_layers, (list, tuple))
        and len(native_layers) == int(profile["geometry"]["layers"]),
        "replay cache layer inventory differs",
    )
    replay_layer_classes = sorted(
        {
            f"{type(layer).__module__}.{type(layer).__name__}"
            for layer in native_layers
        }
    )
    require(len(replay_layer_classes) == 1, "replay cache layer classes differ")
    replay_cache_observation = {
        "cacheClass": f"{type(native_cache).__module__}.{type(native_cache).__name__}",
        "layerClass": replay_layer_classes[0],
        "tensorLayout": "batch,kv_head,token,head_dimension",
        "batchSize": 1,
        "layers": int(profile["geometry"]["layers"]),
        "kvHeads": int(profile["geometry"]["kvHeads"]),
        "headDimension": int(profile["geometry"]["headDimension"]),
        "dtype": "bfloat16",
        "targetContextTokens": int(profile["gpuAdmission"]["maxInputTokens"]),
        "prefillTokens": prefill_tokens,
        "finalPromptTokens": 1,
        "continuationTokens": HORIZON,
        "effectiveCacheTokens": prefill_tokens,
        "evictedTokens": 0,
    }
    require(
        replay_cache_observation == result["cacheObservation"],
        "replayed cache observation differs",
    )
    canonical, raw_layers = _extract_canonical_layers(
        native_cache, profile, prefill_tokens, torch_module
    )
    direct_token = torch_module.tensor(
        [[last_prompt_token]], dtype=torch_module.long, device="cuda:0"
    )
    direct_logits, direct_cache = _model_step(
        model, direct_token, native_cache, torch_module
    )
    require(
        _cache_digest(raw_layers) == result["canonicalCacheBF16SHA256"],
        "replayed canonical BF16 cache digest differs",
    )
    rebuilt_cache = _dynamic_cache_from_layers(model, canonical, profile, torch_module)
    rebuilt_logits, rebuilt_cache = _model_step(
        model, direct_token, rebuilt_cache, torch_module
    )
    structural_difference = float((direct_logits - rebuilt_logits).abs().max().item())
    structural_top1 = bool(
        torch_module.equal(
            direct_logits.argmax(dim=-1), rebuilt_logits.argmax(dim=-1)
        )
    )
    require(
        structural_difference == 0.0 and structural_top1,
        "fresh flatten/rebuild replay is not exact",
    )
    require(
        result["structuralReplay"]
        == {
            "maxAbsLogitDifference": structural_difference,
            "top1Identical": structural_top1,
        },
        "recorded structural replay differs",
    )
    del native_cache, direct_cache, prefill, rebuilt_cache, direct_logits, rebuilt_logits
    torch_module.cuda.empty_cache()
    cell_root = internal["runRoot"] / "cells" / model_id / workload_id
    _, reconstructed = _decode_containers(
        cell_root=cell_root,
        result=result,
        profile=profile,
        backend=internal["backend"],
        retain_layers=True,
    )
    observed_behavior = _controlled_metrics(
        model,
        tokenizer,
        canonical,
        reconstructed,
        profile,
        last_prompt_token,
        torch_module,
    )
    _compare_behavior(observed_behavior, result["behavior"])
    result_path = cell_root / "result.json"
    report = {
        "schemaVersion": REPLAY_SCHEMA,
        "status": "MODEL_REPLAY_VERIFIED",
        "classification": CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "modelId": model_id,
        "workloadId": workload_id,
        "resultSHA256": sha256_file(result_path),
        "preflightSHA256": verification["preflightSHA256"],
        "assetReceiptSHA256": verification["assetReceiptSHA256"],
        "runSHA256": verification["runSHA256"],
        "structuralVerificationSHA256": verification[
            "structuralVerificationSHA256"
        ],
        "predictionTokens": HORIZON,
        "canonicalCacheBF16SHA256": result["canonicalCacheBF16SHA256"],
        "structuralReplayExact": True,
        "controlledTop1Agreement": observed_behavior[
            "controlledTop1Agreement"
        ],
        "meanKLDivergenceNat": observed_behavior["meanKLDivergenceNat"],
        "meanBaselineSelectedTokenSurprisalDeltaNat": observed_behavior[
            "meanBaselineSelectedTokenSurprisalDeltaNat"
        ],
        "baselineContinuationSHA256": sha256_bytes(
            observed_behavior["baselineContinuation"].encode("utf-8")
        ),
        "candidateContinuationSHA256": sha256_bytes(
            observed_behavior["candidateFreeRunContinuation"].encode("utf-8")
        ),
        "device": "cuda:0",
        "gpuName": torch_module.cuda.get_device_name(0),
        "gpuDriverVersion": _gpu_driver_version(),
        "peakAllocatedBytes": int(torch_module.cuda.max_memory_allocated()),
    }
    require(
        report["gpuDriverVersion"] == result["runtime"]["gpuDriverVersion"],
        "replay NVIDIA driver version differs from the producing cell",
    )
    del model, tokenizer, canonical, reconstructed
    gc.collect()
    torch_module.cuda.empty_cache()
    return report


def _public_summary(verification: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in verification.items() if key != "_internal"}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify-run")
    replay = commands.add_parser("replay-cell")
    for command in (verify, replay):
        command.add_argument("--codec-root", type=Path, required=True)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--assets", type=Path, required=True)
        command.add_argument("--preflight", type=Path, required=True)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    replay.add_argument("--model-id", choices=MODEL_ORDER, required=True)
    replay.add_argument("--workload-id", required=True)
    replay.add_argument("--structural", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    global np
    arguments = parse_arguments()
    import numpy as numpy_module

    np = numpy_module
    if arguments.command == "verify-run":
        result = _public_summary(
            verify_run(
                codec_root=arguments.codec_root,
                cache=arguments.cache,
                assets_path=arguments.assets,
                preflight_path=arguments.preflight,
                run_dir=arguments.run_dir,
            )
        )
    elif arguments.command == "replay-cell":
        result = replay_cell(
            codec_root=arguments.codec_root,
            cache=arguments.cache,
            assets_path=arguments.assets,
            preflight_path=arguments.preflight,
            run_dir=arguments.run_dir,
            structural_path=arguments.structural,
            model_id=arguments.model_id,
            workload_id=arguments.workload_id,
        )
    else:
        raise AssertionError(arguments.command)
    write_canonical_json(arguments.output, result)
    print(canonical_json_bytes(result).decode("utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ADAPTER SWEEP VERIFICATION FAIL: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
