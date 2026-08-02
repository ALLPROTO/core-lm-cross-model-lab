#!/usr/bin/env python3
"""Run one isolated real-data cross-model VoidToken v5 regression cell."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# These controls must exist before importing Torch, NumPy, or Transformers.
os.environ.setdefault("PYTORCH_MPS_HIGH_WATERMARK_RATIO", "0.85")
os.environ.setdefault("PYTORCH_MPS_LOW_WATERMARK_RATIO", "0.75")
os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "0")
os.environ.setdefault("OMP_NUM_THREADS", "2")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
os.environ.setdefault("MKL_NUM_THREADS", "2")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "2")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "2")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

import numpy as np


LAB_ROOT = Path(__file__).resolve().parent
MODEL_MATRIX_PATH = LAB_ROOT / "models.json"
EXPECTED_REPOSITORY_COMMIT = "61afcf1a44007dec54bd1c56e3403bc74182a400"
EXPECTED_SOURCE_SHA256 = {
    "RealLLM/beacon_registration.json": (
        "7c0cb4cf544773041be84e75de4314c72769c71682e1b138b99ea85996cc5779"
    ),
    "RealLLM/benchmark_real_llm.py": (
        "b5e7b301222501e148d54cda3f0d04997e6a061051cedc6393d1a87b638522d0"
    ),
    "RealLLM/codecs.py": (
        "fe5763b7cb0b2e775436c7414a1af48704095518e0428fe4a7965b84f0ce7a05"
    ),
    "RealLLM/requirements.lock": (
        "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561"
    ),
    "RealLLM/voidtoken_v5.py": (
        "80ed51aa2a201dbdaae36434709a50a8a679fa84d29b08ad7b083c14cec33758"
    ),
}
EXPECTED_CONFIGURATION_SHA256 = (
    "4c7be8c836aa725722b51f66dce78af7a5094e887432e622b5322f7ca2cf0af8"
)
BLOCK_TOKENS = 512
PREFILL_TOKENS = 383
PREDICTION_TOKENS = 128
DEFAULT_START_BLOCK = 64
DEFAULT_BLOCKS = 1


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def exclusive_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def command_output(arguments: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def validate_codec_source(codec_root: Path) -> dict[str, Any]:
    codec_root = codec_root.resolve()
    if not (codec_root / ".git").exists():
        raise RuntimeError("codec root is not a Git worktree")
    commit = command_output(["git", "rev-parse", "HEAD"], codec_root)
    if commit != EXPECTED_REPOSITORY_COMMIT:
        raise RuntimeError(
            f"codec source commit mismatch: {commit} != "
            f"{EXPECTED_REPOSITORY_COMMIT}"
        )
    manifest: dict[str, Any] = {"commit": commit, "files": {}}
    for relative, expected in EXPECTED_SOURCE_SHA256.items():
        path = codec_root / relative
        observed = sha256_file(path)
        if observed != expected:
            raise RuntimeError(f"codec source digest mismatch: {relative}")
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", relative],
            cwd=codec_root,
        ).returncode
        if dirty != 0:
            raise RuntimeError(f"codec source file has local changes: {relative}")
        manifest["files"][relative] = {
            "bytes": path.stat().st_size,
            "sha256": observed,
        }
    return manifest


def load_fixed_configuration(codec_root: Path) -> dict[str, Any]:
    registration = load_json(codec_root / "RealLLM/beacon_registration.json")
    configuration = registration.get("configuration")
    if not isinstance(configuration, dict):
        raise RuntimeError("registration configuration is missing")
    digest = sha256_bytes(canonical_json_bytes(configuration))
    if digest != EXPECTED_CONFIGURATION_SHA256:
        raise RuntimeError("registered configuration digest mismatch")
    if registration.get("configurationSHA256") != digest:
        raise RuntimeError("registration configuration commitment mismatch")
    schedule = configuration.get("bitsByLayer")
    if (
        not isinstance(schedule, list)
        or len(schedule) != 24
        or any(type(bits) is not int or bits not in {8, 9} for bits in schedule)
    ):
        raise RuntimeError("fixed candidate must contain exactly 24 8/9-bit layers")
    return configuration


def check_power_and_memory(device: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if platform.system() == "Darwin":
        battery = command_output(["pmset", "-g", "batt"])
        result["power"] = battery
        if device == "mps" and "AC Power" not in battery:
            raise RuntimeError(
                "NOT_RUN_SAFETY_ABORT: connect AC power before MPS inference"
            )
        memory = command_output(["memory_pressure", "-Q"])
        result["memoryPressure"] = memory
        match = re.search(r"free percentage:\s*(\d+)%", memory)
        if match is None or int(match.group(1)) < 30:
            raise RuntimeError(
                "NOT_RUN_SAFETY_ABORT: memory free percentage is below 30%"
            )
        result["thermal"] = command_output(["pmset", "-g", "therm"])
    return result


def verify_asset(path: Path, specification: dict[str, Any], label: str) -> None:
    if path.stat().st_size != int(specification["bytes"]):
        raise RuntimeError(f"asset size mismatch: {label}")
    if sha256_file(path) != specification["sha256"]:
        raise RuntimeError(f"asset SHA-256 mismatch: {label}")


def resolve_assets(
    model_specification: dict[str, Any],
    dataset_specification: dict[str, Any],
    cache_dir: Path,
    *,
    local_files_only: bool,
) -> tuple[Path, Path, dict[str, Any]]:
    from huggingface_hub import hf_hub_download

    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cache_dir, 0o700)
    files: dict[str, Any] = {}
    snapshot: Path | None = None
    for filename, specification in model_specification["files"].items():
        path = Path(
            hf_hub_download(
                model_specification["repository"],
                revision=model_specification["revision"],
                filename=filename,
                cache_dir=cache_dir,
                local_files_only=local_files_only,
                token=False,
            )
        )
        verify_asset(path, specification, f"model/{filename}")
        files[f"model/{filename}"] = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        if filename == "model.safetensors":
            snapshot = path.parent
    if snapshot is None:
        raise RuntimeError("model snapshot could not be resolved")
    dataset_path = Path(
        hf_hub_download(
            dataset_specification["repository"],
            repo_type="dataset",
            revision=dataset_specification["revision"],
            filename=dataset_specification["file"],
            cache_dir=cache_dir,
            local_files_only=local_files_only,
            token=False,
        )
    )
    verify_asset(dataset_path, dataset_specification, "dataset/validation")
    files["dataset/validation"] = {
        "bytes": dataset_path.stat().st_size,
        "sha256": sha256_file(dataset_path),
    }
    return snapshot, dataset_path, {"files": files}


def token_blocks(
    tokenizer: Any,
    parquet_path: Path,
    *,
    start_block: int,
    blocks: int,
) -> tuple[list[list[int]], bytes, dict[str, Any]]:
    import pyarrow.parquet as parquet

    rows = parquet.read_table(parquet_path, columns=["text"]).column("text")
    corpus = "\n\n".join(rows.to_pylist())
    previous_maximum = tokenizer.model_max_length
    tokenizer.model_max_length = sys.maxsize
    try:
        token_ids = tokenizer(
            corpus,
            add_special_tokens=False,
            return_attention_mask=False,
            return_token_type_ids=False,
        )["input_ids"]
    finally:
        tokenizer.model_max_length = previous_maximum
    if any(type(token_id) is not int or token_id < 0 for token_id in token_ids):
        raise RuntimeError("tokenizer produced invalid token IDs")
    all_bytes = np.asarray(token_ids, dtype="<u4").tobytes()
    required = (start_block + blocks) * BLOCK_TOKENS
    if len(token_ids) < required:
        raise RuntimeError("validation token stream is too short")
    selected = token_ids[start_block * BLOCK_TOKENS : required]
    selected_bytes = np.asarray(selected, dtype="<u4").tobytes()
    selections = [
        selected[offset : offset + BLOCK_TOKENS]
        for offset in range(0, len(selected), BLOCK_TOKENS)
    ]
    inventory = {
        "joinSeparator": "\\n\\n",
        "normalization": "none",
        "rowOrder": "stored-order",
        "addSpecialTokens": False,
        "tokenCount": len(token_ids),
        "fullBlocks": len(token_ids) // BLOCK_TOKENS,
        "remainderTokens": len(token_ids) % BLOCK_TOKENS,
        "allTokenIdsSHA256": sha256_bytes(all_bytes),
        "startBlock": start_block,
        "blocks": blocks,
        "selectedTokenIds": len(selected),
        "selectedTokenIdsSHA256": sha256_bytes(selected_bytes),
        "rawCorpusUTF8SHA256": sha256_bytes(corpus.encode("utf-8")),
    }
    return selections, selected_bytes, inventory


def model_geometry(model: Any) -> dict[str, int | str]:
    config = model.config
    model_type = str(config.model_type)
    if model_type == "gpt2":
        layers = int(config.n_layer)
        attention_heads = int(config.n_head)
        hidden_size = int(config.n_embd)
        kv_heads = attention_heads
    elif model_type == "bloom":
        layers = int(config.n_layer)
        attention_heads = int(config.num_attention_heads)
        hidden_size = int(config.hidden_size)
        kv_heads = attention_heads
    else:
        layers = int(config.num_hidden_layers)
        attention_heads = int(config.num_attention_heads)
        hidden_size = int(config.hidden_size)
        kv_heads = int(getattr(config, "num_key_value_heads", attention_heads))
    if hidden_size % attention_heads:
        raise RuntimeError("hidden size is not divisible by attention heads")
    return {
        "modelType": model_type,
        "layers": layers,
        "attentionHeads": attention_heads,
        "kvHeads": kv_heads,
        "headDimension": hidden_size // attention_heads,
        "hiddenSize": hidden_size,
    }


def validate_model_geometry(
    observed: dict[str, int | str], expected: dict[str, Any]
) -> None:
    fields = (
        "modelType",
        "layers",
        "attentionHeads",
        "kvHeads",
        "headDimension",
        "hiddenSize",
    )
    for field in fields:
        if observed[field] != expected[field]:
            raise RuntimeError(
                f"model geometry mismatch for {field}: "
                f"{observed[field]} != {expected[field]}"
            )


def extract_cache_layers(
    dynamic_cache: Any,
    *,
    expected_layers: int,
    expected_kv_heads: int,
    expected_head_dimension: int,
    torch_module: Any,
) -> tuple[list[np.ndarray], list[np.ndarray], list[bytes], list[dict[str, int]]]:
    if not hasattr(dynamic_cache, "layers"):
        raise RuntimeError("model did not return a DynamicCache")
    if len(dynamic_cache.layers) != expected_layers:
        raise RuntimeError("cache layer count differs from model configuration")
    original: list[np.ndarray] = []
    canonical: list[np.ndarray] = []
    canonical_bytes: list[bytes] = []
    layouts: list[dict[str, int]] = []
    for layer_index, layer in enumerate(dynamic_cache.layers):
        keys = layer.keys.detach().float().cpu()
        values = layer.values.detach().float().cpu()
        expected_shape = (
            1,
            expected_kv_heads,
            PREFILL_TOKENS,
            expected_head_dimension,
        )
        if tuple(keys.shape) != expected_shape or tuple(values.shape) != expected_shape:
            raise RuntimeError(
                f"layer {layer_index} cache shape mismatch: {tuple(keys.shape)}"
            )
        if not torch_module.isfinite(keys).all() or not torch_module.isfinite(
            values
        ).all():
            raise RuntimeError(f"layer {layer_index} cache is non-finite")
        key_trajectory = (
            keys[0]
            .permute(1, 0, 2)
            .contiguous()
            .reshape(PREFILL_TOKENS, expected_kv_heads * expected_head_dimension)
        )
        value_trajectory = (
            values[0]
            .permute(1, 0, 2)
            .contiguous()
            .reshape(PREFILL_TOKENS, expected_kv_heads * expected_head_dimension)
        )
        joined = torch_module.cat((key_trajectory, value_trajectory), dim=1)
        if joined.shape[1] % 128:
            raise RuntimeError("cache trajectory width is not divisible by 128")
        original.append(np.ascontiguousarray(joined.numpy(), dtype=np.float32))
        bf16 = joined.to(torch_module.bfloat16).contiguous()
        canonical_bytes.append(
            bf16.view(torch_module.uint16)
            .numpy()
            .astype("<u2", copy=False)
            .tobytes()
        )
        canonical.append(
            np.ascontiguousarray(bf16.float().numpy(), dtype=np.float32)
        )
        layouts.append(
            {
                "kvHeads": expected_kv_heads,
                "headDimension": expected_head_dimension,
            }
        )
    return original, canonical, canonical_bytes, layouts


def dynamic_cache_from_layers(
    layers: list[np.ndarray],
    layouts: list[dict[str, int]],
    *,
    model: Any,
    device: str,
    torch_module: Any,
) -> Any:
    from transformers import DynamicCache

    if len(layers) != len(layouts) or len(layers) != 24:
        raise RuntimeError("decoded cache must contain exactly 24 layouts")
    cache = DynamicCache(config=model.config)
    for layer_index, (trajectory, layout) in enumerate(zip(layers, layouts)):
        heads = int(layout["kvHeads"])
        head_dimension = int(layout["headDimension"])
        key_width = heads * head_dimension
        if trajectory.shape != (PREFILL_TOKENS, 2 * key_width):
            raise RuntimeError("decoded cache trajectory has an invalid shape")
        keys = (
            torch_module.from_numpy(np.ascontiguousarray(trajectory[:, :key_width]))
            .reshape(PREFILL_TOKENS, heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .to(device)
        )
        values = (
            torch_module.from_numpy(np.ascontiguousarray(trajectory[:, key_width:]))
            .reshape(PREFILL_TOKENS, heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .to(device)
        )
        cache.update(keys, values, layer_index)
    if int(cache.get_seq_length()) != PREFILL_TOKENS:
        raise RuntimeError("rebuilt DynamicCache length mismatch")
    return cache


def continuation_logits(
    model: Any,
    continuation_ids: Any,
    cache: Any,
    *,
    device: str,
    torch_module: Any,
) -> tuple[Any, int]:
    cached_tokens = int(cache.get_seq_length())
    continuation_tokens = int(continuation_ids.shape[1])
    positions = torch_module.arange(
        cached_tokens,
        cached_tokens + continuation_tokens,
        dtype=torch_module.long,
        device=device,
    )
    kwargs: dict[str, Any] = {
        "past_key_values": cache,
        "attention_mask": torch_module.ones(
            (1, cached_tokens + continuation_tokens),
            dtype=torch_module.long,
            device=device,
        ),
        "use_cache": False,
        "return_dict": True,
    }
    if model.config.model_type in {"qwen2", "gpt_neox", "gpt2"}:
        kwargs["position_ids"] = positions.unsqueeze(0)
    if model.config.model_type in {"qwen2", "gpt_neox"}:
        kwargs["cache_position"] = positions
    started = time.perf_counter_ns()
    with torch_module.inference_mode():
        logits = model(continuation_ids, **kwargs).logits.float().cpu()
    return logits, time.perf_counter_ns() - started


def continuation_from_layers(
    model: Any,
    continuation_ids: Any,
    layers: list[np.ndarray],
    layouts: list[dict[str, int]],
    *,
    device: str,
    torch_module: Any,
) -> tuple[Any, int]:
    cache = dynamic_cache_from_layers(
        layers,
        layouts,
        model=model,
        device=device,
        torch_module=torch_module,
    )
    return continuation_logits(
        model,
        continuation_ids,
        cache,
        device=device,
        torch_module=torch_module,
    )


class ContainerWriter:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write_container(
        self, *, block_index: int, layer_index: int, container: bytes
    ) -> None:
        relative = Path("containers") / f"block-{block_index:06d}" / (
            f"layer-{layer_index:02d}.vtl5"
        )
        exclusive_write(self.root / relative, container)


def cache_digest(canonical_bytes: list[bytes]) -> str:
    digest = hashlib.sha256()
    for layer_index, raw in enumerate(canonical_bytes):
        digest.update(layer_index.to_bytes(4, "little"))
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def evaluate_block(
    token_ids: list[int],
    block_index: int,
    configuration: dict[str, Any],
    *,
    model: Any,
    geometry: dict[str, int | str],
    device: str,
    torch_module: Any,
    core: Any,
    writer: ContainerWriter,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ids_cpu = torch_module.tensor(token_ids, dtype=torch_module.long).unsqueeze(0)
    ids = ids_cpu.to(device)
    prefix_ids = ids[:, :PREFILL_TOKENS]
    continuation_ids = ids[:, PREFILL_TOKENS:-1]
    targets_cpu = ids_cpu[:, PREFILL_TOKENS + 1 :]
    if targets_cpu.numel() != PREDICTION_TOKENS:
        raise RuntimeError("block does not contain exactly 128 predictions")
    with torch_module.inference_mode():
        prefill = model(prefix_ids, use_cache=True, return_dict=True)
    original, canonical, canonical_bytes, layouts = extract_cache_layers(
        prefill.past_key_values,
        expected_layers=int(geometry["layers"]),
        expected_kv_heads=int(geometry["kvHeads"]),
        expected_head_dimension=int(geometry["headDimension"]),
        torch_module=torch_module,
    )
    direct_logits, direct_runtime = continuation_logits(
        model,
        continuation_ids,
        prefill.past_key_values,
        device=device,
        torch_module=torch_module,
    )
    if not torch_module.isfinite(direct_logits).all():
        raise RuntimeError(
            "MODEL_BASELINE_INVALID: direct uncompressed continuation "
            "contains non-finite logits before codec evaluation"
        )
    del prefill
    rebuilt_logits, rebuilt_runtime = continuation_from_layers(
        model,
        continuation_ids,
        original,
        layouts,
        device=device,
        torch_module=torch_module,
    )
    if not torch_module.isfinite(rebuilt_logits).all():
        raise RuntimeError(
            "MODEL_ADAPTER_INVALID: rebuilt uncompressed continuation "
            "contains non-finite logits before codec evaluation"
        )
    layout_difference = float((direct_logits - rebuilt_logits).abs().max().item())
    layout_top1 = bool(
        torch_module.equal(
            direct_logits.argmax(dim=-1), rebuilt_logits.argmax(dim=-1)
        )
    )
    if layout_difference != 0.0 or not layout_top1:
        raise RuntimeError(
            "flatten/rebuild changed the direct FP32 continuation: "
            f"maxAbsLogitDifference={layout_difference!r}, "
            f"top1Identical={layout_top1}"
        )
    baseline_logits, baseline_runtime = continuation_from_layers(
        model,
        continuation_ids,
        canonical,
        layouts,
        device=device,
        torch_module=torch_module,
    )
    if not torch_module.isfinite(baseline_logits).all():
        raise RuntimeError("canonical BF16 baseline contains non-finite logits")
    exact_logits, exact_runtime = continuation_from_layers(
        model,
        continuation_ids,
        [layer.copy() for layer in canonical],
        layouts,
        device=device,
        torch_module=torch_module,
    )
    exact_difference = float((baseline_logits - exact_logits).abs().max().item())
    exact_top1 = bool(
        torch_module.equal(
            baseline_logits.argmax(dim=-1), exact_logits.argmax(dim=-1)
        )
    )
    if exact_difference != 0.0 or not exact_top1:
        raise RuntimeError("canonical cache replay is not exact")
    token_digest = sha256_bytes(np.asarray(token_ids, dtype="<u4").tobytes())
    canonical_digest = cache_digest(canonical_bytes)
    direct_nll = core._nll(direct_logits, targets_cpu)
    baseline_nll = core._nll(baseline_logits, targets_cpu)
    native_agreements = int(
        (
            direct_logits.argmax(dim=-1)
            == baseline_logits.argmax(dim=-1)
        ).sum().item()
    )
    baseline = {
        "blockIndex": block_index,
        "tokenIdsSHA256": token_digest,
        "canonicalCacheBF16SHA256": canonical_digest,
        "layers": len(canonical),
        "kvHeads": int(geometry["kvHeads"]),
        "headDimension": int(geometry["headDimension"]),
        "trajectoryShapePerLayer": list(canonical[0].shape),
        "predictionTokens": PREDICTION_TOKENS,
        "denseBF16Bytes": sum(layer.size * 2 for layer in canonical),
        "originalFP32NLLNatPerToken": direct_nll,
        "canonicalBF16NLLNatPerToken": baseline_nll,
        "nativeBF16DeltaNLLNatPerToken": baseline_nll - direct_nll,
        "nativeBF16Top1Agreement": native_agreements / PREDICTION_TOKENS,
        "layoutRebuildMaxAbsLogitDifference": layout_difference,
        "layoutRebuildTop1Identical": layout_top1,
        "exactRebuildMaxAbsLogitDifference": exact_difference,
        "exactRebuildTop1Identical": exact_top1,
        "directContinuationNanoseconds": direct_runtime,
        "layoutRebuildContinuationNanoseconds": rebuilt_runtime,
        "baselineContinuationNanoseconds": baseline_runtime,
        "exactReplayContinuationNanoseconds": exact_runtime,
    }
    reconstructed, encoding = core._encode_layers(
        canonical,
        configuration,
        primary_evidence_writer=writer,
        block_index=block_index,
    )
    candidate_logits, candidate_runtime = continuation_from_layers(
        model,
        continuation_ids,
        reconstructed,
        layouts,
        device=device,
        torch_module=torch_module,
    )
    if not torch_module.isfinite(candidate_logits).all():
        raise RuntimeError("decoded candidate cache produced non-finite logits")
    candidate_nll = core._nll(candidate_logits, targets_cpu)
    agreements = int(
        (
            baseline_logits.argmax(dim=-1)
            == candidate_logits.argmax(dim=-1)
        ).sum().item()
    )
    record = {
        "blockIndex": block_index,
        "tokenIdsSHA256": token_digest,
        "canonicalCacheBF16SHA256": canonical_digest,
        "configurationId": core.configuration_id(configuration),
        "predictionTokens": PREDICTION_TOKENS,
        "denseBF16Bytes": sum(layer.size * 2 for layer in canonical),
        **encoding,
        **core._cache_error_accumulators(canonical, reconstructed),
        "baselineNLLNatPerToken": baseline_nll,
        "candidateNLLNatPerToken": candidate_nll,
        "deltaNLLNatPerToken": candidate_nll - baseline_nll,
        "perplexityRatio": math.exp(candidate_nll - baseline_nll),
        "top1AgreementCount": agreements,
        "top1Agreement": agreements / PREDICTION_TOKENS,
        "meanKLDivergenceNat": core._mean_kl_divergence(
            baseline_logits, candidate_logits
        ),
        "modelContinuationNanoseconds": candidate_runtime,
    }
    del (
        ids,
        prefix_ids,
        continuation_ids,
        direct_logits,
        rebuilt_logits,
        baseline_logits,
        exact_logits,
        candidate_logits,
        original,
        canonical,
        canonical_bytes,
        reconstructed,
    )
    if device == "mps":
        torch_module.mps.synchronize()
        torch_module.mps.empty_cache()
    gc.collect()
    return baseline, record


def run(arguments: argparse.Namespace) -> Path:
    matrix = load_json(MODEL_MATRIX_PATH)
    models = matrix.get("models")
    if not isinstance(models, dict) or arguments.model not in models:
        raise ValueError(f"unknown model key: {arguments.model}")
    model_specification = models[arguments.model]
    dataset_specification = matrix["dataset"]
    codec_root = arguments.codec_root.resolve()
    source_manifest = validate_codec_source(codec_root)
    source_manifest["labFiles"] = {
        "models.json": {
            "bytes": MODEL_MATRIX_PATH.stat().st_size,
            "sha256": sha256_file(MODEL_MATRIX_PATH),
        },
        "run_cross_model.py": {
            "bytes": Path(__file__).stat().st_size,
            "sha256": sha256_file(Path(__file__)),
        },
        "verify_run.py": {
            "bytes": (LAB_ROOT / "verify_run.py").stat().st_size,
            "sha256": sha256_file(LAB_ROOT / "verify_run.py"),
        },
    }
    configuration = load_fixed_configuration(codec_root)
    if len(configuration["bitsByLayer"]) != 24:
        raise RuntimeError("configuration layer count is not exactly 24")
    sys.path.insert(0, str(codec_root))
    from RealLLM import benchmark_real_llm as core

    if core.configuration_id(configuration) != EXPECTED_CONFIGURATION_SHA256[:16]:
        raise RuntimeError("configuration ID differs from its commitment")
    snapshot, dataset_path, asset_manifest = resolve_assets(
        model_specification,
        dataset_specification,
        arguments.cache_dir.resolve(),
        local_files_only=arguments.local_files_only,
    )
    if arguments.prepare_only:
        print(
            json.dumps(
                {
                    "status": "assets-prepared-and-verified",
                    "model": arguments.model,
                    "modelSnapshot": str(snapshot),
                    "dataset": str(dataset_path),
                    **asset_manifest,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return Path()

    safety = check_power_and_memory(arguments.device)
    import pyarrow
    import torch
    import transformers
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.manual_seed(arguments.seed)
    np.random.seed(arguments.seed)
    torch.set_num_threads(2)
    if hasattr(torch, "use_deterministic_algorithms"):
        torch.use_deterministic_algorithms(True, warn_only=True)
    if arguments.device == "mps" and not torch.backends.mps.is_available():
        raise RuntimeError("MPS was requested but is unavailable")

    started_at = datetime.now(UTC)
    run_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    model_root = arguments.output_root.resolve() / arguments.model
    partial = model_root / f"{run_id}.partial"
    completed = model_root / run_id
    partial.mkdir(parents=True, exist_ok=False, mode=0o700)
    writer = ContainerWriter(partial)
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            snapshot,
            local_files_only=True,
            trust_remote_code=False,
        )
        model = AutoModelForCausalLM.from_pretrained(
            snapshot,
            local_files_only=True,
            trust_remote_code=False,
            dtype=torch.float32,
            attn_implementation="eager",
            disable_mmap=True,
        ).to(arguments.device)
        model.eval()
        geometry = model_geometry(model)
        validate_model_geometry(geometry, model_specification["architecture"])
        if int(geometry["layers"]) != len(configuration["bitsByLayer"]):
            raise RuntimeError("model layers and fixed bit schedule differ")
        blocks, selected_token_bytes, inventory = token_blocks(
            tokenizer,
            dataset_path,
            start_block=arguments.start_block,
            blocks=arguments.blocks,
        )
        exclusive_write(partial / "selected-token-ids.u32le", selected_token_bytes)
        baselines: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        for relative_index, block in enumerate(blocks):
            source_index = arguments.start_block + relative_index
            print(
                f"{arguments.model}: real validation block "
                f"{relative_index + 1}/{len(blocks)} (source {source_index})",
                flush=True,
            )
            baseline, record = evaluate_block(
                block,
                source_index,
                configuration,
                model=model,
                geometry=geometry,
                device=arguments.device,
                torch_module=torch,
                core=core,
                writer=writer,
            )
            baselines.append(baseline)
            records.append(record)
            check_power_and_memory(arguments.device)
        aggregate = core.aggregate_candidate_records(configuration, records)
        finished_at = datetime.now(UTC)
        result = {
            "schemaVersion": "corelm-cross-model-regression-v1",
            "status": "exploratory-cross-model-regression",
            "countsTowardScientificVerdict": False,
            "blind": False,
            "claimBoundary": (
                "Tests unchanged Qwen-derived cache configuration transfer to "
                "one pinned model-tokenizer pair on public WikiText validation; "
                "not blind data, corpus-wide, or LLM-wide generalization."
            ),
            "modelKey": arguments.model,
            "modelRole": model_specification["role"],
            "model": {
                "repository": model_specification["repository"],
                "revision": model_specification["revision"],
                "license": model_specification["license"],
                "geometry": geometry,
            },
            "dataset": dataset_specification,
            "tokenization": inventory,
            "protocol": {
                "blockTokens": BLOCK_TOKENS,
                "prefillTokens": PREFILL_TOKENS,
                "predictionsPerBlock": PREDICTION_TOKENS,
                "teacherForced": True,
                "cacheCanonicalization": "FP32-to-BF16-to-FP32",
                "compressionByteAccounting": "complete-VTL5-container-bytes",
                "configuration": configuration,
                "configurationSHA256": EXPECTED_CONFIGURATION_SHA256,
                "diagnosticThresholds": core.THRESHOLDS,
                "thresholdsPreregisteredForThisModel": False,
            },
            "source": {
                **source_manifest,
            },
            "assets": asset_manifest,
            "runtime": {
                "startedAt": started_at.isoformat(),
                "finishedAt": finished_at.isoformat(),
                "durationSeconds": (finished_at - started_at).total_seconds(),
                "platform": platform.platform(),
                "python": sys.version,
                "torch": torch.__version__,
                "transformers": transformers.__version__,
                "numpy": np.__version__,
                "pyarrow": pyarrow.__version__,
                "device": arguments.device,
                "seed": arguments.seed,
                "safetyAtStart": safety,
            },
            "baselines": baselines,
            "records": records,
            "aggregate": aggregate,
            "diagnosticVerdict": "PASS" if aggregate["pass"] else "FAIL",
        }
        result_bytes = canonical_json_bytes(result) + b"\n"
        exclusive_write(partial / "result.json", result_bytes)
        exclusive_write(
            partial / "result.sha256",
            f"{sha256_bytes(result_bytes)}  result.json\n".encode("ascii"),
        )
        os.replace(partial, completed)
        print(f"result: {completed / 'result.json'}", flush=True)
        return completed / "result.json"
    except BaseException as error:
        failure = {
            "schemaVersion": "corelm-cross-model-failure-v1",
            "status": "FAIL_EXECUTION",
            "modelKey": arguments.model,
            "errorType": type(error).__name__,
            "error": str(error),
            "recordedAt": datetime.now(UTC).isoformat(),
        }
        try:
            exclusive_write(
                partial / "failure.json", canonical_json_bytes(failure) + b"\n"
            )
        except OSError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "--model",
        required=True,
        choices=(
            "qwen2.5-0.5b",
            "gpt2-medium",
            "pythia-410m-deduped",
            "bloom-560m",
        ),
    )
    value.add_argument("--blocks", type=int, default=DEFAULT_BLOCKS)
    value.add_argument("--start-block", type=int, default=DEFAULT_START_BLOCK)
    value.add_argument("--device", choices=("mps", "cpu"), default="mps")
    value.add_argument("--seed", type=int, default=20260729)
    value.add_argument("--codec-root", type=Path, required=True)
    value.add_argument(
        "--cache-dir",
        type=Path,
        default=Path.home() / ".cache/corelm/cross-model-lab-assets",
    )
    value.add_argument("--output-root", type=Path, default=LAB_ROOT / "runs")
    value.add_argument("--local-files-only", action="store_true")
    value.add_argument("--prepare-only", action="store_true")
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.blocks < 1 or arguments.blocks > 8:
        raise SystemExit("--blocks must be in 1..8")
    if arguments.start_block < 64 or arguments.start_block + arguments.blocks > 72:
        raise SystemExit("only public validation blocks 64..71 are allowed")
    run(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
