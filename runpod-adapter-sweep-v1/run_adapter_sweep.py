#!/usr/bin/env python3
"""Run the fixed seven-adapter, four-workload long-context sweep."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIXED_ENVIRONMENT = {
    "CUBLAS_WORKSPACE_CONFIG": ":4096:8",
    "DO_NOT_TRACK": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
    "OMP_NUM_THREADS": "4",
    "OPENBLAS_NUM_THREADS": "4",
    "MKL_NUM_THREADS": "4",
    "NUMEXPR_NUM_THREADS": "4",
    "TOKENIZERS_PARALLELISM": "false",
    "PYTHONDONTWRITEBYTECODE": "1",
}
for environment_name, environment_value in FIXED_ENVIRONMENT.items():
    os.environ[environment_name] = environment_value
sys.dont_write_bytecode = True
os.umask(0o077)

from common import (  # noqa: E402
    ATTEMPT_SCHEMA_VERSION,
    CLASSIFICATION,
    HORIZON,
    LAB_ROOT,
    MODEL_ORDER,
    PROFILES_PATH,
    PROTOCOL_PATH,
    RESULT_SCHEMA_VERSION,
    RUN_SCHEMA_VERSION,
    SUITE_ROOT,
    TORCH_LOCK_PATH,
    WORKLOADS_PATH,
    bits_schedule,
    canonical_json_bytes,
    command_output,
    configuration_for_profile,
    configuration_sha256,
    exclusive_write,
    git_blob_sha1,
    load_profiles,
    load_workloads,
    profile_by_id,
    require,
    require_digest,
    require_number,
    require_regular,
    sha256_bytes,
    sha256_file,
    strict_json_file,
    validate_codec_root,
    verify_asset_receipt,
    verify_digest_sidecar,
    workload_text,
    write_canonical_json,
)


np: Any = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_source_identity() -> dict[str, Any]:
    root = LAB_ROOT.resolve()
    require(root == LAB_ROOT.absolute(), "lab root traverses a symlink")
    status = command_output(
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
    # During local development the suite is necessarily untracked.  A real
    # RunPod execution is accepted only from a committed, completely clean tree.
    require(status == "", "lab checkout must be completely clean for execution")
    return {
        "commit": command_output(["git", "rev-parse", "HEAD"], root),
        "tree": command_output(["git", "rev-parse", "HEAD^{tree}"], root),
        "branch": command_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], root),
    }


def safe_directory(path: Path, label: str, *, create: bool) -> Path:
    unresolved = Path(os.path.abspath(path))
    if create:
        unresolved.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(unresolved.is_dir(), f"{label} is not a directory")
    require(unresolved == unresolved.resolve(), f"{label} traverses a symlink")
    status = unresolved.stat()
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is accessible to another user")
    return unresolved


def asset_snapshot(cache_root: Path, profile: dict[str, Any]) -> Path:
    snapshot = cache_root / profile["modelId"]
    require(snapshot.parent == cache_root, "asset snapshot escaped cache root")
    require(snapshot.is_dir() and snapshot == snapshot.resolve(), "asset snapshot is unsafe")
    for asset in profile["files"]:
        path = snapshot / asset["path"]
        status = require_regular(path, f"asset {profile['modelId']}/{asset['path']}")
        require(status.st_size == int(asset["bytes"]), "asset size differs")
        if asset.get("sha256") is None:
            require(git_blob_sha1(path.read_bytes()) == asset["hfGitOidSha1"], "gated Git blob OID differs")
        else:
            require(sha256_file(path) == asset["sha256"], "asset digest differs")
    if profile.get("weightConversion") is not None:
        require_regular(snapshot / "model.safetensors", "converted OPT safetensors")
    return snapshot


def tokenizer_ids(tokenizer: Any, text: str) -> list[int]:
    previous = tokenizer.model_max_length
    tokenizer.model_max_length = sys.maxsize
    try:
        values = tokenizer(
            text,
            add_special_tokens=False,
            return_attention_mask=False,
            return_token_type_ids=False,
        )["input_ids"]
    finally:
        tokenizer.model_max_length = previous
    require(isinstance(values, list) and all(type(value) is int and value >= 0 for value in values), "tokenizer produced invalid IDs")
    return values


def token_digest(values: list[int]) -> str:
    return sha256_bytes(np.asarray(values, dtype="<u4").tobytes())


def workload_by_id(identifier: str) -> dict[str, Any]:
    matches = [entry for entry in load_workloads()["workloads"] if entry["workloadId"] == identifier]
    require(len(matches) == 1, f"unknown or duplicate workload: {identifier}")
    return matches[0]


def source_material(profile: dict[str, Any], workload: dict[str, Any], tokenizer: Any) -> tuple[list[int], dict[str, Any]]:
    text, inventory = workload_text(workload)
    framed = text.encode("utf-8")
    ids = tokenizer_ids(tokenizer, text)
    prefill_tokens = int(profile["maxPrefillTokens"])
    required = prefill_tokens + 1
    require(len(ids) >= required, f"workload {workload['workloadId']} has only {len(ids)} tokens for {profile['modelId']}; need {required}")
    selected = ids[:required]
    return selected, {
        "workloadId": workload["workloadId"],
        "category": workload["contentClass"],
        "promptUTF8SHA256": sha256_bytes(framed),
        "framedUTF8Bytes": len(framed),
        "availableTokens": len(ids),
        "selectedTokens": required,
        "prefillTokens": prefill_tokens,
        "tokenIdsU32LESHA256": token_digest(selected),
        "sourceFiles": inventory,
    }


def configuration_geometry(config: Any) -> dict[str, Any]:
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
    return {
        "modelType": model_type,
        "architecture": str(config.architectures[0]),
        "layers": layers,
        "hiddenSize": hidden,
        "attentionHeads": heads,
        "kvHeads": kv_heads,
        "headDimension": head_dimension,
        "contextTokens": int(getattr(config, "max_position_embeddings", profile_context_fallback(config))),
    }


def profile_context_fallback(config: Any) -> int:
    for name in ("n_positions", "n_ctx", "seq_length"):
        value = getattr(config, name, None)
        if isinstance(value, int) and value > 0:
            return value
    return 0


def validate_geometry(observed: dict[str, Any], profile: dict[str, Any]) -> None:
    expected = profile["geometry"]
    for field in ("modelType", "architecture", "layers", "hiddenSize", "attentionHeads", "kvHeads", "headDimension", "contextTokens"):
        require(observed[field] == expected[field], f"observed geometry differs for {field}: {observed[field]!r} != {expected[field]!r}")


def configure_torch() -> Any:
    import torch

    require(torch.cuda.is_available(), "CUDA is required for the RunPod sweep")
    require(torch.cuda.device_count() == 1, "exactly one visible CUDA device is required")
    torch.manual_seed(20260812)
    torch.cuda.manual_seed_all(20260812)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    torch.use_deterministic_algorithms(True)
    return torch


def load_tokenizer_and_config(
    profile: dict[str, Any], cache_root: Path
) -> tuple[Any, Any, Path]:
    from transformers import AutoConfig, AutoTokenizer

    snapshot = asset_snapshot(cache_root, profile)
    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    config = AutoConfig.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False
    )
    validate_geometry(configuration_geometry(config), profile)
    require(
        int(config.vocab_size) == int(profile["geometry"]["vocabularySize"]),
        "configured model vocabulary size differs",
    )
    return tokenizer, config, snapshot


def load_model(
    profile: dict[str, Any],
    snapshot: Path,
    config: Any,
    torch_module: Any,
) -> Any:
    from transformers import AutoModelForCausalLM

    if profile["weights"].get("disableMmap") is True:
        from safetensors.torch import load as load_safetensors_bytes

        model = AutoModelForCausalLM.from_config(
            config,
            trust_remote_code=False,
            dtype=torch_module.bfloat16,
            attn_implementation="eager",
        )
        state = load_safetensors_bytes((snapshot / "model.safetensors").read_bytes())
        if profile["modelType"] == "gpt2":
            require(
                "transformer.wte.weight" in state,
                "GPT-2 safetensors omit the input embedding tensor",
            )
            require(
                "lm_head.weight" not in state,
                "pinned GPT-2 safetensors unexpectedly duplicate tied weights",
            )
            state["lm_head.weight"] = state["transformer.wte.weight"]
        incompatible = model.load_state_dict(state, strict=True, assign=False)
        require(not incompatible.missing_keys and not incompatible.unexpected_keys, "non-mmap safetensors keys differ from the model")
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
            config=config,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
            dtype=torch_module.bfloat16,
            attn_implementation="eager",
            low_cpu_mem_usage=True,
        )
    model.train(False).to("cuda:0")
    validate_geometry(configuration_geometry(model.config), profile)
    return model


def cache_layer_tensors(layer: Any) -> tuple[Any, Any]:
    keys = getattr(layer, "keys", None)
    values = getattr(layer, "values", None)
    require(keys is not None and values is not None, "DynamicCache layer has no key/value tensors")
    return keys, values


def extract_canonical_layers(cache: Any, profile: dict[str, Any], expected_tokens: int, torch_module: Any) -> tuple[list[np.ndarray], list[bytes]]:
    layers = getattr(cache, "layers", None)
    require(isinstance(layers, (list, tuple)) and len(layers) == int(profile["geometry"]["layers"]), "DynamicCache layer count differs")
    arrays: list[np.ndarray] = []
    raw_layers: list[bytes] = []
    kv_heads = int(profile["geometry"]["kvHeads"])
    head_dimension = int(profile["geometry"]["headDimension"])
    for index, layer in enumerate(layers):
        keys, values = cache_layer_tensors(layer)
        expected = (1, kv_heads, expected_tokens, head_dimension)
        require(tuple(keys.shape) == expected and tuple(values.shape) == expected, f"cache layer {index} shape differs")
        require(keys.dtype == torch_module.bfloat16 and values.dtype == torch_module.bfloat16, "cache is not BF16")
        require(
            bool(torch_module.isfinite(keys).all())
            and bool(torch_module.isfinite(values).all()),
            f"cache layer {index} contains a non-finite K/V value",
        )
        key_rows = keys[0].permute(1, 0, 2).contiguous().reshape(expected_tokens, -1)
        value_rows = values[0].permute(1, 0, 2).contiguous().reshape(expected_tokens, -1)
        joined = torch_module.cat((key_rows, value_rows), dim=1).contiguous().cpu()
        require(joined.shape[1] % 128 == 0, "cache width is not codec aligned")
        raw = joined.view(torch_module.uint16).numpy().astype("<u2", copy=False).tobytes()
        raw_layers.append(raw)
        arrays.append(np.ascontiguousarray(joined.float().numpy(), dtype=np.float32))
    return arrays, raw_layers


def cache_digest(raw_layers: list[bytes]) -> str:
    digest = hashlib.sha256()
    for index, raw in enumerate(raw_layers):
        digest.update(index.to_bytes(4, "little"))
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    return digest.hexdigest()


def cache_observation(
    cache: Any, profile: dict[str, Any], expected_tokens: int
) -> dict[str, Any]:
    layers = getattr(cache, "layers", None)
    require(
        isinstance(layers, (list, tuple))
        and len(layers) == int(profile["geometry"]["layers"]),
        "observed cache layer inventory differs",
    )
    layer_classes = sorted(
        {f"{type(layer).__module__}.{type(layer).__name__}" for layer in layers}
    )
    expected_layer_suffix = (
        ".DynamicSlidingWindowLayer"
        if profile["modelId"] == "mistral-7b-v0.1"
        else ".DynamicLayer"
    )
    require(
        len(layer_classes) == 1
        and layer_classes[0].endswith(expected_layer_suffix),
        "observed DynamicCache layer class differs from the profile",
    )
    cache_class = f"{type(cache).__module__}.{type(cache).__name__}"
    require(cache_class.endswith(".DynamicCache"), "observed cache class differs")
    return {
        "cacheClass": cache_class,
        "layerClass": layer_classes[0],
        "tensorLayout": "batch,kv_head,token,head_dimension",
        "batchSize": 1,
        "layers": int(profile["geometry"]["layers"]),
        "kvHeads": int(profile["geometry"]["kvHeads"]),
        "headDimension": int(profile["geometry"]["headDimension"]),
        "dtype": "bfloat16",
        "targetContextTokens": int(profile["gpuAdmission"]["maxInputTokens"]),
        "prefillTokens": expected_tokens,
        "finalPromptTokens": 1,
        "continuationTokens": HORIZON,
        "effectiveCacheTokens": expected_tokens,
        "evictedTokens": 0,
    }


def cgroup_memory_observation() -> dict[str, int | None]:
    root = Path("/sys/fs/cgroup")

    def read_counter(name: str, *, allow_max: bool = False) -> int | None:
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"cgroup {name} is absent")
        raw = path.read_text(encoding="ascii").strip()
        if allow_max and raw == "max":
            return None
        require(raw.isascii() and raw.isdigit(), f"cgroup {name} is invalid")
        return int(raw)

    current = read_counter("memory.current")
    peak = read_counter("memory.peak")
    limit = read_counter("memory.max", allow_max=True)
    require(
        isinstance(current, int)
        and isinstance(peak, int)
        and peak >= current,
        "cgroup memory counters differ",
    )
    return {
        "cgroupMemoryCurrentBytesAtCompletion": current,
        "cgroupMemoryPeakBytesAtCompletion": peak,
        "cgroupMemoryLimitBytes": limit,
    }


def runtime_package_versions() -> dict[str, str]:
    names = (
        "huggingface-hub",
        "numpy",
        "safetensors",
        "tokenizers",
        "torch",
        "transformers",
    )
    return {name: importlib.metadata.version(name) for name in names}


def gpu_driver_version() -> str:
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
        "cannot establish the NVIDIA driver version",
    )
    return value


def dynamic_cache_from_layers(model: Any, layers: list[np.ndarray], profile: dict[str, Any], torch_module: Any) -> Any:
    from transformers import DynamicCache

    expected_tokens = int(profile["maxPrefillTokens"])
    heads = int(profile["geometry"]["kvHeads"])
    head_dimension = int(profile["geometry"]["headDimension"])
    key_width = heads * head_dimension
    require(len(layers) == int(profile["geometry"]["layers"]), "rebuilt cache layer count differs")
    cache = DynamicCache(config=model.config)
    for index, trajectory in enumerate(layers):
        require(trajectory.shape == (expected_tokens, 2 * key_width), "rebuilt cache layer shape differs")
        keys = (
            torch_module.from_numpy(np.ascontiguousarray(trajectory[:, :key_width]))
            .to(device="cuda:0", dtype=torch_module.bfloat16)
            .reshape(expected_tokens, heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .contiguous()
        )
        values = (
            torch_module.from_numpy(np.ascontiguousarray(trajectory[:, key_width:]))
            .to(device="cuda:0", dtype=torch_module.bfloat16)
            .reshape(expected_tokens, heads, head_dimension)
            .permute(1, 0, 2)
            .unsqueeze(0)
            .contiguous()
        )
        cache.update(keys, values, index)
    require(int(cache.get_seq_length()) == expected_tokens, "rebuilt cache sequence length differs")
    return cache


def forward_kwargs(model: Any, cache: Any, input_tokens: int, torch_module: Any, *, use_cache: bool) -> dict[str, Any]:
    cached = int(cache.get_seq_length())
    positions = torch_module.arange(cached, cached + input_tokens, dtype=torch_module.long, device="cuda:0")
    kwargs: dict[str, Any] = {
        "past_key_values": cache,
        "attention_mask": torch_module.ones((1, cached + input_tokens), dtype=torch_module.long, device="cuda:0"),
        "use_cache": use_cache,
        "return_dict": True,
    }
    if model.config.model_type in {"qwen2", "llama", "mistral", "gpt_neox", "gpt2", "gemma"}:
        kwargs["position_ids"] = positions.unsqueeze(0)
    if model.config.model_type in {"qwen2", "llama", "mistral", "gemma"}:
        kwargs["cache_position"] = positions
    return kwargs


def model_step(model: Any, token: Any, cache: Any, torch_module: Any) -> tuple[Any, Any]:
    before = int(cache.get_seq_length())
    with torch_module.inference_mode():
        output = model(token, **forward_kwargs(model, cache, int(token.shape[1]), torch_module, use_cache=True))
    updated = output.past_key_values
    require(int(updated.get_seq_length()) == before + int(token.shape[1]), "cache did not advance exactly")
    logits = output.logits[:, -1, :].float()
    require(bool(torch_module.isfinite(logits).all()), "model produced non-finite logits")
    return logits, updated


def encode_layers(canonical: list[np.ndarray], profile: dict[str, Any], cell_root: Path) -> tuple[list[np.ndarray], dict[str, Any]]:
    from RealLLM.voidtoken_v5 import VoidTokenV5Backend

    schedule = bits_schedule(len(canonical))
    containers = cell_root / "containers"
    containers.mkdir(mode=0o700, parents=False, exist_ok=False)
    reconstructed: list[np.ndarray] = []
    manifest: list[dict[str, Any]] = []
    dense_bytes = 0
    container_bytes = 0
    payload_bytes = 0
    started = time.perf_counter_ns()
    for index, matrix in enumerate(canonical):
        representation = VoidTokenV5Backend.encode(
            matrix,
            bits=schedule[index],
            group_size=128,
            transform_block_size=128,
            layer_index=index,
            scale_compression="zlib-9",
            code_compression="zlib-9",
            sign_mode="none",
        )
        container = representation.to_bytes()
        parsed = VoidTokenV5Backend.from_bytes(container)
        require(parsed.to_bytes() == container, "codec parser changed canonical bytes")
        require(np.array_equal(parsed.reconstructed, representation.reconstructed), "codec reconstruction differs after parse")
        path = containers / f"layer-{index:03d}.vtl5"
        exclusive_write(path, container)
        dense = matrix.size * 2
        dense_bytes += dense
        container_bytes += len(container)
        payload_bytes += len(parsed.payload)
        reconstructed.append(np.ascontiguousarray(parsed.reconstructed, dtype=np.float32))
        manifest.append(
            {
                "layerIndex": index,
                "bits": schedule[index],
                "rows": int(matrix.shape[0]),
                "columns": int(matrix.shape[1]),
                "denseBF16Bytes": dense,
                "containerBytes": len(container),
                "payloadBytes": len(parsed.payload),
                "containerSHA256": sha256_bytes(container),
                "payloadSHA256": sha256_bytes(parsed.payload),
                "path": str(path.relative_to(cell_root)),
            }
        )
    require(container_bytes > 0, "encoded container bytes are zero")
    return reconstructed, {
        "configuration": configuration_for_profile(profile),
        "configurationSHA256": configuration_sha256(profile),
        "denseBF16Bytes": dense_bytes,
        "containerBytes": container_bytes,
        "payloadBytes": payload_bytes,
        "compressionRatio": dense_bytes / container_bytes,
        "encodingNanoseconds": time.perf_counter_ns() - started,
        "containers": manifest,
    }


def controlled_metrics(model: Any, tokenizer: Any, canonical: list[np.ndarray], reconstructed: list[np.ndarray], profile: dict[str, Any], last_prompt_token: int, torch_module: Any) -> dict[str, Any]:
    baseline_cache = dynamic_cache_from_layers(model, canonical, profile, torch_module)
    candidate_cache = dynamic_cache_from_layers(model, reconstructed, profile, torch_module)
    current = torch_module.tensor([[last_prompt_token]], dtype=torch_module.long, device="cuda:0")
    baseline_tokens: list[int] = []
    controlled_candidate_top1: list[int] = []
    top1_agreements = 0
    kl_sum = 0.0
    selected_surprisal_delta_sum = 0.0
    max_abs_logit_difference = 0.0
    per_token_kl: list[float] = []
    per_token_surprisal: list[float] = []
    per_token_max_difference: list[float] = []
    for _ in range(HORIZON):
        baseline_logits, baseline_cache = model_step(model, current, baseline_cache, torch_module)
        candidate_logits, candidate_cache = model_step(model, current, candidate_cache, torch_module)
        baseline_logp = torch_module.log_softmax(baseline_logits, dim=-1)
        candidate_logp = torch_module.log_softmax(candidate_logits, dim=-1)
        baseline_top = int(torch_module.argmax(baseline_logits, dim=-1).item())
        candidate_top = int(torch_module.argmax(candidate_logits, dim=-1).item())
        baseline_tokens.append(baseline_top)
        controlled_candidate_top1.append(candidate_top)
        top1_agreements += int(baseline_top == candidate_top)
        token_kl = float((baseline_logp.exp() * (baseline_logp - candidate_logp)).sum().item())
        token_surprisal = float((-candidate_logp[0, baseline_top] + baseline_logp[0, baseline_top]).item())
        token_max_difference = float((baseline_logits - candidate_logits).abs().max().item())
        require(
            math.isfinite(token_kl)
            and math.isfinite(token_surprisal)
            and math.isfinite(token_max_difference),
            "controlled behavior metric is non-finite",
        )
        per_token_kl.append(token_kl)
        per_token_surprisal.append(token_surprisal)
        per_token_max_difference.append(token_max_difference)
        kl_sum += token_kl
        selected_surprisal_delta_sum += token_surprisal
        max_abs_logit_difference = max(max_abs_logit_difference, token_max_difference)
        current = torch_module.tensor([[baseline_top]], dtype=torch_module.long, device="cuda:0")
    del baseline_cache, candidate_cache

    candidate_free_cache = dynamic_cache_from_layers(model, reconstructed, profile, torch_module)
    current = torch_module.tensor([[last_prompt_token]], dtype=torch_module.long, device="cuda:0")
    candidate_free_tokens: list[int] = []
    for _ in range(HORIZON):
        logits, candidate_free_cache = model_step(model, current, candidate_free_cache, torch_module)
        token = int(torch_module.argmax(logits, dim=-1).item())
        candidate_free_tokens.append(token)
        current = torch_module.tensor([[token]], dtype=torch_module.long, device="cuda:0")
    common_prefix = 0
    for baseline_token, candidate_token in zip(baseline_tokens, candidate_free_tokens):
        if baseline_token != candidate_token:
            break
        common_prefix += 1
    return {
        "predictionTokens": HORIZON,
        "controlledTop1AgreementCount": top1_agreements,
        "controlledTop1Agreement": top1_agreements / HORIZON,
        "meanKLDivergenceNat": kl_sum / HORIZON,
        "meanBaselineSelectedTokenSurprisalDeltaNat": selected_surprisal_delta_sum / HORIZON,
        "maxAbsLogitDifference": max_abs_logit_difference,
        "perTokenKLDivergenceNat": per_token_kl,
        "perTokenBaselineSelectedTokenSurprisalDeltaNat": per_token_surprisal,
        "perTokenMaxAbsLogitDifference": per_token_max_difference,
        "baselineTokenIds": baseline_tokens,
        "controlledCandidateTop1TokenIds": controlled_candidate_top1,
        "candidateFreeRunTokenIds": candidate_free_tokens,
        "freeRunExact": baseline_tokens == candidate_free_tokens,
        "freeRunSamePositionCount": sum(a == b for a, b in zip(baseline_tokens, candidate_free_tokens)),
        "freeRunLongestCommonPrefixTokens": common_prefix,
        "baselineContinuation": tokenizer.decode(baseline_tokens, clean_up_tokenization_spaces=False),
        "candidateFreeRunContinuation": tokenizer.decode(candidate_free_tokens, clean_up_tokenization_spaces=False),
    }


def preflight(arguments: argparse.Namespace) -> int:
    profiles = load_profiles()
    workloads = load_workloads()
    codec = validate_codec_root(arguments.codec_root)
    cache_root = safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_receipt_digest = verify_asset_receipt(arguments.assets, cache_root)
    from transformers import AutoConfig, AutoTokenizer

    cells: list[dict[str, Any]] = []
    for profile in profiles["profiles"]:
        snapshot = asset_snapshot(cache_root, profile)
        config = AutoConfig.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
        require(str(config.model_type) == profile["geometry"]["modelType"], "preflight model type differs")
        tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
        for workload in workloads["workloads"]:
            _, material = source_material(profile, workload, tokenizer)
            cells.append({"modelId": profile["modelId"], **material})
        del tokenizer, config
        gc.collect()
    result = {
        "schemaVersion": "corelm-runpod-adapter-preflight-v1",
        "status": "TOKENIZER_ONLY_NO_MODEL_INFERENCE",
        "countsTowardScientificVerdict": False,
        "source": git_source_identity(),
        "codecSource": codec,
        "assetReceiptSHA256": asset_receipt_digest,
        "profilesSHA256": sha256_file(PROFILES_PATH),
        "workloadsSHA256": sha256_file(WORKLOADS_PATH),
        "protocolSHA256": sha256_file(PROTOCOL_PATH),
        "modelOrder": list(MODEL_ORDER),
        "workloadOrder": [entry["workloadId"] for entry in workloads["workloads"]],
        "horizon": HORIZON,
        "cells": cells,
    }
    write_canonical_json(arguments.output, result)
    print(canonical_json_bytes(result).decode("utf-8"), flush=True)
    return 0


def load_preflight(path: Path) -> dict[str, Any]:
    value = strict_json_file(path, "preflight")
    require(value.get("schemaVersion") == "corelm-runpod-adapter-preflight-v1", "preflight schema differs")
    require(value.get("status") == "TOKENIZER_ONLY_NO_MODEL_INFERENCE", "preflight status differs")
    require(value.get("profilesSHA256") == sha256_file(PROFILES_PATH), "preflight profiles changed")
    require(value.get("workloadsSHA256") == sha256_file(WORKLOADS_PATH), "preflight workloads changed")
    require(value.get("protocolSHA256") == sha256_file(PROTOCOL_PATH), "preflight protocol changed")
    require(value.get("horizon") == HORIZON, "preflight horizon differs")
    return value


def preflight_cell(preflight_value: dict[str, Any], model_id: str, workload_id: str) -> dict[str, Any]:
    matches = [entry for entry in preflight_value["cells"] if entry["modelId"] == model_id and entry["workloadId"] == workload_id]
    require(len(matches) == 1, "preflight cell is absent or duplicated")
    return matches[0]


def run_cell(arguments: argparse.Namespace) -> int:
    started_at = utc_now()
    profile = profile_by_id(arguments.model_id)
    workload = workload_by_id(arguments.workload_id)
    preflight_value = load_preflight(arguments.preflight)
    expected_cell = preflight_cell(preflight_value, arguments.model_id, arguments.workload_id)
    codec_manifest = validate_codec_root(arguments.codec_root)
    cache_root = safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_receipt_digest = verify_asset_receipt(arguments.assets, cache_root)
    require(
        preflight_value.get("assetReceiptSHA256") == asset_receipt_digest,
        "preflight asset receipt differs",
    )
    run_root = safe_directory(arguments.run_dir, "run directory", create=False)
    cell_root = run_root / "cells" / arguments.model_id / arguments.workload_id
    require(
        cell_root.is_dir()
        and not cell_root.is_symlink()
        and cell_root == cell_root.resolve(),
        "supervisor-created cell directory is absent or unsafe",
    )

    source = git_source_identity()
    require(preflight_value.get("source") == source, "preflight source identity differs")
    require(
        preflight_value.get("codecSource") == codec_manifest,
        "preflight codec identity differs",
    )
    attempt = strict_json_file(cell_root / "attempt.json", "cell attempt")
    verify_digest_sidecar(cell_root / "attempt.json")
    require(
        attempt.get("schemaVersion") == ATTEMPT_SCHEMA_VERSION
        and attempt.get("status") == "STARTED"
        and attempt.get("classification") == CLASSIFICATION
        and attempt.get("countsTowardScientificVerdict") is False
        and attempt.get("modelId") == arguments.model_id
        and attempt.get("adapterId") == profile["adapterId"]
        and attempt.get("workloadId") == arguments.workload_id
        and attempt.get("source") == source
        and attempt.get("codecSource") == codec_manifest
        and attempt.get("preflightSHA256") == sha256_file(arguments.preflight)
        and attempt.get("assetReceiptSHA256") == asset_receipt_digest,
        "supervisor cell attempt binding differs",
    )

    tokenizer, config, snapshot = load_tokenizer_and_config(profile, cache_root)
    selected, material = source_material(profile, workload, tokenizer)
    require(material["tokenIdsU32LESHA256"] == expected_cell["tokenIdsU32LESHA256"], "run token IDs differ from preflight")
    prefill_tokens = int(profile["maxPrefillTokens"])
    dense_bytes = prefill_tokens * 2 * int(profile["geometry"]["kvHeads"]) * int(profile["geometry"]["headDimension"]) * int(profile["geometry"]["layers"]) * 2
    weight_bytes = sum(int(asset["bytes"]) for asset in profile["files"] if asset["path"].endswith((".safetensors", ".bin")))
    estimate = weight_bytes + 6 * dense_bytes + 4 * 1024**3
    disk_required_bytes = max(8 * 1024**3, 8 * dense_bytes)
    disk_free_bytes = shutil.disk_usage(cell_root).free
    require(
        disk_free_bytes >= disk_required_bytes,
        f"cell requires {disk_required_bytes} free bytes; only {disk_free_bytes} remain",
    )
    sys.path.insert(0, str(arguments.codec_root.resolve()))
    torch_module = configure_torch()
    torch_module.cuda.reset_peak_memory_stats()
    free_bytes, total_bytes = torch_module.cuda.mem_get_info()
    require(
        estimate <= int(profile["gpuAdmission"]["maxGpuMemoryBytes"]),
        "cell memory estimate exceeds the registered per-profile planning cap",
    )
    require(estimate <= int(total_bytes * 0.80), f"cell memory estimate {estimate} exceeds 80% of GPU memory {total_bytes}")
    require(estimate <= int(free_bytes * 0.80), f"cell memory estimate {estimate} exceeds 80% of free GPU memory {free_bytes}")
    model = load_model(profile, snapshot, config, torch_module)
    prefix = torch_module.tensor([selected[:prefill_tokens]], dtype=torch_module.long, device="cuda:0")
    last_prompt_token = int(selected[prefill_tokens])

    from transformers import DynamicCache

    with torch_module.inference_mode():
        prefill = model(
            prefix,
            past_key_values=DynamicCache(config=model.config),
            use_cache=True,
            return_dict=True,
        )
    cache = prefill.past_key_values
    require(int(cache.get_seq_length()) == prefill_tokens, "prefill cache length differs")
    observed_cache = cache_observation(cache, profile, prefill_tokens)
    canonical, raw_layers = extract_canonical_layers(cache, profile, prefill_tokens, torch_module)
    direct_token = torch_module.tensor([[last_prompt_token]], dtype=torch_module.long, device="cuda:0")
    direct_logits, direct_cache = model_step(model, direct_token, cache, torch_module)
    rebuilt_cache = dynamic_cache_from_layers(model, canonical, profile, torch_module)
    rebuilt_logits, rebuilt_cache = model_step(model, direct_token, rebuilt_cache, torch_module)
    structural_difference = float((direct_logits - rebuilt_logits).abs().max().item())
    structural_top1 = bool(torch_module.equal(direct_logits.argmax(dim=-1), rebuilt_logits.argmax(dim=-1)))
    require(structural_difference == 0.0 and structural_top1, "flatten/rebuild changed the native cache continuation")
    del cache, direct_cache, prefill, rebuilt_cache, direct_logits, rebuilt_logits
    torch_module.cuda.empty_cache()

    reconstructed, encoding = encode_layers(canonical, profile, cell_root)
    behavior = controlled_metrics(model, tokenizer, canonical, reconstructed, profile, last_prompt_token, torch_module)
    peak_allocated = int(torch_module.cuda.max_memory_allocated())
    peak_reserved = int(torch_module.cuda.max_memory_reserved())
    hard_memory_limit = int(profile["gpuAdmission"]["maxGpuMemoryBytes"])
    require(
        peak_allocated <= hard_memory_limit and peak_reserved <= hard_memory_limit,
        "actual CUDA peak exceeded the registered hard admission limit",
    )
    cgroup_memory = cgroup_memory_observation()
    peak_rss_bytes = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    packages = runtime_package_versions()
    result = {
        "schemaVersion": RESULT_SCHEMA_VERSION,
        "status": "COMPLETE",
        "classification": CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "model": {
            "modelId": profile["modelId"],
            "adapterId": profile["adapterId"],
            "repository": profile["repository"],
            "revision": profile["revision"],
            "geometry": profile["geometry"],
            "assetRootName": snapshot.name,
        },
        "workload": material,
        "codecSource": codec_manifest,
        "assetReceiptSHA256": asset_receipt_digest,
        "canonicalCacheBF16SHA256": cache_digest(raw_layers),
        "cacheObservation": observed_cache,
        "structuralReplay": {"maxAbsLogitDifference": structural_difference, "top1Identical": structural_top1},
        "encoding": encoding,
        "behavior": behavior,
        "runtime": {
            "startedAt": started_at,
            "completedAt": utc_now(),
            "python": platform.python_version(),
            "torch": torch_module.__version__,
            "cuda": torch_module.version.cuda,
            "gpuName": torch_module.cuda.get_device_name(0),
            "gpuDriverVersion": gpu_driver_version(),
            "gpuTotalBytes": total_bytes,
            "gpuFreeBytesBeforeCell": free_bytes,
            "memoryEstimateBytes": estimate,
            "peakAllocatedBytes": peak_allocated,
            "peakReservedBytes": peak_reserved,
            "peakRssBytes": peak_rss_bytes,
            "diskFreeBytesBeforeCell": disk_free_bytes,
            "diskRequiredBytes": disk_required_bytes,
            "modelRequirementsLockSHA256": codec_manifest["files"]["RealLLM/requirements.lock"]["sha256"],
            "pipBootstrapLockSHA256": codec_manifest["files"][".github/locks/pip-bootstrap.txt"]["sha256"],
            "portableRuntimeLockSHA256": codec_manifest["files"][".github/locks/real-llm-linux-cpu-py312.txt"]["sha256"],
            "cudaRuntimeLockSHA256": sha256_file(TORCH_LOCK_PATH),
            "packages": packages,
            **cgroup_memory,
            "dtype": "bfloat16",
            "attentionImplementation": "eager",
            "deterministicAlgorithms": True,
        },
    }
    result_path = cell_root / "result.json"
    write_canonical_json(result_path, result)
    print(canonical_json_bytes({"status": "COMPLETE", "modelId": arguments.model_id, "workloadId": arguments.workload_id, "resultSHA256": sha256_file(result_path)}).decode("utf-8"), flush=True)
    return 0


def sanitized_environment() -> dict[str, str]:
    allowed = {
        "HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "CUDA_VISIBLE_DEVICES",
        "CUDA_HOME",
        "VIRTUAL_ENV",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "HF_HOME",
    }
    result = {key: value for key, value in os.environ.items() if key in allowed and value}
    result.update(FIXED_ENVIRONMENT)
    result.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
    return result


def run_process_group(
    command: list[str],
    *,
    stdout: Any,
    stderr: Any,
    timeout_seconds: int,
    termination_grace_seconds: float = 60.0,
) -> tuple[int, bool]:
    """Run one cell in a fresh session and reap its entire group on timeout."""

    class ProcessGroupInterrupted(BaseException):
        def __init__(self, signum: int) -> None:
            self.signum = signum

    process: Any = None
    pending_signal: list[int] = []

    def group_exists() -> bool:
        require(process is not None, "cell process was not started")
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError as error:
            raise RuntimeError(
                "cannot prove ownership of the cell process group"
            ) from error

    def terminate_group(*, grace_seconds: float = termination_grace_seconds) -> None:
        require(process is not None, "cell process was not started")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace_seconds
        while group_exists() and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)
        if group_exists():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.wait(timeout=10)
        reap_deadline = time.monotonic() + 10.0
        while group_exists() and time.monotonic() < reap_deadline:
            time.sleep(0.05)
        require(not group_exists(), "cell process group survived TERM/KILL cleanup")

    handled_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous_handlers = {
        signum: signal.getsignal(signum) for signum in handled_signals
    }

    def interrupt_handler(signum: int, _frame: Any) -> None:
        if process is None:
            pending_signal.append(signum)
            return
        raise ProcessGroupInterrupted(signum)

    for signum in handled_signals:
        signal.signal(signum, interrupt_handler)
    try:
        process = subprocess.Popen(
            command,
            cwd=LAB_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=sanitized_environment(),
            start_new_session=True,
        )
        if pending_signal:
            raise ProcessGroupInterrupted(pending_signal[0])
        returncode = process.wait(timeout=timeout_seconds)
        if not group_exists():
            return returncode, False
        terminate_group()
        return 125, False
    except subprocess.TimeoutExpired:
        terminate_group()
        return 124, True
    except ProcessGroupInterrupted as interruption:
        # The outer wrapper sends TERM and allows 60 seconds before KILL.
        # Bound child-group cleanup to half that window, then terminate the
        # orchestrator without starting another matrix cell.
        terminate_group(grace_seconds=min(termination_grace_seconds, 30.0))
        raise SystemExit(128 + interruption.signum) from None
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


def orchestrate(arguments: argparse.Namespace) -> int:
    preflight_value = load_preflight(arguments.preflight)
    codec_manifest = validate_codec_root(arguments.codec_root)
    source = git_source_identity()
    require(preflight_value.get("source") == source, "preflight source identity differs")
    require(preflight_value.get("codecSource") == codec_manifest, "preflight codec identity differs")
    cache_root = safe_directory(arguments.cache, "asset cache", create=False)
    _, asset_receipt_digest = verify_asset_receipt(arguments.assets, cache_root)
    require(
        preflight_value.get("assetReceiptSHA256") == asset_receipt_digest,
        "preflight asset receipt differs",
    )
    run_root = safe_directory(arguments.run_dir, "run directory", create=True)
    (run_root / "cells").mkdir(mode=0o700)
    (run_root / "logs").mkdir(mode=0o700)
    workload_order = [entry["workloadId"] for entry in load_workloads()["workloads"]]
    records: list[dict[str, Any]] = []
    run_id = str(uuid.uuid4())
    python = str(Path(sys.executable).resolve())
    for model_id in MODEL_ORDER:
        for workload_id in workload_order:
            identifier = f"{model_id}--{workload_id}"
            stdout_path = run_root / "logs" / f"{identifier}.stdout.log"
            stderr_path = run_root / "logs" / f"{identifier}.stderr.log"
            command = [
                python,
                "-E",
                "-s",
                "-B",
                str(Path(__file__).resolve()),
                "run-cell",
                "--codec-root",
                str(arguments.codec_root.resolve()),
                "--cache",
                str(arguments.cache.resolve()),
                "--assets",
                str(arguments.assets.resolve()),
                "--preflight",
                str(arguments.preflight.resolve()),
                "--run-dir",
                str(run_root),
                "--model-id",
                model_id,
                "--workload-id",
                workload_id,
            ]
            started = utc_now()
            profile = profile_by_id(model_id)
            timeout_limit = int(profile["gpuAdmission"]["executionTimeoutSeconds"])
            cell_root = run_root / "cells" / model_id / workload_id
            cell_root.mkdir(mode=0o700, parents=True, exist_ok=False)
            write_canonical_json(
                cell_root / "attempt.json",
                {
                    "schemaVersion": ATTEMPT_SCHEMA_VERSION,
                    "status": "STARTED",
                    "classification": CLASSIFICATION,
                    "countsTowardScientificVerdict": False,
                    "runId": run_id,
                    "attemptId": str(uuid.uuid4()),
                    "startedAt": started,
                    "modelId": model_id,
                    "adapterId": profile["adapterId"],
                    "workloadId": workload_id,
                    "timeoutLimitSeconds": timeout_limit,
                    "source": source,
                    "codecSource": codec_manifest,
                    "preflightSHA256": sha256_file(arguments.preflight),
                    "assetReceiptSHA256": asset_receipt_digest,
                    "profilesSHA256": sha256_file(PROFILES_PATH),
                    "workloadsSHA256": sha256_file(WORKLOADS_PATH),
                    "protocolSHA256": sha256_file(PROTOCOL_PATH),
                },
            )
            timeout = False
            with stdout_path.open("xb") as stdout_handle, stderr_path.open("xb") as stderr_handle:
                os.chmod(stdout_path, 0o600)
                os.chmod(stderr_path, 0o600)
                returncode, timeout = run_process_group(
                    command,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout_seconds=timeout_limit,
                )
            result_path = run_root / "cells" / model_id / workload_id / "result.json"
            result_digest = sha256_file(result_path) if result_path.is_file() else None
            record_status = (
                "COMPLETE" if returncode == 0 and result_digest else "EXECUTION_ERROR"
            )
            if timeout:
                termination_reason = "timeout"
            elif returncode == 125:
                termination_reason = "process-group-residue"
            elif returncode < 0:
                termination_reason = "signal"
            elif returncode != 0:
                termination_reason = "nonzero-exit"
            elif result_digest is None:
                termination_reason = "missing-result"
            else:
                termination_reason = "completed"
            records.append(
                {
                    "modelId": model_id,
                    "workloadId": workload_id,
                    "startedAt": started,
                    "completedAt": utc_now(),
                    "returnCode": returncode,
                    "exitSignal": -returncode if returncode < 0 else None,
                    "timedOut": timeout,
                    "timeoutLimitSeconds": timeout_limit,
                    "terminationReason": termination_reason,
                    "status": record_status,
                    "resultPath": str(result_path.relative_to(run_root)) if result_digest else None,
                    "resultSHA256": result_digest,
                    "stdoutSHA256": sha256_file(stdout_path),
                    "stderrSHA256": sha256_file(stderr_path),
                }
            )
            print(f"CELL {model_id} {workload_id} {record_status}", flush=True)
            gc.collect()
    complete = all(record["status"] == "COMPLETE" for record in records)
    run = {
        "schemaVersion": RUN_SCHEMA_VERSION,
        "runId": run_id,
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "classification": CLASSIFICATION,
        "countsTowardScientificVerdict": False,
        "source": git_source_identity(),
        "preflightSHA256": sha256_file(arguments.preflight),
        "assetReceiptSHA256": asset_receipt_digest,
        "profilesSHA256": sha256_file(PROFILES_PATH),
        "workloadsSHA256": sha256_file(WORKLOADS_PATH),
        "protocolSHA256": sha256_file(PROTOCOL_PATH),
        "expectedCells": len(MODEL_ORDER) * len(workload_order),
        "completeCells": sum(record["status"] == "COMPLETE" for record in records),
        "cells": records,
    }
    write_canonical_json(run_root / "run.json", run)
    print(canonical_json_bytes(run).decode("utf-8"), flush=True)
    return 0 if complete else 1


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--codec-root", type=Path, required=True)
    preflight_parser.add_argument("--cache", type=Path, required=True)
    preflight_parser.add_argument("--assets", type=Path, required=True)
    preflight_parser.add_argument("--output", type=Path, required=True)
    orchestrator = subparsers.add_parser("orchestrate")
    orchestrator.add_argument("--codec-root", type=Path, required=True)
    orchestrator.add_argument("--cache", type=Path, required=True)
    orchestrator.add_argument("--assets", type=Path, required=True)
    orchestrator.add_argument("--preflight", type=Path, required=True)
    orchestrator.add_argument("--run-dir", type=Path, required=True)
    orchestrator.add_argument("--cell-timeout-seconds", type=int, default=2700)
    cell = subparsers.add_parser("run-cell")
    cell.add_argument("--codec-root", type=Path, required=True)
    cell.add_argument("--cache", type=Path, required=True)
    cell.add_argument("--assets", type=Path, required=True)
    cell.add_argument("--preflight", type=Path, required=True)
    cell.add_argument("--run-dir", type=Path, required=True)
    cell.add_argument("--model-id", choices=MODEL_ORDER, required=True)
    cell.add_argument("--workload-id", required=True)
    return parser.parse_args()


def main() -> int:
    global np
    arguments = parse_arguments()
    import numpy as numpy_module

    np = numpy_module
    if arguments.command == "preflight":
        return preflight(arguments)
    if arguments.command == "orchestrate":
        registered_maximum = max(
            int(profile["gpuAdmission"]["executionTimeoutSeconds"])
            for profile in load_profiles()["profiles"]
        )
        require(
            arguments.cell_timeout_seconds == registered_maximum,
            "orchestrator timeout ceiling differs from the registered maximum",
        )
        return orchestrate(arguments)
    if arguments.command == "run-cell":
        return run_cell(arguments)
    raise AssertionError(arguments.command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ADAPTER SWEEP FAIL: {error}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        raise SystemExit(1)
