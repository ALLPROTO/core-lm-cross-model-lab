#!/usr/bin/env python3
"""Variable-layer KV-cache geometry and lossless layout controls for v2.

This module contains no model loading or inference entry point. Its NumPy
round-trip is a protocol-control test only; the frozen experiment must also
prove exact logits with every registered real model before design release.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np


SUPPORTED_MODEL_TYPES = {"gpt_neo", "llama", "gpt_bigcode"}


def _positive_int(config: Mapping[str, Any], field: str) -> int:
    value = config.get(field)
    if type(value) is not int or value < 1:
        raise ValueError(f"model config field is not a positive integer: {field}")
    return value


def geometry_from_config(config: Mapping[str, Any]) -> dict[str, int | str]:
    model_type = config.get("model_type")
    if model_type not in SUPPORTED_MODEL_TYPES:
        raise ValueError(f"unsupported v2 model_type: {model_type!r}")
    if model_type == "gpt_neo":
        layers = _positive_int(config, "num_layers")
        attention_heads = _positive_int(config, "num_heads")
        hidden_size = _positive_int(config, "hidden_size")
        kv_heads = attention_heads
        attention_layout = "mixed-global-local"
    elif model_type == "llama":
        layers = _positive_int(config, "num_hidden_layers")
        attention_heads = _positive_int(config, "num_attention_heads")
        hidden_size = _positive_int(config, "hidden_size")
        kv_heads = _positive_int(config, "num_key_value_heads")
        attention_layout = "grouped-query"
    else:
        layers = _positive_int(config, "n_layer")
        attention_heads = _positive_int(config, "n_head")
        hidden_size = _positive_int(config, "n_embd")
        multi_query = config.get("multi_query")
        if type(multi_query) is not bool:
            raise ValueError("GPTBigCode multi_query must be an explicit boolean")
        kv_heads = 1 if multi_query else attention_heads
        attention_layout = "multi-query" if multi_query else "multi-head"
    if hidden_size % attention_heads:
        raise ValueError("hidden size is not divisible by attention heads")
    head_dimension = hidden_size // attention_heads
    trajectory_width = 2 * kv_heads * head_dimension
    if trajectory_width % 128:
        raise ValueError("K+V trajectory width is not divisible by transform block 128")
    return {
        "modelType": str(model_type),
        "attentionLayout": attention_layout,
        "layers": layers,
        "attentionHeads": attention_heads,
        "kvHeads": kv_heads,
        "headDimension": head_dimension,
        "hiddenSize": hidden_size,
        "trajectoryWidth": trajectory_width,
    }


def flatten_kv_numpy(
    keys: np.ndarray,
    values: np.ndarray,
    geometry: Mapping[str, int | str],
    *,
    tokens: int,
) -> np.ndarray:
    kv_heads = int(geometry["kvHeads"])
    head_dimension = int(geometry["headDimension"])
    expected = (1, kv_heads, tokens, head_dimension)
    if keys.shape != expected or values.shape != expected:
        raise ValueError(
            f"cache shape mismatch: keys={keys.shape}, values={values.shape}, expected={expected}"
        )
    if keys.dtype != np.float32 or values.dtype != np.float32:
        raise ValueError("cache arrays must be canonical float32")
    if not np.isfinite(keys).all() or not np.isfinite(values).all():
        raise ValueError("cache arrays contain non-finite values")
    key_trajectory = keys[0].transpose(1, 0, 2).reshape(tokens, -1)
    value_trajectory = values[0].transpose(1, 0, 2).reshape(tokens, -1)
    result = np.ascontiguousarray(
        np.concatenate((key_trajectory, value_trajectory), axis=1),
        dtype=np.float32,
    )
    if result.shape != (tokens, int(geometry["trajectoryWidth"])):
        raise ValueError("flattened cache trajectory shape mismatch")
    return result


def rebuild_kv_numpy(
    trajectory: np.ndarray,
    geometry: Mapping[str, int | str],
    *,
    tokens: int,
) -> tuple[np.ndarray, np.ndarray]:
    width = int(geometry["trajectoryWidth"])
    kv_heads = int(geometry["kvHeads"])
    head_dimension = int(geometry["headDimension"])
    if trajectory.shape != (tokens, width) or trajectory.dtype != np.float32:
        raise ValueError("decoded trajectory has an invalid shape or dtype")
    key_width = kv_heads * head_dimension
    keys = np.ascontiguousarray(
        trajectory[:, :key_width]
        .reshape(tokens, kv_heads, head_dimension)
        .transpose(1, 0, 2)[None, ...],
        dtype=np.float32,
    )
    values = np.ascontiguousarray(
        trajectory[:, key_width:]
        .reshape(tokens, kv_heads, head_dimension)
        .transpose(1, 0, 2)[None, ...],
        dtype=np.float32,
    )
    return keys, values


def validate_trajectory_layers(
    layers: list[np.ndarray], geometry: Mapping[str, int | str], *, tokens: int
) -> None:
    expected_layers = int(geometry["layers"])
    expected_shape = (tokens, int(geometry["trajectoryWidth"]))
    if len(layers) != expected_layers:
        raise ValueError(
            f"cache layer count mismatch: {len(layers)} != {expected_layers}"
        )
    for layer_index, trajectory in enumerate(layers):
        if trajectory.shape != expected_shape or trajectory.dtype != np.float32:
            raise ValueError(f"trajectory layer is invalid: {layer_index}")
        if not np.isfinite(trajectory).all():
            raise ValueError(f"trajectory layer is non-finite: {layer_index}")


def build_dynamic_cache(
    layers: list[np.ndarray],
    geometry: Mapping[str, int | str],
    *,
    model_config: Any,
    device: str,
    torch_module: Any,
    tokens: int,
) -> Any:
    """Build a Transformers DynamicCache without a fixed layer-count assumption."""

    from transformers import DynamicCache

    validate_trajectory_layers(layers, geometry, tokens=tokens)
    cache = DynamicCache(config=model_config)
    for layer_index, trajectory in enumerate(layers):
        keys, values = rebuild_kv_numpy(trajectory, geometry, tokens=tokens)
        cache.update(
            torch_module.from_numpy(keys).to(device),
            torch_module.from_numpy(values).to(device),
            layer_index,
        )
    if len(cache.layers) != int(geometry["layers"]):
        raise ValueError("rebuilt DynamicCache layer count mismatch")
    if int(cache.get_seq_length()) != tokens:
        raise ValueError("rebuilt DynamicCache sequence length mismatch")
    return cache
