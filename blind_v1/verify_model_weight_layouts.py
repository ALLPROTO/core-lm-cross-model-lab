#!/usr/bin/env python3
"""Re-derive the frozen safetensors layout fixture without reading payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
SUITE_ID = "corelm-blind-crossmodel-v1"
SCHEMA = "corelm-blind-crossmodel-v1-model-weight-layouts-v1"
MODEL_KEYS = {
    "distilgpt2-82m",
    "gpt2-124m",
    "pythia-160m",
    "pythia-70m",
    "smollm-135m",
    "smollm-360m",
}
MAX_HEADER_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GPT2_BUFFER = re.compile(r"transformer\.h\.[0-9]+\.attn\.(?:bias|masked_bias)\Z")
GPT_NEOX_BUFFER = re.compile(
    r"gpt_neox\.layers\.[0-9]+\.attention\."
    r"(?:bias|masked_bias|rotary_emb\.inv_freq)\Z"
)


class ModelWeightLayoutError(RuntimeError):
    """Raised when the exact downloaded headers differ from the tracked fixture."""


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def key_digest(keys: Any) -> str:
    ordered = sorted(str(key) for key in keys)
    return sha256_bytes(("\n".join(ordered) + "\n").encode("utf-8"))


def load_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelWeightLayoutError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ModelWeightLayoutError(f"{label} is not an object")
    return value


def read_small_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ModelWeightLayoutError(f"cannot stat {label}: {path}") from error
    if not path.is_file() or path.is_symlink() or size <= 0 or size > maximum_bytes:
        raise ModelWeightLayoutError(f"unsafe {label}: {path}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ModelWeightLayoutError(f"{label} changed while being read: {path}")
    return raw


def read_safetensors_header(
    path: Path, *, expected_file_bytes: int
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Read exactly 8 + header-length bytes and stop before the tensor payload."""

    try:
        size = path.stat().st_size
    except OSError as error:
        raise ModelWeightLayoutError(f"cannot stat model weights: {path}") from error
    if (
        not path.is_file()
        or path.is_symlink()
        or size != expected_file_bytes
        or size <= 8
    ):
        raise ModelWeightLayoutError(f"model weight file identity differs: {path}")
    with path.open("rb") as handle:
        prefix = handle.read(8)
        if len(prefix) != 8:
            raise ModelWeightLayoutError(f"truncated safetensors prefix: {path}")
        header_bytes = int.from_bytes(prefix, "little")
        if (
            header_bytes <= 0
            or header_bytes > MAX_HEADER_BYTES
            or header_bytes >= expected_file_bytes - 8
        ):
            raise ModelWeightLayoutError(f"unsafe safetensors header length: {path}")
        raw_header = handle.read(header_bytes)
        if len(raw_header) != header_bytes:
            raise ModelWeightLayoutError(f"truncated safetensors header: {path}")
        if handle.tell() != 8 + header_bytes:
            raise ModelWeightLayoutError(
                f"header reader crossed tensor-payload boundary: {path}"
            )
    return prefix, raw_header, load_json(raw_header, label=f"header {path}")


def normalize_keys(
    keys: set[str], *, model_type: str, tie_word_embeddings: bool
) -> tuple[str, str, list[str], set[str]]:
    """Return namespace policy, input key, ignored source keys, and target keys."""

    if model_type == "gpt2":
        prefixed = any(key.startswith("transformer.") for key in keys)
        legacy = any(key.startswith(("h.", "wte.", "wpe.", "ln_f.")) for key in keys)
        if prefixed == legacy:
            raise ModelWeightLayoutError("GPT-2 header namespace is ambiguous")
        if legacy and any(
            key != "lm_head.weight"
            and not key.startswith(("h.", "wte.", "wpe.", "ln_f."))
            for key in keys
        ):
            raise ModelWeightLayoutError("GPT-2 legacy namespace contains unknown keys")
        namespace = "add-transformer-prefix" if legacy else "identity-transformer-prefix"
        input_key = "transformer.wte.weight"
    elif model_type == "gpt_neox":
        if "embed_out.weight" not in keys or "lm_head.weight" in keys:
            raise ModelWeightLayoutError("Pythia output-head namespace differs")
        namespace = "embed-out-to-lm-head"
        input_key = "gpt_neox.embed_in.weight"
    elif model_type == "llama":
        namespace = "identity"
        input_key = "model.embed_tokens.weight"
    else:
        raise ModelWeightLayoutError(f"unexpected confirmatory model_type: {model_type}")

    ignored: list[str] = []
    result: set[str] = set()
    for source in keys:
        if model_type == "gpt2" and namespace == "add-transformer-prefix" and source != "lm_head.weight":
            target = "transformer." + source
        elif model_type == "gpt_neox" and source == "embed_out.weight":
            target = "lm_head.weight"
        else:
            target = source
        discard = (
            model_type == "gpt2" and GPT2_BUFFER.fullmatch(target) is not None
        ) or (
            model_type == "gpt_neox" and GPT_NEOX_BUFFER.fullmatch(target) is not None
        )
        if discard:
            ignored.append(source)
            continue
        if target in result:
            raise ModelWeightLayoutError(f"weight normalization collision: {target}")
        result.add(target)
    if input_key not in result:
        raise ModelWeightLayoutError("normalized input embedding is absent")
    if tie_word_embeddings:
        result.add("lm_head.weight")
    elif "lm_head.weight" not in result:
        raise ModelWeightLayoutError("normalized untied output head is absent")
    return namespace, input_key, sorted(ignored), result


def derive_layout(*, asset_root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest_raw = read_small_file(
        manifest_path, maximum_bytes=64 * 1024, label="model asset manifest"
    )
    manifest = load_json(manifest_raw, label="model asset manifest")
    models = manifest.get("models")
    if not isinstance(models, dict) or set(models) != MODEL_KEYS:
        raise ModelWeightLayoutError("model asset manifest pool differs")

    derived: dict[str, Any] = {}
    for model_key in sorted(MODEL_KEYS):
        record = models[model_key]
        if not isinstance(record, dict) or not isinstance(record.get("files"), dict):
            raise ModelWeightLayoutError(f"model manifest record differs: {model_key}")
        files = record["files"]
        config_commitment = files.get("config.json")
        weight_commitment = files.get("model.safetensors")
        if not isinstance(config_commitment, dict) or not isinstance(weight_commitment, dict):
            raise ModelWeightLayoutError(f"model file commitments differ: {model_key}")
        for commitment in (config_commitment, weight_commitment):
            if (
                set(commitment) != {"bytes", "sha256"}
                or type(commitment["bytes"]) is not int
                or commitment["bytes"] <= 0
                or not isinstance(commitment["sha256"], str)
                or SHA256.fullmatch(commitment["sha256"]) is None
            ):
                raise ModelWeightLayoutError(f"invalid model commitment: {model_key}")

        model_root = asset_root / model_key
        config_raw = read_small_file(
            model_root / "config.json",
            maximum_bytes=64 * 1024,
            label=f"{model_key} config",
        )
        if (
            len(config_raw) != config_commitment["bytes"]
            or sha256_bytes(config_raw) != config_commitment["sha256"]
        ):
            raise ModelWeightLayoutError(f"config commitment differs: {model_key}")
        config = load_json(config_raw, label=f"{model_key} config")
        model_type = config.get("model_type")
        tie_value = config.get("tie_word_embeddings")
        if tie_value is None and model_type == "gpt2":
            # Transformers 5.14.1 GPT2Config defaults this omitted field to true.
            tie_value = True
        if type(tie_value) is not bool:
            raise ModelWeightLayoutError(
                f"tie_word_embeddings is not fixed for {model_key}"
            )

        prefix, raw_header, header = read_safetensors_header(
            model_root / "model.safetensors",
            expected_file_bytes=weight_commitment["bytes"],
        )
        header.pop("__metadata__", None)
        tensors: dict[str, dict[str, Any]] = {}
        for key, tensor in header.items():
            if (
                not isinstance(key, str)
                or not key
                or not isinstance(tensor, dict)
                or not isinstance(tensor.get("dtype"), str)
                or not isinstance(tensor.get("shape"), list)
                or any(type(value) is not int or value <= 0 for value in tensor["shape"])
            ):
                raise ModelWeightLayoutError(f"invalid header tensor: {model_key}/{key}")
            tensors[key] = {"dtype": tensor["dtype"], "shape": tensor["shape"]}
        namespace, input_key, ignored, normalized = normalize_keys(
            set(tensors),
            model_type=model_type,
            tie_word_embeddings=tie_value,
        )
        derived[model_key] = {
            "modelFileBytes": weight_commitment["bytes"],
            # This full-file identity comes from the separately full-rehashed
            # asset manifest; this header-only verifier never recomputes it.
            "modelFileSHA256": weight_commitment["sha256"],
            "headerLengthPrefixHex": prefix.hex(),
            "headerBytes": len(raw_header),
            "headerSHA256": sha256_bytes(raw_header),
            "tensorCount": len(tensors),
            "stateKeysSHA256": key_digest(tensors),
            "modelType": model_type,
            "tieWordEmbeddings": tie_value,
            "inputEmbeddingKey": input_key,
            "namespacePolicy": namespace,
            "ignoredStateKeys": ignored,
            "normalizedStateKeyCount": len(normalized),
            "normalizedStateKeysSHA256": key_digest(normalized),
            "tensors": tensors,
        }
    return {
        "schemaVersion": SCHEMA,
        "suiteId": SUITE_ID,
        "status": "EXACT_SAFETENSORS_HEADERS_PINNED_NO_TENSOR_PAYLOAD",
        "payloadBytesIncluded": False,
        "models": derived,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--asset-root",
        type=Path,
        default=BLIND_V1_ROOT / ".assets",
        help="directory populated by fetch_assets.py",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=BLIND_V1_ROOT / "model-assets.draft.json",
    )
    parser.add_argument(
        "--tracked",
        type=Path,
        default=BLIND_V1_ROOT / "model-weight-layouts.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    derived = canonical_json_bytes(
        derive_layout(
            asset_root=arguments.asset_root.resolve(strict=True),
            manifest_path=arguments.manifest.resolve(strict=True),
        )
    )
    tracked = read_small_file(
        arguments.tracked.resolve(strict=True),
        maximum_bytes=4 * 1024 * 1024,
        label="tracked model-weight layouts",
    )
    if derived != tracked:
        raise ModelWeightLayoutError(
            "re-derived model-weight layouts differ from the tracked fixture"
        )
    print(
        json.dumps(
            {
                "schemaVersion": "corelm-blind-crossmodel-v1-model-weight-layout-check-v1",
                "status": "PASS_EXACT_HEADER_LAYOUTS_MATCH",
                "modelCount": len(MODEL_KEYS),
                "tensorCount": sum(
                    record["tensorCount"]
                    for record in json.loads(derived)["models"].values()
                ),
                "trackedBytes": len(tracked),
                "trackedSHA256": sha256_bytes(tracked),
                "tensorPayloadBytesRead": 0,
                "modelInferenceUsed": False,
                "networkUsed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
