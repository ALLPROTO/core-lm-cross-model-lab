#!/usr/bin/env python3
"""Independent real-model replay for the blind multi-model v4 evidence.

This module deliberately does not import ``model_worker``, ``evidence``, or
``protocol``.  It owns its input parsing, corpus-record parsing, VTL5 decoder,
cache layout, model loading, tokenization, and exact per-token comparison.
The public production entry point has no fixture/backend injection parameter;
small injected backends are exposed only through the page-level validation
seam used by unit tests.
"""

from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import re
import socket
import stat
import struct
import sys
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol


# These controls are fixed before NumPy, Torch, tokenizers, safetensors, or
# Transformers are imported lazily by the production backend.
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OPENBLAS_NUM_THREADS"] = "2"
os.environ["MKL_NUM_THREADS"] = "2"
os.environ["VECLIB_MAXIMUM_THREADS"] = "2"
os.environ["NUMEXPR_NUM_THREADS"] = "2"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
os.environ["DO_NOT_TRACK"] = "1"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v4-author-verified"
SUMMARY_SCHEMA = "corelm-crossmodel-livewiki-v4-independent-model-replay-v1"
RAW_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v4-raw-token-evidence-v1"
PAGE_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v4-page-token-evidence-v1"
CONTAINER_SCHEMA = "corelm-crossmodel-livewiki-v4-container-evidence-v1"
WORKER_JOB_SCHEMA = "corelm-crossmodel-livewiki-v4-worker-job-v1"
RECORD_MAGIC = b"CORELM-LIVEWIKI-V4-RECORD\0"
PREFILL_TOKENS = 383
PREDICTION_TOKENS = 128
PAGE_TOKENS = 512
PAGES_PER_CORPUS = 16
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
MODEL_FILES = {
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
}
RAW_FIELDS = {
    "schemaVersion",
    "suiteId",
    "attemptId",
    "modelKey",
    "corpusProject",
    "pageRevisionId",
    "pageSelectionIndex",
    "predictionIndex",
    "targetTokenId",
    "baselineLossF32Bits",
    "candidateLossF32Bits",
    "baselineTop1TokenId",
    "candidateTop1TokenId",
}
PAGE_FIELDS = {
    "schemaVersion",
    "suiteId",
    "attemptId",
    "modelKey",
    "corpusProject",
    "pageRevisionId",
    "pageSelectionIndex",
    "vocabSize",
    "first512TokenIds",
    "first512StreamSHA256",
}
CONTAINER_FIELDS = {
    "schemaVersion",
    "suiteId",
    "attemptId",
    "modelKey",
    "corpusProject",
    "pageRevisionId",
    "pageSelectionIndex",
    "layerIndex",
    "denseBF16Bytes",
    "containerBytes",
    "containerSHA256",
    "relativePath",
    "structuralReplay",
}


class IndependentModelReplayError(RuntimeError):
    """Raised when archived evidence differs from real-model replay."""


class PageReplayBackend(Protocol):
    """Narrow pure-validation seam; production always uses the real backend."""

    vocab_size: int
    layers: int
    trajectory_width: int

    def tokenize(self, text: str) -> list[int]: ...

    def baseline_cache(self, prefix_ids: list[int]) -> list[Any]: ...

    def evaluate(
        self,
        continuation_ids: list[int],
        targets: list[int],
        baseline_layers: list[Any],
        candidate_layers: list[Any],
    ) -> list[dict[str, Any]]: ...


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise IndependentModelReplayError("value is not canonical JSON") from error


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentModelReplayError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise IndependentModelReplayError(f"non-finite JSON value: {value}")


def load_json_strict_bytes(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndependentModelReplayError(f"invalid JSON: {label}") from error


def load_canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise IndependentModelReplayError(f"canonical JSON lacks terminal LF: {label}")
    value = load_json_strict_bytes(raw[:-1], label=label)
    if not isinstance(value, dict) or canonical_json_bytes(value) + b"\n" != raw:
        raise IndependentModelReplayError(f"non-canonical JSON object: {label}")
    return value


def load_canonical_jsonl(raw: bytes, *, label: str) -> list[dict[str, Any]]:
    if not raw or not raw.endswith(b"\n"):
        raise IndependentModelReplayError(f"canonical JSONL lacks terminal LF: {label}")
    values: list[dict[str, Any]] = []
    for index, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise IndependentModelReplayError(f"blank JSONL line: {label}:{index}")
        value = load_json_strict_bytes(line, label=f"{label}:{index}")
        if not isinstance(value, dict) or canonical_json_bytes(value) != line:
            raise IndependentModelReplayError(
                f"non-canonical JSONL object: {label}:{index}"
            )
        values.append(value)
    return values


def _safe_relative(value: Any, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise IndependentModelReplayError(f"invalid relative path: {label}")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise IndependentModelReplayError(f"relative path escapes root: {label}")
    return relative


def read_beneath(
    root: Path,
    relative_value: Any,
    *,
    maximum_bytes: int,
    expected_bytes: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    relative = _safe_relative(relative_value, label="sealed input")
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise IndependentModelReplayError("invalid input resource bound")
    if expected_bytes is not None and (
        type(expected_bytes) is not int
        or expected_bytes < 0
        or expected_bytes > maximum_bytes
    ):
        raise IndependentModelReplayError("invalid committed byte count")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or HEX_64.fullmatch(expected_sha256) is None
    ):
        raise IndependentModelReplayError("invalid committed SHA-256")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    try:
        directory = os.open(absolute_root, directory_flags)
    except OSError as error:
        raise IndependentModelReplayError("sealed root cannot be opened safely") from error
    try:
        for component in relative.parts[:-1]:
            next_directory = os.open(component, directory_flags, dir_fd=directory)
            metadata = os.fstat(next_directory)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_directory)
                raise IndependentModelReplayError("sealed parent is not a directory")
            os.close(directory)
            directory = next_directory
        descriptor = os.open(
            relative.parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
                raise IndependentModelReplayError("sealed file type/size is invalid")
            if expected_bytes is not None and before.st_size != expected_bytes:
                raise IndependentModelReplayError("sealed file byte count differs")
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise IndependentModelReplayError("sealed file was truncated")
                chunks.append(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            identity = lambda item: (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
            )
            if identity(before) != identity(after):
                raise IndependentModelReplayError("sealed file changed during read")
            if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
                raise IndependentModelReplayError("sealed file SHA-256 differs")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise IndependentModelReplayError(
            "sealed path contains a symlink or missing component"
        ) from error
    finally:
        os.close(directory)


def _u64(raw: bytes, offset: int, *, label: str) -> tuple[int, int]:
    if offset + 8 > len(raw):
        raise IndependentModelReplayError(f"corpus record is truncated: {label}")
    return int.from_bytes(raw[offset : offset + 8], "big"), offset + 8


def parse_corpus_record(raw: bytes) -> dict[str, Any]:
    """Parse and byte-for-byte reconstruct the frozen corpus record format."""

    if not raw.startswith(RECORD_MAGIC):
        raise IndependentModelReplayError("corpus record magic differs")
    offset = len(RECORD_MAGIC)

    def take_string(label: str) -> tuple[str, bytes]:
        nonlocal offset
        length, offset = _u64(raw, offset, label=f"{label} length")
        end = offset + length
        if end > len(raw):
            raise IndependentModelReplayError(f"corpus record is truncated: {label}")
        encoded = raw[offset:end]
        offset = end
        try:
            value = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise IndependentModelReplayError(
                f"corpus record is not UTF-8: {label}"
            ) from error
        if value.encode("utf-8", errors="strict") != encoded:
            raise IndependentModelReplayError(f"corpus record is non-canonical: {label}")
        return value, encoded

    project, project_raw = take_string("project")
    numbers: list[int] = []
    number_raw: list[bytes] = []
    for label in ("pageid", "revid", "userid"):
        start = offset
        number, offset = _u64(raw, offset, label=label)
        numbers.append(number)
        number_raw.append(raw[start:offset])
    strings: list[str] = []
    string_raw: list[bytes] = []
    for label in ("timestamp", "username", "title", "content"):
        start = offset
        value, _encoded = take_string(label)
        strings.append(value)
        string_raw.append(raw[start:offset])
    if offset != len(raw):
        raise IndependentModelReplayError("corpus record has trailing bytes")
    rebuilt = b"".join(
        (RECORD_MAGIC, len(project_raw).to_bytes(8, "big"), project_raw)
        + tuple(number_raw)
        + tuple(string_raw)
    )
    if rebuilt != raw:
        raise IndependentModelReplayError("corpus record reconstruction differs")
    return {
        "project": project,
        "pageid": numbers[0],
        "revid": numbers[1],
        "userid": numbers[2],
        "timestamp": strings[0],
        "username": strings[1],
        "title": strings[2],
        "content": strings[3],
    }


def token_id_stream(token_ids: list[int]) -> bytes:
    if any(type(item) is not int or not 0 <= item < 2**32 for item in token_ids):
        raise IndependentModelReplayError("token stream contains a non-uint32 ID")
    return struct.pack("<Q", len(token_ids)) + b"".join(
        struct.pack("<I", item) for item in token_ids
    )


def float32_bits(value: float) -> str:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise IndependentModelReplayError("model replay produced a non-finite float")
    packed = struct.pack(">f", numeric)
    if not math.isfinite(struct.unpack(">f", packed)[0]):
        raise IndependentModelReplayError("model replay overflowed float32")
    return packed.hex()


def _float32_sha256(array: Any) -> str:
    import numpy as np

    canonical = np.ascontiguousarray(np.asarray(array), dtype=np.dtype("<f4"))
    return hashlib.sha256(canonical.tobytes(order="C")).hexdigest()


def _decompress_canonical(
    stored: bytes, mode: str, expected_bytes: int, *, label: str
) -> bytes:
    if mode == "none":
        raw = stored
    elif mode == "zlib-9":
        decompressor = zlib.decompressobj()
        try:
            raw = decompressor.decompress(stored, expected_bytes + 1)
            if len(raw) > expected_bytes or decompressor.unconsumed_tail:
                raise IndependentModelReplayError(f"decoded {label} exceeds bound")
            raw += decompressor.flush(expected_bytes + 1 - len(raw))
        except zlib.error as error:
            raise IndependentModelReplayError(f"invalid compressed {label}") from error
        if (
            len(raw) > expected_bytes
            or not decompressor.eof
            or decompressor.unused_data
            or decompressor.unconsumed_tail
            or zlib.compress(raw, level=9) != stored
        ):
            raise IndependentModelReplayError(f"non-canonical zlib-9 {label}")
    else:
        raise IndependentModelReplayError(f"unsupported compression for {label}")
    if len(raw) != expected_bytes:
        raise IndependentModelReplayError(f"decoded {label} length differs")
    return raw


def _unpack_lsb_codes(packed: bytes, bits: int, count: int) -> list[int]:
    expected = (count * bits + 7) // 8
    if len(packed) != expected:
        raise IndependentModelReplayError("packed VTL5 code length differs")
    mask = (1 << bits) - 1
    values: list[int] = []
    accumulator = 0
    buffered = 0
    for byte in packed:
        accumulator |= byte << buffered
        buffered += 8
        while buffered >= bits and len(values) < count:
            values.append(accumulator & mask)
            accumulator >>= bits
            buffered -= bits
    if len(values) != count or accumulator != 0:
        raise IndependentModelReplayError("VTL5 code stream/padding differs")
    return values


def _unpack_vtl5_codes(packed: bytes, bits: int, count: int) -> list[int]:
    if bits <= 8:
        return _unpack_lsb_codes(packed, bits, count)
    if len(packed) < count:
        raise IndependentModelReplayError("VTL5 high-bit code stream is truncated")
    lows = packed[:count]
    highs = _unpack_lsb_codes(packed[count:], bits - 8, count)
    return [low | (high << 8) for low, high in zip(lows, highs, strict=True)]


def _walsh_hadamard(values: Any) -> Any:
    import numpy as np

    transformed = np.asarray(values, dtype=np.float64).copy()
    width = transformed.shape[-1]
    if width < 1 or width & (width - 1):
        raise IndependentModelReplayError("VTL5 transform width is not power-of-two")
    flattened = transformed.reshape(-1, width)
    half = 1
    while half < width:
        stride = half * 2
        for start in range(0, width, stride):
            left = flattened[:, start : start + half].copy()
            right = flattened[:, start + half : start + stride].copy()
            flattened[:, start : start + half] = left + right
            flattened[:, start + half : start + stride] = left - right
        half = stride
    transformed /= math.sqrt(width)
    return transformed


def decode_vtl5_container(
    raw: bytes,
    *,
    expected_layer: int,
    expected_bits: int,
    expected_rows: int,
    expected_columns: int,
    expected_group_size: int,
    expected_transform_block_size: int,
    expected_sign_mode: str,
    expected_input_sha256: str,
) -> tuple[Any, dict[str, Any]]:
    """Decode the registered uniform-bit VTL5 profile without codec imports."""

    import numpy as np

    if len(raw) < 8 or len(raw) > 256 * 1024 * 1024:
        raise IndependentModelReplayError("VTL5 container size is invalid")
    magic, metadata_length = struct.unpack_from("<4sI", raw)
    if magic != b"VTL5" or metadata_length > 1024 * 1024:
        raise IndependentModelReplayError("VTL5 header differs")
    metadata_end = 8 + metadata_length
    if metadata_end > len(raw):
        raise IndependentModelReplayError("VTL5 metadata is truncated")
    metadata_bytes = raw[8:metadata_end]
    metadata = load_json_strict_bytes(metadata_bytes, label="VTL5 metadata")
    if not isinstance(metadata, dict) or canonical_json_bytes(metadata) != metadata_bytes:
        raise IndependentModelReplayError("VTL5 metadata is not canonical")
    expected_fields = {
        "bits",
        "codeCompression",
        "codeCount",
        "codeMapping",
        "dtype",
        "format",
        "groupSize",
        "groupsPerRow",
        "inputSha256",
        "layerIndex",
        "packedBytes",
        "packing",
        "payloadBytes",
        "payloadSha256",
        "quantization",
        "reconstructionSha256",
        "scaleBytes",
        "scaleCompression",
        "scaleCount",
        "scaleDtype",
        "shape",
        "signDerivation",
        "signMode",
        "storedCodeBytes",
        "storedScaleBytes",
        "transform",
        "transformBlockSize",
    }
    if set(metadata) != expected_fields:
        raise IndependentModelReplayError("VTL5 metadata fields differ")
    expected_strings = {
        "format": "voidtoken-rotated-entropy-v5",
        "dtype": "float32",
        "scaleDtype": "float16-le",
        "quantization": "symmetric-max-abs-v1",
        "codeMapping": "zigzag-symmetric-v1",
        "transform": "normalized-walsh-hadamard-v1",
        "signDerivation": "shake256-layer-column-v1",
        "scaleCompression": "zlib-9",
        "codeCompression": "zlib-9",
        "signMode": expected_sign_mode,
        "packing": (
            "lsb-first-v1"
            if expected_bits <= 8
            else "byte-low-plus-lsb-high-fields-v1"
        ),
    }
    for field, expected in expected_strings.items():
        if metadata.get(field) != expected:
            raise IndependentModelReplayError(f"VTL5 metadata differs: {field}")
    if (
        metadata.get("shape") != [expected_rows, expected_columns]
        or metadata.get("bits") != expected_bits
        or metadata.get("layerIndex") != expected_layer
        or metadata.get("groupSize") != expected_group_size
        or metadata.get("transformBlockSize") != expected_transform_block_size
        or metadata.get("inputSha256") != expected_input_sha256
    ):
        raise IndependentModelReplayError("VTL5 container-to-cache mapping differs")
    if expected_columns % expected_group_size or expected_columns % expected_transform_block_size:
        raise IndependentModelReplayError("VTL5 expected cache geometry is invalid")
    groups_per_row = expected_columns // expected_group_size
    scale_count = expected_rows * groups_per_row
    code_count = expected_rows * expected_columns
    scale_bytes = scale_count * 2
    packed_bytes = (code_count * expected_bits + 7) // 8
    expected_integers = {
        "groupsPerRow": groups_per_row,
        "scaleCount": scale_count,
        "codeCount": code_count,
        "scaleBytes": scale_bytes,
        "packedBytes": packed_bytes,
    }
    for field, expected in expected_integers.items():
        if type(metadata.get(field)) is not int or metadata[field] != expected:
            raise IndependentModelReplayError(f"VTL5 layout differs: {field}")
    for field in ("storedScaleBytes", "storedCodeBytes", "payloadBytes"):
        if type(metadata.get(field)) is not int or metadata[field] < 1:
            raise IndependentModelReplayError(f"VTL5 byte field is invalid: {field}")
    if metadata["payloadBytes"] != metadata["storedScaleBytes"] + metadata["storedCodeBytes"]:
        raise IndependentModelReplayError("VTL5 payload byte accounting differs")
    for field in ("inputSha256", "payloadSha256", "reconstructionSha256"):
        if not isinstance(metadata[field], str) or HEX_64.fullmatch(metadata[field]) is None:
            raise IndependentModelReplayError(f"VTL5 digest is invalid: {field}")
    payload = raw[metadata_end:]
    if len(payload) != metadata["payloadBytes"] or sha256_bytes(payload) != metadata["payloadSha256"]:
        raise IndependentModelReplayError("VTL5 payload commitment differs")
    scale_payload = _decompress_canonical(
        payload[: metadata["storedScaleBytes"]],
        metadata["scaleCompression"],
        scale_bytes,
        label="VTL5 scales",
    )
    code_payload = _decompress_canonical(
        payload[metadata["storedScaleBytes"] :],
        metadata["codeCompression"],
        packed_bytes,
        label="VTL5 codes",
    )
    scales = np.frombuffer(scale_payload, dtype=np.dtype("<f2"), count=scale_count)
    if (
        not np.isfinite(scales).all()
        or np.any(scales < np.float16(0.0))
        or np.any(np.signbit(scales))
    ):
        raise IndependentModelReplayError("VTL5 scales are invalid")
    codes = np.asarray(
        _unpack_vtl5_codes(code_payload, expected_bits, code_count),
        dtype=np.int32,
    )
    qmax = (1 << (expected_bits - 1)) - 1
    if np.any(codes > 2 * qmax):
        raise IndependentModelReplayError("VTL5 payload uses an unused code")
    quantized = np.where((codes & 1) == 0, codes // 2, -((codes + 1) // 2))
    quantized = quantized.reshape(expected_rows, groups_per_row, expected_group_size)
    scale_groups = scales.reshape(expected_rows, groups_per_row)
    if np.any((scale_groups == np.float16(0.0)) & np.any(quantized != 0, axis=2)):
        raise IndependentModelReplayError("VTL5 zero-scale group has non-zero codes")
    transformed = (
        quantized.astype(np.float64)
        * scale_groups.astype(np.float64)[:, :, np.newaxis]
    ).reshape(expected_rows, expected_columns)
    grouped = transformed.reshape(
        expected_rows,
        expected_columns // expected_transform_block_size,
        expected_transform_block_size,
    )
    reconstructed = _walsh_hadamard(grouped)
    if expected_sign_mode == "none":
        signs = 1.0
    else:
        material = (
            "voidtoken-rotated-entropy-v5|shake256-layer-column-v1|"
            f"layer={expected_layer}|columns={expected_columns}"
        ).encode("ascii")
        sign_bytes = hashlib.shake_256(material).digest(expected_columns)
        sign_vector = np.where(
            (np.frombuffer(sign_bytes, dtype=np.uint8) & np.uint8(1)) == 0,
            -1.0,
            1.0,
        ).astype(np.float64)
        signs = sign_vector.reshape(
            1,
            expected_columns // expected_transform_block_size,
            expected_transform_block_size,
        )
    reconstructed = np.ascontiguousarray(
        (reconstructed * signs).reshape(expected_rows, expected_columns),
        dtype=np.float32,
    )
    if _float32_sha256(reconstructed) != metadata["reconstructionSha256"]:
        raise IndependentModelReplayError("VTL5 reconstruction SHA-256 differs")
    return reconstructed, metadata


def _geometry_from_config(config: dict[str, Any]) -> dict[str, int | str]:
    model_type = config.get("model_type")

    def positive(field: str) -> int:
        value = config.get(field)
        if type(value) is not int or value < 1:
            raise IndependentModelReplayError(
                f"model config geometry is invalid: {field}"
            )
        return value

    if model_type == "gpt_neo":
        layers = positive("num_layers")
        attention_heads = positive("num_heads")
        hidden_size = positive("hidden_size")
        kv_heads = attention_heads
        layout = "mixed-global-local"
    elif model_type == "llama":
        layers = positive("num_hidden_layers")
        attention_heads = positive("num_attention_heads")
        hidden_size = positive("hidden_size")
        kv_heads = positive("num_key_value_heads")
        layout = "grouped-query"
    elif model_type == "gpt_bigcode":
        layers = positive("n_layer")
        attention_heads = positive("n_head")
        hidden_size = positive("n_embd")
        multi_query = config.get("multi_query")
        if type(multi_query) is not bool:
            raise IndependentModelReplayError(
                "GPTBigCode multi_query geometry is not explicit"
            )
        kv_heads = 1 if multi_query else attention_heads
        layout = "multi-query" if multi_query else "multi-head"
    else:
        raise IndependentModelReplayError(
            f"unsupported registered model_type: {model_type!r}"
        )
    if hidden_size % attention_heads:
        raise IndependentModelReplayError("hidden size is not divisible by heads")
    head_dimension = hidden_size // attention_heads
    trajectory_width = 2 * kv_heads * head_dimension
    if trajectory_width % 128:
        raise IndependentModelReplayError(
            "cache trajectory width is not divisible by 128"
        )
    return {
        "modelType": str(model_type),
        "attentionLayout": layout,
        "layers": layers,
        "attentionHeads": attention_heads,
        "kvHeads": kv_heads,
        "headDimension": head_dimension,
        "hiddenSize": hidden_size,
        "trajectoryWidth": trajectory_width,
    }


class RealModelReplayBackend:
    """Fresh CPU model/tokenizer loaded solely from committed owned bytes."""

    def __init__(
        self,
        model_bytes: dict[str, bytes],
        *,
        expected_vocab_size: int,
        expected_layers: int,
    ) -> None:
        import numpy as np
        import safetensors
        import tokenizers
        import torch
        import transformers
        from safetensors.torch import load as load_safetensors
        from tokenizers import Tokenizer
        from transformers import (
            GPTBigCodeConfig,
            GPTBigCodeForCausalLM,
            GPTNeoConfig,
            GPTNeoForCausalLM,
            LlamaConfig,
            LlamaForCausalLM,
        )

        config_object = load_json_strict_bytes(
            model_bytes["config.json"], label="replay model config"
        )
        if not isinstance(config_object, dict):
            raise IndependentModelReplayError("model config is not an object")
        classes = {
            "gpt_neo": (GPTNeoConfig, GPTNeoForCausalLM),
            "llama": (LlamaConfig, LlamaForCausalLM),
            "gpt_bigcode": (GPTBigCodeConfig, GPTBigCodeForCausalLM),
        }
        model_type = config_object.get("model_type")
        if model_type not in classes:
            raise IndependentModelReplayError(
                f"unsupported replay model_type: {model_type!r}"
            )
        config_class, model_class = classes[model_type]
        config = config_class.from_dict(config_object)
        config._attn_implementation = "eager"
        config.use_cache = True
        model = model_class(config).float().cpu()
        try:
            state = load_safetensors(model_bytes["model.safetensors"])
        except BaseException as error:
            raise IndependentModelReplayError(
                "independent replay could not decode safetensors weights"
            ) from error
        missing, unexpected = model.load_state_dict(state, strict=False, assign=False)
        allowed_missing = {"lm_head.weight"}
        if set(missing) - allowed_missing:
            raise IndependentModelReplayError(
                f"replay model weights are incomplete: {sorted(set(missing) - allowed_missing)}"
            )
        allowed_unexpected = re.compile(
            r"transformer\.h\.\d+\.attn(?:\.attention)?\.(?:bias|masked_bias)\Z"
        )
        if any(allowed_unexpected.fullmatch(value) is None for value in unexpected):
            raise IndependentModelReplayError(
                f"replay model weights contain unexpected tensors: {unexpected}"
            )
        model.tie_weights()
        if "lm_head.weight" in missing:
            output = model.get_output_embeddings()
            inputs = model.get_input_embeddings()
            if (
                output is None
                or inputs is None
                or output.weight.data_ptr() != inputs.weight.data_ptr()
            ):
                raise IndependentModelReplayError(
                    "replay model did not restore tied output weights"
                )
        del state
        model.eval()
        for parameter in model.parameters():
            if parameter.device.type != "cpu" or parameter.dtype != torch.float32:
                raise IndependentModelReplayError(
                    "replay model parameters are not CPU float32"
                )
            if not torch.isfinite(parameter).all():
                raise IndependentModelReplayError(
                    "replay model contains a non-finite parameter"
                )
        try:
            tokenizer = Tokenizer.from_str(
                model_bytes["tokenizer.json"].decode("utf-8", errors="strict")
            )
        except (UnicodeDecodeError, ValueError) as error:
            raise IndependentModelReplayError(
                "independent replay could not load tokenizer bytes"
            ) from error
        geometry = _geometry_from_config(config_object)
        observed_vocab = config_object.get("vocab_size")
        tokenizer_vocab = tokenizer.get_vocab_size(with_added_tokens=True)
        if observed_vocab != expected_vocab_size or tokenizer_vocab != expected_vocab_size:
            raise IndependentModelReplayError(
                "replay model/tokenizer vocabulary differs from frozen design"
            )
        if int(geometry["layers"]) != expected_layers:
            raise IndependentModelReplayError(
                "replay model layer count differs from frozen design"
            )
        self._np = np
        self._torch = torch
        self._model = model
        self._tokenizer = tokenizer
        self._config_object = config_object
        self.geometry = geometry
        self.vocab_size = expected_vocab_size
        self.layers = expected_layers
        self.trajectory_width = int(geometry["trajectoryWidth"])
        self.runtime = {
            "numpy": str(np.__version__),
            "safetensors": str(safetensors.__version__),
            "tokenizers": str(tokenizers.__version__),
            "torch": str(torch.__version__),
            "transformers": str(transformers.__version__),
        }

    def tokenize(self, text: str) -> list[int]:
        encoded = self._tokenizer.encode(text, add_special_tokens=False)
        values = list(encoded.ids)
        if any(
            type(value) is not int or not 0 <= value < self.vocab_size
            for value in values
        ):
            raise IndependentModelReplayError(
                "replay tokenizer produced an out-of-vocabulary ID"
            )
        return values

    def baseline_cache(self, prefix_ids: list[int]) -> list[Any]:
        np = self._np
        torch = self._torch
        ids = torch.tensor([prefix_ids], dtype=torch.long)
        with torch.inference_mode():
            prefill = self._model(
                ids,
                use_cache=True,
                return_dict=True,
                logits_to_keep=1,
            )
        cache = prefill.past_key_values
        if not hasattr(cache, "layers") or len(cache.layers) != self.layers:
            raise IndependentModelReplayError(
                "replay model returned an unexpected cache layer count"
            )
        kv_heads = int(self.geometry["kvHeads"])
        head_dimension = int(self.geometry["headDimension"])
        expected = (1, kv_heads, PREFILL_TOKENS, head_dimension)
        canonical: list[Any] = []
        for layer_index, layer in enumerate(cache.layers):
            keys = layer.keys.detach().float().cpu()
            values = layer.values.detach().float().cpu()
            if tuple(keys.shape) != expected or tuple(values.shape) != expected:
                raise IndependentModelReplayError(
                    f"replay cache shape differs at layer {layer_index}"
                )
            key_trajectory = (
                keys.numpy()[0]
                .transpose(1, 0, 2)
                .reshape(PREFILL_TOKENS, -1)
            )
            value_trajectory = (
                values.numpy()[0]
                .transpose(1, 0, 2)
                .reshape(PREFILL_TOKENS, -1)
            )
            flattened = np.ascontiguousarray(
                np.concatenate((key_trajectory, value_trajectory), axis=1),
                dtype=np.float32,
            )
            canonical_tensor = torch.from_numpy(flattened).to(torch.bfloat16)
            canonical.append(
                np.ascontiguousarray(
                    canonical_tensor.float().numpy(), dtype=np.float32
                )
            )
        return canonical

    def _build_cache(self, layers: list[Any]) -> Any:
        np = self._np
        torch = self._torch
        from transformers import DynamicCache

        if len(layers) != self.layers:
            raise IndependentModelReplayError("replay cache layer count differs")
        cache = DynamicCache(config=self._model.config)
        kv_heads = int(self.geometry["kvHeads"])
        head_dimension = int(self.geometry["headDimension"])
        key_width = kv_heads * head_dimension
        expected_shape = (PREFILL_TOKENS, self.trajectory_width)
        for layer_index, candidate in enumerate(layers):
            trajectory = np.asarray(candidate)
            if (
                trajectory.shape != expected_shape
                or trajectory.dtype != np.float32
                or not np.isfinite(trajectory).all()
            ):
                raise IndependentModelReplayError(
                    f"replay trajectory is invalid at layer {layer_index}"
                )
            keys = np.ascontiguousarray(
                trajectory[:, :key_width]
                .reshape(PREFILL_TOKENS, kv_heads, head_dimension)
                .transpose(1, 0, 2)[None, ...],
                dtype=np.float32,
            )
            values = np.ascontiguousarray(
                trajectory[:, key_width:]
                .reshape(PREFILL_TOKENS, kv_heads, head_dimension)
                .transpose(1, 0, 2)[None, ...],
                dtype=np.float32,
            )
            cache.update(
                torch.from_numpy(keys),
                torch.from_numpy(values),
                layer_index,
            )
        if len(cache.layers) != self.layers or int(cache.get_seq_length()) != PREFILL_TOKENS:
            raise IndependentModelReplayError("rebuilt replay cache geometry differs")
        return cache

    def _continuation_logits(self, continuation_ids: list[int], layers: list[Any]) -> Any:
        torch = self._torch
        input_ids = torch.tensor([continuation_ids], dtype=torch.long)
        cache = self._build_cache(layers)
        positions = torch.arange(
            PREFILL_TOKENS,
            PREFILL_TOKENS + PREDICTION_TOKENS,
            dtype=torch.long,
        ).unsqueeze(0)
        kwargs: dict[str, Any] = {
            "past_key_values": cache,
            "position_ids": positions,
            "attention_mask": torch.ones(
                (1, PAGE_TOKENS - 1), dtype=torch.long
            ),
            "use_cache": False,
            "return_dict": True,
            "logits_to_keep": 0,
        }
        if self._config_object["model_type"] == "llama":
            kwargs["cache_position"] = positions
        with torch.inference_mode():
            logits = self._model(input_ids, **kwargs).logits.float().cpu()
        if (
            tuple(logits.shape[:2]) != (1, PREDICTION_TOKENS)
            or int(logits.shape[-1]) != self.vocab_size
            or not torch.isfinite(logits).all()
        ):
            raise IndependentModelReplayError(
                "replay continuation logits are invalid"
            )
        return logits

    def evaluate(
        self,
        continuation_ids: list[int],
        targets: list[int],
        baseline_layers: list[Any],
        candidate_layers: list[Any],
    ) -> list[dict[str, Any]]:
        import torch.nn.functional as functional

        torch = self._torch
        baseline_logits = self._continuation_logits(
            continuation_ids, baseline_layers
        )
        candidate_logits = self._continuation_logits(
            continuation_ids, candidate_layers
        )
        target_tensor = torch.tensor(targets, dtype=torch.long)
        baseline_losses = functional.cross_entropy(
            baseline_logits.reshape(-1, self.vocab_size),
            target_tensor,
            reduction="none",
        ).float()
        candidate_losses = functional.cross_entropy(
            candidate_logits.reshape(-1, self.vocab_size),
            target_tensor,
            reduction="none",
        ).float()
        baseline_top1 = baseline_logits.argmax(dim=-1).reshape(-1)
        candidate_top1 = candidate_logits.argmax(dim=-1).reshape(-1)
        if any(
            value.numel() != PREDICTION_TOKENS
            for value in (
                baseline_losses,
                candidate_losses,
                baseline_top1,
                candidate_top1,
            )
        ):
            raise IndependentModelReplayError(
                "replay did not produce exactly 128 predictions"
            )
        return [
            {
                "targetTokenId": targets[index],
                "baselineLossF32Bits": float32_bits(
                    float(baseline_losses[index].item())
                ),
                "candidateLossF32Bits": float32_bits(
                    float(candidate_losses[index].item())
                ),
                "baselineTop1TokenId": int(baseline_top1[index].item()),
                "candidateTop1TokenId": int(candidate_top1[index].item()),
            }
            for index in range(PREDICTION_TOKENS)
        ]

    def close(self) -> None:
        self._model = None
        self._tokenizer = None
        gc.collect()


def replay_page(
    *,
    backend: PageReplayBackend,
    suite_id: str,
    attempt_id: str,
    model_key: str,
    corpus: str,
    page_index: int,
    revision: int,
    record_raw: bytes,
    page_evidence: dict[str, Any],
    raw_evidence: list[dict[str, Any]],
    container_evidence: list[dict[str, Any]],
    candidate: dict[str, Any],
    bits_by_layer: list[int],
    container_reader: Callable[[dict[str, Any]], bytes],
    container_decoder: Callable[..., tuple[Any, dict[str, Any]]] = decode_vtl5_container,
) -> dict[str, Any]:
    """Pure page replay seam shared by production and adversarial unit tests."""

    import numpy as np

    parsed = parse_corpus_record(record_raw)
    if parsed["project"] != corpus or parsed["revid"] != revision:
        raise IndependentModelReplayError("corpus record identity differs")
    text = parsed["title"] + "\n\n" + parsed["content"]
    token_ids = backend.tokenize(text)
    if len(token_ids) < PAGE_TOKENS:
        raise IndependentModelReplayError("retokenized corpus record has fewer than 512 IDs")
    token_ids = token_ids[:PAGE_TOKENS]
    if any(type(value) is not int or not 0 <= value < backend.vocab_size for value in token_ids):
        raise IndependentModelReplayError("retokenized ID is outside frozen vocabulary")
    expected_identity = {
        "suiteId": suite_id,
        "attemptId": attempt_id,
        "modelKey": model_key,
        "corpusProject": corpus,
        "pageRevisionId": revision,
        "pageSelectionIndex": page_index,
    }
    if (
        not isinstance(page_evidence, dict)
        or set(page_evidence) != PAGE_FIELDS
        or page_evidence.get("schemaVersion") != PAGE_TOKEN_SCHEMA
        or any(page_evidence.get(field) != value for field, value in expected_identity.items())
        or page_evidence.get("vocabSize") != backend.vocab_size
        or page_evidence.get("first512TokenIds") != token_ids
        or page_evidence.get("first512StreamSHA256")
        != sha256_bytes(token_id_stream(token_ids))
    ):
        raise IndependentModelReplayError(
            "retokenized IDs differ from page-token evidence"
        )
    prefix_ids = token_ids[:PREFILL_TOKENS]
    continuation_ids = token_ids[PREFILL_TOKENS:-1]
    targets = token_ids[PREFILL_TOKENS + 1 :]
    if len(continuation_ids) != PREDICTION_TOKENS or len(targets) != PREDICTION_TOKENS:
        raise IndependentModelReplayError("page replay token partition differs")
    baseline_layers = backend.baseline_cache(prefix_ids)
    if len(baseline_layers) != backend.layers or len(bits_by_layer) != backend.layers:
        raise IndependentModelReplayError("baseline cache/frozen schedule layer count differs")
    expected_shape = (PREFILL_TOKENS, backend.trajectory_width)
    for layer_index, layer in enumerate(baseline_layers):
        array = np.asarray(layer)
        if (
            array.shape != expected_shape
            or array.dtype != np.float32
            or not np.isfinite(array).all()
        ):
            raise IndependentModelReplayError(
                f"baseline BF16 cache trajectory is invalid: layer {layer_index}"
            )

    ordered_containers = sorted(
        container_evidence, key=lambda item: item.get("layerIndex", -1)
    )
    if len(ordered_containers) != backend.layers:
        raise IndependentModelReplayError("page container layer coverage differs")
    candidate_layers: list[Any] = []
    container_commitments: list[dict[str, Any]] = []
    for layer_index, record in enumerate(ordered_containers):
        expected_path = (
            f"containers/{model_key}/{corpus}/revision-{revision}/"
            f"layer-{layer_index:02d}.vtl5"
        )
        dense_bytes = int(np.asarray(baseline_layers[layer_index]).size) * 2
        if (
            not isinstance(record, dict)
            or set(record) != CONTAINER_FIELDS
            or record.get("schemaVersion") != CONTAINER_SCHEMA
            or any(record.get(field) != value for field, value in expected_identity.items())
            or record.get("layerIndex") != layer_index
            or record.get("denseBF16Bytes") != dense_bytes
            or record.get("relativePath") != expected_path
            or record.get("structuralReplay") is not True
            or type(record.get("containerBytes")) is not int
            or record["containerBytes"] < 1
            or not isinstance(record.get("containerSHA256"), str)
            or HEX_64.fullmatch(record["containerSHA256"]) is None
        ):
            raise IndependentModelReplayError(
                f"container-to-page/layer mapping differs: layer {layer_index}"
            )
        container_raw = container_reader(record)
        if (
            len(container_raw) != record["containerBytes"]
            or sha256_bytes(container_raw) != record["containerSHA256"]
        ):
            raise IndependentModelReplayError(
                f"container bytes differ: layer {layer_index}"
            )
        decoded, metadata = container_decoder(
            container_raw,
            expected_layer=layer_index,
            expected_bits=bits_by_layer[layer_index],
            expected_rows=PREFILL_TOKENS,
            expected_columns=backend.trajectory_width,
            expected_group_size=candidate["groupSize"],
            expected_transform_block_size=candidate["transformBlockSize"],
            expected_sign_mode=candidate["signMode"],
            expected_input_sha256=_float32_sha256(baseline_layers[layer_index]),
        )
        decoded_array = np.asarray(decoded)
        if (
            decoded_array.shape != expected_shape
            or decoded_array.dtype != np.float32
            or not np.isfinite(decoded_array).all()
        ):
            raise IndependentModelReplayError(
                f"decoded candidate cache is invalid: layer {layer_index}"
            )
        candidate_layers.append(np.ascontiguousarray(decoded_array, dtype=np.float32))
        container_commitments.append(
            {
                "layerIndex": layer_index,
                "relativePath": expected_path,
                "containerBytes": record["containerBytes"],
                "containerSHA256": record["containerSHA256"],
                "inputSHA256": metadata["inputSha256"],
                "reconstructionSHA256": metadata["reconstructionSha256"],
            }
        )
    computed = backend.evaluate(
        continuation_ids,
        targets,
        baseline_layers,
        candidate_layers,
    )
    ordered_raw = sorted(raw_evidence, key=lambda item: item.get("predictionIndex", -1))
    if len(ordered_raw) != PREDICTION_TOKENS or len(computed) != PREDICTION_TOKENS:
        raise IndependentModelReplayError("raw-token replay coverage differs")
    metric_fields = {
        "targetTokenId",
        "baselineLossF32Bits",
        "candidateLossF32Bits",
        "baselineTop1TokenId",
        "candidateTop1TokenId",
    }
    for prediction_index, (record, expected_metrics) in enumerate(
        zip(ordered_raw, computed, strict=True)
    ):
        if (
            not isinstance(record, dict)
            or set(record) != RAW_FIELDS
            or record.get("schemaVersion") != RAW_TOKEN_SCHEMA
            or any(record.get(field) != value for field, value in expected_identity.items())
            or record.get("predictionIndex") != prediction_index
            or not isinstance(expected_metrics, dict)
            or set(expected_metrics) != metric_fields
        ):
            raise IndependentModelReplayError(
                f"raw-token identity/order differs: prediction {prediction_index}"
            )
        for field in metric_fields:
            if record[field] != expected_metrics[field]:
                raise IndependentModelReplayError(
                    "real-model replay differs from raw-token evidence: "
                    f"prediction {prediction_index}/{field}"
                )
    return {
        "corpusProject": corpus,
        "pageSelectionIndex": page_index,
        "pageRevisionId": revision,
        "predictions": PREDICTION_TOKENS,
        "containers": backend.layers,
        "tokenStreamSHA256": page_evidence["first512StreamSHA256"],
        "containerCommitmentsSHA256": sha256_bytes(
            canonical_json_bytes(container_commitments)
        ),
    }


def install_network_denial() -> None:
    """Install an independent in-process denial in addition to the OS sandbox."""

    def deny(event: str, _arguments: tuple[Any, ...]) -> None:
        if event.startswith("socket."):
            raise IndependentModelReplayError(
                f"network forbidden during independent model replay: {event}"
            )

    sys.addaudithook(deny)

    class DeniedSocket:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise IndependentModelReplayError(
                "network forbidden during independent model replay"
            )

    socket.socket = DeniedSocket  # type: ignore[assignment]
    socket.create_connection = DeniedSocket  # type: ignore[assignment]


def _configure_deterministic_cpu() -> None:
    import numpy as np
    import torch

    torch.manual_seed(0)
    np.random.seed(0)
    try:
        torch.set_num_threads(2)
        torch.set_num_interop_threads(1)
    except RuntimeError as error:
        raise IndependentModelReplayError(
            "Torch thread pools initialized before replay controls"
        ) from error
    torch.use_deterministic_algorithms(True, warn_only=False)
    if torch.get_num_threads() != 2 or torch.get_num_interop_threads() != 1:
        raise IndependentModelReplayError("Torch CPU thread controls differ")


def _private_entries(private_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = private_manifest.get("files")
    if not isinstance(files, list) or not files:
        raise IndependentModelReplayError("private snapshot file inventory is absent")
    result: dict[str, dict[str, Any]] = {}
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "bytes", "sha256", "role"}
            or not isinstance(entry.get("path"), str)
            or entry["path"] in result
            or type(entry.get("bytes")) is not int
            or entry["bytes"] < 1
            or not isinstance(entry.get("sha256"), str)
            or HEX_64.fullmatch(entry["sha256"]) is None
        ):
            raise IndependentModelReplayError(
                "private snapshot contains an invalid/duplicate file entry"
            )
        _safe_relative(entry["path"], label="private snapshot entry")
        result[entry["path"]] = entry
    return result


def _expected_worker_job(
    *,
    model_key: str,
    design: dict[str, Any],
    selection: dict[str, Any],
    marker: dict[str, Any],
    private_entries: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    models = design.get("models")
    if not isinstance(models, list):
        raise IndependentModelReplayError("frozen model list is absent")
    matching = [item for item in models if isinstance(item, dict) and item.get("key") == model_key]
    if len(matching) != 1:
        raise IndependentModelReplayError(f"frozen model identity differs: {model_key}")
    model = matching[0]
    files: dict[str, dict[str, Any]] = {}
    for filename in sorted(MODEL_FILES):
        path = f"models/{model_key}/{filename}"
        entry = private_entries.get(path)
        if entry is None or entry["role"] != "model-asset":
            raise IndependentModelReplayError(f"sealed model asset is absent: {path}")
        files[filename] = {
            "path": path,
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
        }
    if (
        files["model.safetensors"]["bytes"] != model.get("weightBytes")
        or files["model.safetensors"]["sha256"] != model.get("weightSHA256")
    ):
        raise IndependentModelReplayError(
            f"sealed weight bytes differ from frozen design: {model_key}"
        )
    corpora = selection.get("selectedCorpora")
    selected_pages = selection.get("selectedPages")
    if (
        not isinstance(corpora, list)
        or len(corpora) != 2
        or len(set(corpora)) != 2
        or not isinstance(selected_pages, dict)
        or set(selected_pages) != set(corpora)
    ):
        raise IndependentModelReplayError("selected corpus/page binding differs")
    pages: dict[str, list[dict[str, Any]]] = {}
    for corpus in corpora:
        selected = selected_pages[corpus]
        if not isinstance(selected, list) or len(selected) != PAGES_PER_CORPUS:
            raise IndependentModelReplayError("selected page count differs")
        values: list[dict[str, Any]] = []
        for page_index, item in enumerate(selected):
            if not isinstance(item, dict) or type(item.get("revid")) is not int:
                raise IndependentModelReplayError("selected revision is invalid")
            revision = item["revid"]
            path = f"records/{corpus}/{revision}.bin"
            entry = private_entries.get(path)
            if entry is None or entry["role"] != "eligible-corpus-record":
                raise IndependentModelReplayError(
                    f"sealed selected corpus record is absent: {path}"
                )
            values.append(
                {
                    "pageSelectionIndex": page_index,
                    "pageRevisionId": revision,
                    "recordPath": path,
                    "recordBytes": entry["bytes"],
                    "recordSHA256": entry["sha256"],
                }
            )
        pages[corpus] = values
    candidate = design.get("candidate")
    if not isinstance(candidate, dict):
        raise IndependentModelReplayError("frozen candidate profile is absent")
    return {
        "schemaVersion": WORKER_JOB_SCHEMA,
        "suiteId": marker["suiteId"],
        "attemptId": marker["attemptId"],
        "countsTowardScientificVerdict": True,
        "model": {
            "key": model_key,
            "files": files,
            "layers": model["layers"],
            "vocabSize": model["vocabSize"],
            "candidateBitsByLayer": model["candidateBitsByLayer"],
        },
        "selectedCorpora": corpora,
        "pages": pages,
        "candidate": {
            "backend": candidate["backend"],
            "groupSize": candidate["groupSize"],
            "transformBlockSize": candidate["transformBlockSize"],
            "codeCompression": candidate["codeCompression"],
            "scaleCompression": candidate["scaleCompression"],
            "signMode": candidate["signMode"],
        },
        "seed": 0,
    }


def _group_one(
    records: list[dict[str, Any]],
    *,
    corpus: str,
    page_index: int,
) -> list[dict[str, Any]]:
    return [
        item
        for item in records
        if item.get("corpusProject") == corpus
        and item.get("pageSelectionIndex") == page_index
    ]


def run_independent_model_replay(
    *,
    evidence_root: Path,
    private_root: Path,
    design: dict[str, Any],
    selection: dict[str, Any],
    marker: dict[str, Any],
    private_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Replay every selected real page with a fresh sequential model load."""

    if marker.get("suiteId") != SUITE_ID or design.get("suiteId") != SUITE_ID:
        raise IndependentModelReplayError("replay suite identity differs")
    attempt_id = marker.get("attemptId")
    if not isinstance(attempt_id, str) or ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise IndependentModelReplayError("replay attempt identity differs")
    model_order = selection.get("modelExecutionOrder")
    selected_corpora = selection.get("selectedCorpora")
    design_models = design.get("models")
    if (
        not isinstance(model_order, list)
        or len(model_order) != 3
        or len(set(model_order)) != 3
        or not isinstance(selected_corpora, list)
        or len(selected_corpora) != 2
        or not isinstance(design_models, list)
        or set(model_order)
        != {item.get("key") for item in design_models if isinstance(item, dict)}
    ):
        raise IndependentModelReplayError("replay model/corpus order differs")
    install_network_denial()
    _configure_deterministic_cpu()
    entries = _private_entries(private_manifest)
    model_summaries: list[dict[str, Any]] = []
    observed_runtime: dict[str, str] | None = None
    total_pages = 0
    total_predictions = 0
    total_containers = 0

    for model_key in model_order:
        job_relative = f"jobs/{model_key}.json"
        job_raw = read_beneath(
            evidence_root,
            job_relative,
            maximum_bytes=16 * 1024 * 1024,
        )
        job = load_canonical_line(job_raw, label=f"replay job {model_key}")
        expected_job = _expected_worker_job(
            model_key=model_key,
            design=design,
            selection=selection,
            marker=marker,
            private_entries=entries,
        )
        if job != expected_job:
            raise IndependentModelReplayError(
                f"replay worker job differs from sealed inputs: {model_key}"
            )
        model_bytes: dict[str, bytes] = {}
        model_file_commitments: list[dict[str, Any]] = []
        for filename in sorted(MODEL_FILES):
            specification = job["model"]["files"][filename]
            maximum = (
                2 * 1024 * 1024 * 1024
                if filename == "model.safetensors"
                else 32 * 1024 * 1024
            )
            raw = read_beneath(
                private_root,
                specification["path"],
                maximum_bytes=maximum,
                expected_bytes=specification["bytes"],
                expected_sha256=specification["sha256"],
            )
            model_bytes[filename] = raw
            model_file_commitments.append(
                {
                    "filename": filename,
                    "bytes": len(raw),
                    "sha256": sha256_bytes(raw),
                }
            )
        raw_relative = f"workers/{model_key}/raw-token-evidence.jsonl"
        container_relative = f"workers/{model_key}/container-evidence.jsonl"
        page_relative = f"workers/{model_key}/page-token-evidence.jsonl"
        raw_bytes = read_beneath(
            evidence_root, raw_relative, maximum_bytes=128 * 1024 * 1024
        )
        container_bytes = read_beneath(
            evidence_root, container_relative, maximum_bytes=64 * 1024 * 1024
        )
        page_bytes = read_beneath(
            evidence_root, page_relative, maximum_bytes=16 * 1024 * 1024
        )
        raw_records = load_canonical_jsonl(raw_bytes, label=raw_relative)
        container_records = load_canonical_jsonl(
            container_bytes, label=container_relative
        )
        page_records = load_canonical_jsonl(page_bytes, label=page_relative)
        expected_pages = 2 * PAGES_PER_CORPUS
        expected_layers = job["model"]["layers"]
        if (
            len(raw_records) != expected_pages * PREDICTION_TOKENS
            or len(container_records) != expected_pages * expected_layers
            or len(page_records) != expected_pages
        ):
            raise IndependentModelReplayError(
                f"replay evidence record counts differ: {model_key}"
            )
        try:
            backend = RealModelReplayBackend(
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
            raise IndependentModelReplayError(
                "dependency versions changed between sequential replay models"
            )
        page_summaries: list[dict[str, Any]] = []
        record_commitments: list[dict[str, Any]] = []
        container_commitments: list[dict[str, Any]] = []
        try:
            for corpus in selected_corpora:
                for page in job["pages"][corpus]:
                    page_index = page["pageSelectionIndex"]
                    revision = page["pageRevisionId"]
                    record_raw = read_beneath(
                        private_root,
                        page["recordPath"],
                        maximum_bytes=64 * 1024 * 1024,
                        expected_bytes=page["recordBytes"],
                        expected_sha256=page["recordSHA256"],
                    )
                    matching_pages = _group_one(
                        page_records, corpus=corpus, page_index=page_index
                    )
                    if len(matching_pages) != 1:
                        raise IndependentModelReplayError(
                            "page-token evidence identity is duplicated/missing"
                        )
                    matching_raw = _group_one(
                        raw_records, corpus=corpus, page_index=page_index
                    )
                    matching_containers = _group_one(
                        container_records, corpus=corpus, page_index=page_index
                    )

                    def container_reader(record: dict[str, Any]) -> bytes:
                        return read_beneath(
                            evidence_root,
                            record["relativePath"],
                            maximum_bytes=256 * 1024 * 1024,
                            expected_bytes=record["containerBytes"],
                            expected_sha256=record["containerSHA256"],
                        )

                    page_summary = replay_page(
                        backend=backend,
                        suite_id=SUITE_ID,
                        attempt_id=attempt_id,
                        model_key=model_key,
                        corpus=corpus,
                        page_index=page_index,
                        revision=revision,
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
                            "corpusProject": corpus,
                            "pageSelectionIndex": page_index,
                            "pageRevisionId": revision,
                            "bytes": len(record_raw),
                            "sha256": sha256_bytes(record_raw),
                        }
                    )
                    for item in sorted(
                        matching_containers, key=lambda value: value["layerIndex"]
                    ):
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
        replayed_predictions = len(page_summaries) * PREDICTION_TOKENS
        replayed_containers = len(container_commitments)
        model_summary = {
            "modelKey": model_key,
            "modelFileSetSHA256": sha256_bytes(
                canonical_json_bytes(model_file_commitments)
            ),
            "weightSHA256": job["model"]["files"]["model.safetensors"]["sha256"],
            "tokenizerSHA256": job["model"]["files"]["tokenizer.json"]["sha256"],
            "corpusRecordSetSHA256": sha256_bytes(
                canonical_json_bytes(record_commitments)
            ),
            "rawTokenEvidenceSHA256": sha256_bytes(raw_bytes),
            "pageTokenEvidenceSHA256": sha256_bytes(page_bytes),
            "containerEvidenceSHA256": sha256_bytes(container_bytes),
            "containerByteSetSHA256": sha256_bytes(
                canonical_json_bytes(container_commitments)
            ),
            "pageReplaySHA256": sha256_bytes(canonical_json_bytes(page_summaries)),
            "replayedPages": len(page_summaries),
            "replayedPredictions": replayed_predictions,
            "replayedContainers": replayed_containers,
            "exactTokenIds": True,
            "exactLossFloat32Bits": True,
            "exactTop1TokenIds": True,
            "allContainerInputsBoundToBaselineCache": True,
        }
        model_summaries.append(model_summary)
        total_pages += len(page_summaries)
        total_predictions += replayed_predictions
        total_containers += replayed_containers
    if observed_runtime is None:
        raise IndependentModelReplayError("no real model was replayed")
    summary: dict[str, Any] = {
        "schemaVersion": SUMMARY_SCHEMA,
        "suiteId": SUITE_ID,
        "attemptId": attempt_id,
        "modelOrder": model_order,
        "selectedCorpora": selected_corpora,
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
        "countsTowardScientificVerdict": True,
    }
    summary["contentSHA256"] = sha256_bytes(canonical_json_bytes(summary))
    return summary


__all__ = [
    "IndependentModelReplayError",
    "SUMMARY_SCHEMA",
    "canonical_json_bytes",
    "decode_vtl5_container",
    "float32_bits",
    "parse_corpus_record",
    "replay_page",
    "run_independent_model_replay",
    "sha256_bytes",
    "token_id_stream",
]
