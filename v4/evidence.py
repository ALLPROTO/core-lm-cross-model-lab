#!/usr/bin/env python3
"""Independent blind-v4 raw-evidence arithmetic and container verification."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from v4.protocol import canonical_json_bytes, evaluate_model_aggregate


RAW_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v4-raw-token-evidence-v1"
CONTAINER_SCHEMA = "corelm-crossmodel-livewiki-v4-container-evidence-v1"
PAGE_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v4-page-token-evidence-v1"
HEX_8 = re.compile(r"[0-9a-f]{8}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
MODELS_PER_SUITE = 3
CORPORA_PER_SUITE = 2
PAGES_PER_CELL = 16
PREDICTIONS_PER_PAGE = 128
PAGE_TOKENS_PER_PAGE = 512
FIRST_TARGET_TOKEN_OFFSET = 384


class EvidenceError(ValueError):
    """Raised when raw evidence cannot support a frozen verdict."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def float32_to_bits(value: float) -> str:
    numeric = float(value)
    if not math.isfinite(numeric):
        raise EvidenceError("non-finite float32 evidence is forbidden")
    packed = struct.pack(">f", numeric)
    decoded = struct.unpack(">f", packed)[0]
    if not math.isfinite(decoded):
        raise EvidenceError("value overflows the finite float32 domain")
    return packed.hex()


def float32_from_bits(value: Any, label: str) -> float:
    if not isinstance(value, str) or HEX_8.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be exactly eight lowercase hex digits")
    result = struct.unpack(">f", bytes.fromhex(value))[0]
    if not math.isfinite(result):
        raise EvidenceError(f"{label} is non-finite")
    return float(result)


def canonical_json_line(value: Any) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def token_id_stream(token_ids: Iterable[int]) -> bytes:
    """Encode a token stream as little-endian uint64 count plus uint32 IDs."""

    values = list(token_ids)
    for token_id in values:
        if type(token_id) is not int or not 0 <= token_id <= 2**32 - 1:
            raise EvidenceError("token stream contains a non-uint32 token ID")
    return struct.pack("<Q", len(values)) + b"".join(
        struct.pack("<I", token_id) for token_id in values
    )


def _parse_canonical_jsonl(raw: bytes, *, label: str) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n"):
        raise EvidenceError(f"evidence JSONL must end with LF: {label}")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise EvidenceError(f"blank evidence JSONL line {line_number}: {label}")
        try:
            text = line.decode("utf-8", errors="strict")
            value = json.loads(
                text,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(
                f"invalid evidence JSONL line {line_number}: {label}"
            ) from error
        if not isinstance(value, dict):
            raise EvidenceError(f"evidence line {line_number} is not an object")
        if canonical_json_bytes(value) != line:
            raise EvidenceError(f"evidence line {line_number} is not canonical JSON")
        records.append(value)
    return records


def load_canonical_jsonl(path: Path, *, maximum_bytes: int) -> list[dict[str, Any]]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"evidence JSONL is not a regular no-symlink file: {path}")
    if metadata.st_size < 1 or metadata.st_size > maximum_bytes:
        raise EvidenceError(f"evidence JSONL size is outside its bound: {path}")
    return _parse_canonical_jsonl(path.read_bytes(), label=str(path))


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number is forbidden: {value}")


def _require_uint(value: Any, label: str, *, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise EvidenceError(f"{label} is outside its unsigned integer domain")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be a non-empty string")
    value.encode("utf-8", errors="strict")
    return value


def _validate_raw_token(record: Any) -> dict[str, Any]:
    fields = {
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
    if not isinstance(record, dict) or set(record) != fields:
        raise EvidenceError("raw-token evidence fields differ from the frozen schema")
    if record["schemaVersion"] != RAW_TOKEN_SCHEMA:
        raise EvidenceError("raw-token schemaVersion differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _require_string(record[field], f"raw token {field}")
    _require_uint(record["pageRevisionId"], "pageRevisionId")
    _require_uint(
        record["pageSelectionIndex"],
        "pageSelectionIndex",
        maximum=PAGES_PER_CELL - 1,
    )
    _require_uint(
        record["predictionIndex"],
        "predictionIndex",
        maximum=PREDICTIONS_PER_PAGE - 1,
    )
    _require_uint(record["targetTokenId"], "targetTokenId", maximum=2**32 - 1)
    _require_uint(
        record["baselineTop1TokenId"],
        "baselineTop1TokenId",
        maximum=2**32 - 1,
    )
    _require_uint(
        record["candidateTop1TokenId"],
        "candidateTop1TokenId",
        maximum=2**32 - 1,
    )
    baseline = float32_from_bits(record["baselineLossF32Bits"], "baseline loss")
    candidate = float32_from_bits(record["candidateLossF32Bits"], "candidate loss")
    if baseline < 0.0 or candidate < 0.0:
        raise EvidenceError("token negative log-likelihood must be non-negative")
    return record


def _validate_page_token(record: Any) -> dict[str, Any]:
    fields = {
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
    if not isinstance(record, dict) or set(record) != fields:
        raise EvidenceError("page-token evidence fields differ from the frozen schema")
    if record["schemaVersion"] != PAGE_TOKEN_SCHEMA:
        raise EvidenceError("page-token schemaVersion differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _require_string(record[field], f"page token {field}")
    _require_uint(record["pageRevisionId"], "page token pageRevisionId")
    _require_uint(
        record["pageSelectionIndex"],
        "page token pageSelectionIndex",
        maximum=PAGES_PER_CELL - 1,
    )
    vocabulary_size = _require_uint(
        record["vocabSize"], "page token vocabSize", maximum=2**32
    )
    if vocabulary_size < 1:
        raise EvidenceError("page token vocabSize must be positive")
    token_ids = record["first512TokenIds"]
    if not isinstance(token_ids, list) or len(token_ids) != PAGE_TOKENS_PER_PAGE:
        raise EvidenceError("page-token evidence must contain exactly 512 token IDs")
    for token_id in token_ids:
        _require_uint(
            token_id,
            "page token ID",
            maximum=2**32 - 1,
        )
        if token_id >= vocabulary_size:
            raise EvidenceError("page token ID is outside the registered vocabulary")
    stream_digest = record["first512StreamSHA256"]
    if not isinstance(stream_digest, str) or HEX_64.fullmatch(stream_digest) is None:
        raise EvidenceError("page-token stream SHA-256 is invalid")
    if sha256_bytes(token_id_stream(token_ids)) != stream_digest:
        raise EvidenceError("page-token stream SHA-256 differs from the exact token IDs")
    return record


def verify_page_token_evidence(
    page_tokens: Iterable[dict[str, Any]],
    raw_tokens: Iterable[dict[str, Any]],
    *,
    suite_id: str,
    attempt_id: str,
    models: list[str],
    corpora: list[str],
    vocabulary_sizes: dict[str, int],
    selected_revisions: dict[str, list[int]],
    ledger_token_commitments: dict[tuple[str, int, str], dict[str, Any]],
) -> dict[str, Any]:
    """Bind model tokenization, frozen ledgers, and all per-token prediction IDs."""

    if not models or len(set(models)) != len(models):
        raise EvidenceError("page-token model order is invalid")
    if not corpora or len(set(corpora)) != len(corpora):
        raise EvidenceError("page-token corpus order is invalid")
    if set(vocabulary_sizes) != set(models):
        raise EvidenceError("page-token vocabulary commitments are incomplete")
    for model, vocabulary_size in vocabulary_sizes.items():
        if type(vocabulary_size) is not int or not 1 <= vocabulary_size <= 2**32:
            raise EvidenceError(f"registered vocabulary size is invalid: {model}")
    if set(selected_revisions) != set(corpora) or any(
        not isinstance(selected_revisions[corpus], list)
        or len(selected_revisions[corpus]) != PAGES_PER_CELL
        or len(set(selected_revisions[corpus])) != PAGES_PER_CELL
        or any(type(revision) is not int or revision < 1 for revision in selected_revisions[corpus])
        for corpus in corpora
    ):
        raise EvidenceError("page-token selected revision commitments are invalid")

    expected_order = [
        (model, corpus, page_index, revision)
        for model in models
        for corpus in corpora
        for page_index, revision in enumerate(selected_revisions[corpus])
    ]
    expected_ledger_keys = {
        (corpus, revision, model)
        for model, corpus, _page_index, revision in expected_order
    }
    if set(ledger_token_commitments) != expected_ledger_keys:
        raise EvidenceError("selected full-ledger token commitments are incomplete")

    records = [_validate_page_token(record) for record in page_tokens]
    observed_order = [
        (
            record["modelKey"],
            record["corpusProject"],
            record["pageSelectionIndex"],
            record["pageRevisionId"],
        )
        for record in records
    ]
    if observed_order != expected_order:
        raise EvidenceError("page-token evidence order/coverage differs from selection")

    by_page: dict[tuple[str, str, int], dict[str, Any]] = {}
    for record in records:
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise EvidenceError("page-token evidence is not bound to this suite/attempt")
        model = record["modelKey"]
        corpus = record["corpusProject"]
        page_index = record["pageSelectionIndex"]
        revision = record["pageRevisionId"]
        vocabulary_size = vocabulary_sizes.get(model)
        if vocabulary_size is None or record["vocabSize"] != vocabulary_size:
            raise EvidenceError("page-token vocabSize differs from the frozen model")
        ledger = ledger_token_commitments[(corpus, revision, model)]
        if not isinstance(ledger, dict) or set(ledger) != {
            "vocabSize",
            "first512StreamSHA256",
        }:
            raise EvidenceError("selected full-ledger token commitment fields differ")
        if ledger != {
            "vocabSize": vocabulary_size,
            "first512StreamSHA256": record["first512StreamSHA256"],
        }:
            raise EvidenceError("page-token evidence differs from the exact full ledger")
        identity = (model, corpus, page_index)
        if identity in by_page:
            raise EvidenceError("duplicate page-token evidence identity")
        by_page[identity] = record

    raw_by_page: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for candidate in raw_tokens:
        record = _validate_raw_token(candidate)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise EvidenceError("raw token is not bound to this suite/attempt")
        identity = (
            record["modelKey"],
            record["corpusProject"],
            record["pageSelectionIndex"],
        )
        if identity not in by_page:
            raise EvidenceError("raw-token evidence has no page-token binding")
        raw_by_page[identity].append(record)

    for identity, page_record in by_page.items():
        records_for_page = sorted(
            raw_by_page.get(identity, []), key=lambda item: item["predictionIndex"]
        )
        if (
            len(records_for_page) != PREDICTIONS_PER_PAGE
            or [item["predictionIndex"] for item in records_for_page]
            != list(range(PREDICTIONS_PER_PAGE))
        ):
            raise EvidenceError("raw-token coverage differs from page-token evidence")
        if any(
            item["pageRevisionId"] != page_record["pageRevisionId"]
            for item in records_for_page
        ):
            raise EvidenceError("raw/page-token revision binding differs")
        vocabulary_size = page_record["vocabSize"]
        token_ids = page_record["first512TokenIds"]
        for prediction_index, item in enumerate(records_for_page):
            for field in (
                "targetTokenId",
                "baselineTop1TokenId",
                "candidateTop1TokenId",
            ):
                if item[field] >= vocabulary_size:
                    raise EvidenceError(f"raw {field} is outside the registered vocabulary")
            expected_target = token_ids[FIRST_TARGET_TOKEN_OFFSET + prediction_index]
            if item["targetTokenId"] != expected_target:
                raise EvidenceError("raw target token differs from token positions 384..511")

    return {
        "pages": len(records),
        "tokensPerPage": PAGE_TOKENS_PER_PAGE,
        "predictionsPerPage": PREDICTIONS_PER_PAGE,
        "bindingSHA256": sha256_bytes(
            canonical_json_bytes(
                [
                    {
                        "modelKey": record["modelKey"],
                        "corpusProject": record["corpusProject"],
                        "pageRevisionId": record["pageRevisionId"],
                        "pageSelectionIndex": record["pageSelectionIndex"],
                        "vocabSize": record["vocabSize"],
                        "first512StreamSHA256": record["first512StreamSHA256"],
                    }
                    for record in records
                ]
            )
        ),
    }


def selected_ledger_token_commitments(
    ledgers: dict[str, Any],
    *,
    models: list[str],
    vocabulary_sizes: dict[str, int],
    selected_revisions: dict[str, list[int]],
) -> dict[tuple[str, int, str], dict[str, Any]]:
    """Validate every token commitment in full ledgers and select exact revisions."""

    if set(ledgers) != set(selected_revisions):
        raise EvidenceError("full ledger projects differ from selected corpora")
    if set(vocabulary_sizes) != set(models) or len(set(models)) != len(models):
        raise EvidenceError("full-ledger model vocabulary commitments are incomplete")
    selected: dict[tuple[str, int, str], dict[str, Any]] = {}
    for corpus in selected_revisions:
        records = ledgers[corpus]
        if not isinstance(records, list):
            raise EvidenceError(f"full ledger is not an array: {corpus}")
        selected_set = set(selected_revisions[corpus])
        found: set[int] = set()
        observed_revisions: set[int] = set()
        for record in records:
            if not isinstance(record, dict):
                raise EvidenceError(f"full ledger contains a non-object: {corpus}")
            revision = record.get("revid")
            if (
                record.get("project") != corpus
                or type(revision) is not int
                or revision < 1
                or revision in observed_revisions
            ):
                raise EvidenceError(f"full ledger revision identity is invalid: {corpus}")
            observed_revisions.add(revision)
            tokenizers = record.get("tokenizers")
            if not isinstance(tokenizers, dict) or list(tokenizers) != models:
                raise EvidenceError(
                    f"full ledger tokenizer order/set differs: {corpus}/{revision}"
                )
            for model in models:
                commitment = tokenizers[model]
                if not isinstance(commitment, dict) or set(commitment) != {
                    "tokenCount",
                    "vocabSize",
                    "completeStreamSHA256",
                    "first512StreamSHA256",
                }:
                    raise EvidenceError(
                        f"full ledger token commitment fields differ: {corpus}/{revision}/{model}"
                    )
                if (
                    type(commitment["tokenCount"]) is not int
                    or commitment["tokenCount"] < PAGE_TOKENS_PER_PAGE
                    or commitment["vocabSize"] != vocabulary_sizes[model]
                ):
                    raise EvidenceError(
                        f"full ledger token count/vocabSize differs: {corpus}/{revision}/{model}"
                    )
                for field in ("completeStreamSHA256", "first512StreamSHA256"):
                    if (
                        not isinstance(commitment[field], str)
                        or HEX_64.fullmatch(commitment[field]) is None
                    ):
                        raise EvidenceError(
                            f"full ledger token digest is invalid: {corpus}/{revision}/{model}"
                        )
                if revision in selected_set:
                    selected[(corpus, revision, model)] = {
                        "vocabSize": commitment["vocabSize"],
                        "first512StreamSHA256": commitment[
                            "first512StreamSHA256"
                        ],
                    }
            if revision in selected_set:
                found.add(revision)
        if found != selected_set:
            raise EvidenceError(f"selected revisions are absent from full ledger: {corpus}")
    return selected


def _safe_relative_path(value: Any) -> PurePosixPath:
    text = _require_string(value, "container relativePath")
    if "\\" in text or "\x00" in text:
        raise EvidenceError("container relativePath is not canonical POSIX syntax")
    relative = PurePosixPath(text)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise EvidenceError("container relativePath escapes the evidence root")
    if str(relative) != text or any(part in {"", "."} for part in relative.parts):
        raise EvidenceError("container relativePath is not canonical")
    return relative


def _validate_container_record(record: Any) -> dict[str, Any]:
    fields = {
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
    if not isinstance(record, dict) or set(record) != fields:
        raise EvidenceError("container evidence fields differ from the frozen schema")
    if record["schemaVersion"] != CONTAINER_SCHEMA:
        raise EvidenceError("container evidence schemaVersion differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _require_string(record[field], f"container {field}")
    _require_uint(record["pageRevisionId"], "container pageRevisionId")
    _require_uint(
        record["pageSelectionIndex"],
        "container pageSelectionIndex",
        maximum=PAGES_PER_CELL - 1,
    )
    _require_uint(record["layerIndex"], "container layerIndex", maximum=4095)
    _require_uint(record["denseBF16Bytes"], "denseBF16Bytes")
    _require_uint(record["containerBytes"], "containerBytes")
    if record["denseBF16Bytes"] <= 0 or record["containerBytes"] <= 0:
        raise EvidenceError("container byte counts must be positive")
    if not isinstance(record["containerSHA256"], str) or HEX_64.fullmatch(
        record["containerSHA256"]
    ) is None:
        raise EvidenceError("containerSHA256 is invalid")
    _safe_relative_path(record["relativePath"])
    if record["structuralReplay"] is not True:
        raise EvidenceError("every container must declare structuralReplay=true")
    return record


def _read_file_beneath(root: Path, relative: PurePosixPath, expected_bytes: int) -> bytes:
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute_root, flags)
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise EvidenceError("container parent is not a real directory")
            os.close(descriptor)
            descriptor = next_descriptor
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(relative.parts[-1], file_flags, dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_bytes:
                raise EvidenceError("container file size or type differs")
            chunks: list[bytes] = []
            remaining = expected_bytes
            while remaining:
                chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise EvidenceError("container file was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_descriptor)
            identity = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
            )
            if identity(before) != identity(after):
                raise EvidenceError("container changed while being read")
            return b"".join(chunks)
        finally:
            os.close(file_descriptor)
    except OSError as error:
        raise EvidenceError("container path contains a symlink or missing component") from error
    finally:
        os.close(descriptor)


def read_evidence_file(
    root: Path,
    relative_path: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> bytes:
    """Read a bounded regular evidence file without following any symlink."""

    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise EvidenceError("maximum evidence file size must be positive")
    relative = _safe_relative_path(relative_path)
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    try:
        metadata = absolute_root.joinpath(*relative.parts).lstat()
    except (FileNotFoundError, OSError) as error:
        raise EvidenceError(f"required evidence file is missing: {relative_path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"required evidence path is not a regular file: {relative_path}")
    if metadata.st_size > maximum_bytes or (metadata.st_size == 0 and not allow_empty):
        raise EvidenceError(f"required evidence file size is outside its bound: {relative_path}")
    return _read_file_beneath(root, relative, metadata.st_size)


def load_canonical_jsonl_beneath(
    root: Path, relative_path: str, *, maximum_bytes: int
) -> list[dict[str, Any]]:
    raw = read_evidence_file(
        root,
        relative_path,
        maximum_bytes=maximum_bytes,
    )
    return _parse_canonical_jsonl(raw, label=relative_path)


def require_manifest_paths(
    manifest: dict[str, Any], required_paths: Iterable[str]
) -> None:
    """Require every named evidence object to be byte-bound by the manifest."""

    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise EvidenceError("evidence manifest has no entry list")
    observed = {
        entry.get("path")
        for entry in manifest["entries"]
        if isinstance(entry, dict)
    }
    normalized: set[str] = set()
    for value in required_paths:
        if not isinstance(value, str):
            raise EvidenceError("required evidence manifest path is not a string")
        normalized.add(str(_safe_relative_path(value)))
    missing = sorted(normalized - observed)
    if missing:
        raise EvidenceError(
            "evidence manifest omits required paths: " + ", ".join(missing)
        )


def verify_container_bytes(
    record: dict[str, Any],
    *,
    evidence_root: Path,
    codec_root: Path,
    expected_bits: int,
) -> None:
    relative = _safe_relative_path(record["relativePath"])
    raw = _read_file_beneath(evidence_root, relative, record["containerBytes"])
    if sha256_bytes(raw) != record["containerSHA256"]:
        raise EvidenceError("container file SHA-256 differs from its evidence record")
    import sys

    codec_text = str(codec_root)
    if codec_text not in sys.path:
        sys.path.insert(0, codec_text)
    from RealLLM.voidtoken_v5 import VoidTokenV5Backend

    parsed = VoidTokenV5Backend.from_bytes(raw)
    if parsed.container != raw:
        raise EvidenceError("codec parser did not preserve canonical container bytes")
    metadata = parsed.metadata
    if metadata.get("layerIndex") != record["layerIndex"]:
        raise EvidenceError("container layerIndex differs from its evidence record")
    if metadata.get("bits") != expected_bits:
        raise EvidenceError("container bit width differs from the frozen schedule")
    if metadata.get("groupSize") != 128 or metadata.get("transformBlockSize") != 128:
        raise EvidenceError("container transform geometry differs from the frozen candidate")
    if metadata.get("codeCompression") != "zlib-9" or metadata.get("scaleCompression") != "zlib-9":
        raise EvidenceError("container compression mode differs from the frozen candidate")
    if metadata.get("signMode") != "none":
        raise EvidenceError("container sign mode differs from the frozen candidate")
    shape = metadata.get("shape")
    if (
        not isinstance(shape, list)
        or len(shape) != 2
        or any(type(value) is not int or value <= 0 for value in shape)
        or shape[0] != 383
    ):
        raise EvidenceError("container cache shape is invalid")
    dense_bytes = shape[0] * shape[1] * 2
    if dense_bytes != record["denseBF16Bytes"]:
        raise EvidenceError("dense BF16 byte accounting differs from container shape")


def evaluate_raw_evidence(
    raw_tokens: Iterable[dict[str, Any]],
    containers: Iterable[dict[str, Any]],
    *,
    suite_id: str,
    attempt_id: str,
    models: list[str],
    corpora: list[str],
    layer_counts: dict[str, int],
    bits_by_model: dict[str, list[int]],
    selected_revisions: dict[str, list[int]] | None = None,
    counts_toward_scientific_verdict: bool = False,
    evidence_root: Path | None = None,
    codec_root: Path | None = None,
) -> dict[str, Any]:
    if len(models) != MODELS_PER_SUITE or len(set(models)) != len(models):
        raise EvidenceError("the suite requires exactly three distinct models")
    if len(corpora) != CORPORA_PER_SUITE or len(set(corpora)) != len(corpora):
        raise EvidenceError("the suite requires exactly two distinct selected corpora")
    if set(layer_counts) != set(models) or set(bits_by_model) != set(models):
        raise EvidenceError("model geometry commitments are incomplete")
    if type(counts_toward_scientific_verdict) is not bool:
        raise EvidenceError("scientific-verdict flag must be an explicit boolean")
    for model in models:
        if len(bits_by_model[model]) != layer_counts[model]:
            raise EvidenceError("model bit schedule length differs from its layer count")
    if selected_revisions is not None:
        if set(selected_revisions) != set(corpora) or any(
            not isinstance(selected_revisions[corpus], list)
            or len(selected_revisions[corpus]) != PAGES_PER_CELL
            or len(set(selected_revisions[corpus])) != PAGES_PER_CELL
            or any(type(value) is not int or value < 1 for value in selected_revisions[corpus])
            for corpus in corpora
        ):
            raise EvidenceError("selected revision commitments are invalid")

    token_cells: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    identities: set[tuple[str, str, int, int]] = set()
    revision_by_page: dict[tuple[str, str, int], int] = {}
    for candidate in raw_tokens:
        record = _validate_raw_token(candidate)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise EvidenceError("raw token is not bound to this suite/attempt")
        cell = (record["modelKey"], record["corpusProject"])
        if cell[0] not in models or cell[1] not in corpora:
            raise EvidenceError("raw token belongs to an unregistered model/corpus")
        identity = (*cell, record["pageSelectionIndex"], record["predictionIndex"])
        if identity in identities:
            raise EvidenceError("duplicate raw-token evidence identity")
        identities.add(identity)
        page_identity = (*cell, record["pageSelectionIndex"])
        previous_revision = revision_by_page.setdefault(
            page_identity, record["pageRevisionId"]
        )
        if previous_revision != record["pageRevisionId"]:
            raise EvidenceError("one selected page index maps to multiple revisions")
        token_cells[cell].append(record)

    if selected_revisions is not None:
        for model in models:
            for corpus in corpora:
                for page, expected_revision in enumerate(selected_revisions[corpus]):
                    if revision_by_page.get((model, corpus, page)) != expected_revision:
                        raise EvidenceError(
                            "raw-token page revision differs from the NIST selection"
                        )

    container_cells: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    container_identities: set[tuple[str, str, int, int]] = set()
    paths: set[str] = set()
    for candidate in containers:
        record = _validate_container_record(candidate)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise EvidenceError("container is not bound to this suite/attempt")
        cell = (record["modelKey"], record["corpusProject"])
        if cell[0] not in models or cell[1] not in corpora:
            raise EvidenceError("container belongs to an unregistered model/corpus")
        maximum_layer = layer_counts[cell[0]] - 1
        if record["layerIndex"] > maximum_layer:
            raise EvidenceError("container layerIndex exceeds registered model geometry")
        identity = (*cell, record["pageSelectionIndex"], record["layerIndex"])
        if identity in container_identities:
            raise EvidenceError("duplicate container evidence identity")
        container_identities.add(identity)
        if record["relativePath"] in paths:
            raise EvidenceError("container relative paths are not unique")
        paths.add(record["relativePath"])
        page_identity = (*cell, record["pageSelectionIndex"])
        if revision_by_page.get(page_identity) != record["pageRevisionId"]:
            raise EvidenceError("container page revision differs from raw-token evidence")
        if evidence_root is not None or codec_root is not None:
            if evidence_root is None or codec_root is None:
                raise EvidenceError("container byte verification requires both roots")
            verify_container_bytes(
                record,
                evidence_root=evidence_root,
                codec_root=codec_root,
                expected_bits=bits_by_model[cell[0]][record["layerIndex"]],
            )
        container_cells[cell].append(record)

    expected_cells = {(model, corpus) for model in models for corpus in corpora}
    if set(token_cells) != expected_cells or set(container_cells) != expected_cells:
        raise EvidenceError("raw evidence does not contain exactly all six cells")

    cell_results: list[dict[str, Any]] = []
    page_metrics: dict[tuple[str, str, int], tuple[float, int]] = {}
    for model in models:
        for corpus in corpora:
            cell = (model, corpus)
            tokens = sorted(
                token_cells[cell],
                key=lambda item: (item["pageSelectionIndex"], item["predictionIndex"]),
            )
            expected_tokens = PAGES_PER_CELL * PREDICTIONS_PER_PAGE
            if len(tokens) != expected_tokens:
                raise EvidenceError("cell does not contain exactly 2,048 token records")
            expected_order = [
                (page, prediction)
                for page in range(PAGES_PER_CELL)
                for prediction in range(PREDICTIONS_PER_PAGE)
            ]
            observed_order = [
                (item["pageSelectionIndex"], item["predictionIndex"])
                for item in tokens
            ]
            if observed_order != expected_order:
                raise EvidenceError("cell raw-token order has a gap or non-canonical index")
            deltas: list[float] = []
            matches = 0
            for record in tokens:
                baseline = float32_from_bits(
                    record["baselineLossF32Bits"], "baseline loss"
                )
                candidate = float32_from_bits(
                    record["candidateLossF32Bits"], "candidate loss"
                )
                deltas.append(candidate - baseline)
                matches += int(
                    record["baselineTop1TokenId"]
                    == record["candidateTop1TokenId"]
                )
            for page in range(PAGES_PER_CELL):
                page_slice = tokens[
                    page * PREDICTIONS_PER_PAGE : (page + 1) * PREDICTIONS_PER_PAGE
                ]
                page_delta = math.fsum(
                    float32_from_bits(item["candidateLossF32Bits"], "candidate loss")
                    - float32_from_bits(item["baselineLossF32Bits"], "baseline loss")
                    for item in page_slice
                ) / PREDICTIONS_PER_PAGE
                page_matches = sum(
                    item["baselineTop1TokenId"] == item["candidateTop1TokenId"]
                    for item in page_slice
                )
                page_metrics[(model, corpus, page)] = (page_delta, page_matches)

            cell_containers = sorted(
                container_cells[cell],
                key=lambda item: (item["pageSelectionIndex"], item["layerIndex"]),
            )
            expected_containers = PAGES_PER_CELL * layer_counts[model]
            if len(cell_containers) != expected_containers:
                raise EvidenceError("cell container count differs from model geometry")
            expected_container_order = [
                (page, layer)
                for page in range(PAGES_PER_CELL)
                for layer in range(layer_counts[model])
            ]
            observed_container_order = [
                (item["pageSelectionIndex"], item["layerIndex"])
                for item in cell_containers
            ]
            if observed_container_order != expected_container_order:
                raise EvidenceError("cell container order has a gap")
            dense_bytes = sum(item["denseBF16Bytes"] for item in cell_containers)
            container_bytes = sum(item["containerBytes"] for item in cell_containers)
            compression = dense_bytes / container_bytes
            delta_nll = math.fsum(deltas) / expected_tokens
            top1 = matches / expected_tokens
            passed = compression >= 2.0 and delta_nll <= 0.01 and top1 >= 0.99
            cell_results.append(
                {
                    "modelKey": model,
                    "corpusProject": corpus,
                    "pages": PAGES_PER_CELL,
                    "predictions": expected_tokens,
                    "denseBF16Bytes": dense_bytes,
                    "containerBytes": container_bytes,
                    "compressionRatioVsBF16": compression,
                    "deltaNLLNatPerToken": delta_nll,
                    "top1ExactMatches": matches,
                    "top1Agreement": top1,
                    "structuralReplay": True,
                    "pass": passed,
                }
            )

    aggregates: list[dict[str, Any]] = []
    for model in models:
        block_deltas: list[float] = []
        block_matches: list[int] = []
        for corpus in corpora:
            for page in range(PAGES_PER_CELL):
                delta, matches = page_metrics[(model, corpus, page)]
                block_deltas.append(delta)
                block_matches.append(matches)
        aggregate = evaluate_model_aggregate(block_deltas, block_matches)
        aggregates.append({"modelKey": model, **aggregate})

    verdict = "PASS" if all(item["pass"] for item in cell_results + aggregates) else "FAIL_GATES"
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v4-independent-verification-v1",
        "suiteId": suite_id,
        "attemptId": attempt_id,
        "cells": cell_results,
        "modelAggregates": aggregates,
        "verdict": verdict,
        "countsTowardScientificVerdict": counts_toward_scientific_verdict,
    }


def build_sha256_manifest(root: Path, relatives: Iterable[str]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for text in sorted(relatives):
        relative = _safe_relative_path(text)
        if text in seen:
            raise EvidenceError("evidence manifest contains a duplicate path")
        seen.add(text)
        path = root.joinpath(*relative.parts)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError("evidence manifest path is not a regular file")
        raw = _read_file_beneath(root, relative, metadata.st_size)
        entries.append(
            {"path": text, "bytes": len(raw), "sha256": sha256_bytes(raw)}
        )
    manifest = {
        "schemaVersion": "corelm-crossmodel-livewiki-v4-evidence-manifest-v1",
        "entries": entries,
    }
    manifest["entriesSHA256"] = sha256_bytes(canonical_json_bytes(entries))
    return manifest


def verify_sha256_manifest(root: Path, manifest_path: Path) -> tuple[dict[str, Any], str]:
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    absolute_manifest = Path(os.path.abspath(os.fspath(manifest_path)))
    try:
        relative_text = absolute_manifest.relative_to(absolute_root).as_posix()
    except ValueError as error:
        raise EvidenceError("evidence manifest escapes the evidence root") from error
    raw = read_evidence_file(
        absolute_root,
        relative_text,
        maximum_bytes=16 * 1024 * 1024,
    )
    if not raw.endswith(b"\n"):
        raise EvidenceError("evidence manifest must end with LF")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("evidence manifest is invalid JSON") from error
    if canonical_json_bytes(value) + b"\n" != raw:
        raise EvidenceError("evidence manifest is not canonical JSON")
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "entries",
        "entriesSHA256",
    }:
        raise EvidenceError("evidence manifest fields differ")
    if value["schemaVersion"] != "corelm-crossmodel-livewiki-v4-evidence-manifest-v1":
        raise EvidenceError("evidence manifest schemaVersion differs")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("evidence manifest entries must be a non-empty list")
    if value["entriesSHA256"] != sha256_bytes(canonical_json_bytes(entries)):
        raise EvidenceError("evidence manifest entry-list digest differs")
    previous: str | None = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise EvidenceError("evidence manifest entry fields differ")
        relative = _safe_relative_path(entry["path"])
        if previous is not None and entry["path"] <= previous:
            raise EvidenceError("evidence manifest paths are not strictly sorted")
        previous = entry["path"]
        size = _require_uint(entry["bytes"], "manifest entry bytes")
        digest = entry["sha256"]
        if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
            raise EvidenceError("manifest entry SHA-256 is invalid")
        bytes_value = _read_file_beneath(root, relative, size)
        if sha256_bytes(bytes_value) != digest:
            raise EvidenceError("manifest entry digest mismatch")
    return value, sha256_bytes(raw)


__all__ = [
    "CONTAINER_SCHEMA",
    "EvidenceError",
    "PAGE_TOKEN_SCHEMA",
    "RAW_TOKEN_SCHEMA",
    "build_sha256_manifest",
    "canonical_json_line",
    "evaluate_raw_evidence",
    "float32_from_bits",
    "float32_to_bits",
    "load_canonical_jsonl",
    "load_canonical_jsonl_beneath",
    "read_evidence_file",
    "require_manifest_paths",
    "selected_ledger_token_commitments",
    "sha256_bytes",
    "token_id_stream",
    "verify_page_token_evidence",
    "verify_sha256_manifest",
    "verify_container_bytes",
]
