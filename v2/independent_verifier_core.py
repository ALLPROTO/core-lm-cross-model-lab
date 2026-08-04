#!/usr/bin/env python3
"""Second implementation of the blind-v2 scientific verification rules.

This module deliberately does not import the producer protocol, evidence,
worker, MediaWiki, or NIST modules.  Selection, pulse cryptography, token/page
binding, float decoding, metric aggregation, container accounting, and worker
job validation are implemented here from the frozen contract using only the
Python standard library.  Container structural replay necessarily invokes the
published VoidToken parser as the object under test; it does not reuse producer
metric or trust decisions.

The outer verifier still shares mundane input-sealing and publication checks
with the repository (canonical JSONL loading, no-follow file reads, manifests,
and release receipts).  None of those shared helpers computes a scientific
quantity or decides a gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import stat
import statistics
import struct
import sys
import types
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v2"
SELECTION_DOMAIN = b"corelm-voidtoken-crossmodel-livewiki-v2/select\0"
TARGET_UNIX_MILLISECONDS = 1787853600000
TARGET_ENDPOINT = (
    "https://beacon.nist.gov/beacon/2.0/pulse/time/1787853600000"
)
PROJECTS = ["de.wikipedia.org", "en.wikipedia.org", "fr.wikipedia.org"]
MODELS = ["gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py"]
CORPUS_START = datetime(2026, 8, 10, tzinfo=timezone.utc)
CORPUS_END = datetime(2026, 8, 24, tzinfo=timezone.utc)
SNAPSHOT_NOT_BEFORE = datetime(2026, 8, 25, 6, tzinfo=timezone.utc)
SNAPSHOT_DEADLINE = datetime(2026, 8, 26, 18, tzinfo=timezone.utc)

RAW_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v2-raw-token-evidence-v1"
CONTAINER_SCHEMA = "corelm-crossmodel-livewiki-v2-container-evidence-v1"
PAGE_TOKEN_SCHEMA = "corelm-crossmodel-livewiki-v2-page-token-evidence-v1"
TRUST_SCHEMA = "corelm-crossmodel-livewiki-v2-nist-trust-bundle-v1"
NIST_VERIFY_SCHEMA = "corelm-crossmodel-livewiki-v2-nist-verification-v1"
SELECTION_SCHEMA = "corelm-crossmodel-livewiki-v2-selection-v1"
INDEPENDENT_RESULT_SCHEMA = (
    "corelm-crossmodel-livewiki-v2-independent-verification-v1"
)
WORKER_JOB_SCHEMA = "corelm-crossmodel-livewiki-v2-worker-job-v1"
REGISTERED_PULSE_VERSION = "2.0"
REGISTERED_PULSE_CIPHER_SUITE = 0
REGISTERED_PULSE_PERIOD_MILLISECONDS = 60000
HISTORICAL_FIXTURE_PULSE_VERSION = "Version 2.0"
REGISTERED_NIST_TRUST_ROOT_DER_SHA256 = (
    "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
)

PAGES_PER_CELL = 16
PREDICTIONS_PER_PAGE = 128
PAGE_TOKENS_PER_PAGE = 512
FIRST_TARGET_TOKEN_OFFSET = 384
MODEL_AGGREGATE_T = 1.6955187825458675
MODEL_AGGREGATE_Z = 1.6448536269514715

HEX8_LOWER = re.compile(r"[0-9a-f]{8}\Z")
SHA256_LOWER = re.compile(r"[0-9a-f]{64}\Z")
HEX64_BYTES = re.compile(r"[0-9a-fA-F]{128}\Z")
HEX_SIGNATURE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
UTC_MILLISECONDS = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z"
)


class IndependentVerificationError(ValueError):
    """The second implementation cannot establish the claimed condition."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise IndependentVerificationError("value is not canonicalizable JSON") from error


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise IndependentVerificationError(f"non-finite JSON number: {value}")


def _parse_finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise IndependentVerificationError("non-finite JSON number")
    return result


def _check_unicode(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise IndependentVerificationError(f"lone surrogate at {path}")
        value.encode("utf-8", errors="strict")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_unicode(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_unicode(key, f"{path}.<key>")
            _check_unicode(item, f"{path}.{key}")


def load_json_strict_bytes(raw: bytes, *, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
        _check_unicode(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndependentVerificationError(f"invalid strict JSON: {label}") from error


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def decode_float32_bits(value: Any, *, label: str) -> float:
    if not isinstance(value, str) or HEX8_LOWER.fullmatch(value) is None:
        raise IndependentVerificationError(
            f"{label} must be eight lowercase hexadecimal digits"
        )
    numeric = struct.unpack(">f", bytes.fromhex(value))[0]
    if not math.isfinite(numeric):
        raise IndependentVerificationError(f"{label} is non-finite")
    return float(numeric)


def encode_token_id_stream(token_ids: Iterable[int]) -> bytes:
    values = list(token_ids)
    if any(type(value) is not int or not 0 <= value < 2**32 for value in values):
        raise IndependentVerificationError("token ID stream is outside uint32")
    return struct.pack("<Q", len(values)) + b"".join(
        struct.pack("<I", value) for value in values
    )


def _uint(value: Any, label: str, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise IndependentVerificationError(f"{label} is outside its integer domain")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentVerificationError(f"{label} is not a non-empty string")
    value.encode("utf-8", errors="strict")
    return value


def _portable_relative(value: Any, label: str) -> PurePosixPath:
    text = _text(value, label)
    if "\\" in text or "\x00" in text:
        raise IndependentVerificationError(f"{label} is not canonical POSIX syntax")
    relative = PurePosixPath(text)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or str(relative) != text
    ):
        raise IndependentVerificationError(f"{label} escapes its root")
    return relative


def _utc_seconds(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECONDS.fullmatch(value) is None:
        raise IndependentVerificationError(f"{label} is not whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise IndependentVerificationError(f"{label} is not a real timestamp") from error


def _validate_snapshot(snapshot: Any, *, allow_fixture: bool) -> bool:
    if not isinstance(snapshot, dict):
        raise IndependentVerificationError("snapshot registration is not an object")
    if snapshot.get("schemaVersion") == "corelm-crossmodel-livewiki-v2-snapshot-fixture-v1":
        expected = {
            "schemaVersion": "corelm-crossmodel-livewiki-v2-snapshot-fixture-v1",
            "fixtureOnly": True,
            "purpose": "known-answer protocol control; contains no model or corpus evidence",
        }
        if not allow_fixture or snapshot != expected:
            raise IndependentVerificationError("snapshot fixture is forbidden or malformed")
        return True
    fields = {
        "schemaVersion", "suiteId", "status", "designPublicationReceiptSHA256",
        "snapshotReleasePlan", "projects", "models", "ledgers",
        "modelAssetSourceManifestSHA256", "fullAssetReceiptSHA256",
        "corpusManifestSHA256", "createdAt",
    }
    if set(snapshot) != fields:
        raise IndependentVerificationError("snapshot registration fields differ")
    if snapshot["schemaVersion"] != "corelm-crossmodel-livewiki-v2-snapshot-registration-v1":
        raise IndependentVerificationError("snapshot registration schema differs")
    if snapshot["suiteId"] != SUITE_ID:
        raise IndependentVerificationError("snapshot suite differs")
    if snapshot["status"] != "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION":
        raise IndependentVerificationError("snapshot is not frozen for publication")
    if snapshot["projects"] != PROJECTS or snapshot["models"] != MODELS:
        raise IndependentVerificationError("snapshot project/model order differs")
    if snapshot["snapshotReleasePlan"] != {
        "tag": "corelm-crossmodel-livewiki-v2-snapshot",
        "publishNoLaterThan": "2026-08-26T18:00:00Z",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
    }:
        raise IndependentVerificationError("snapshot release plan differs")
    created = _utc_seconds(snapshot["createdAt"], "snapshot createdAt")
    if not SNAPSHOT_NOT_BEFORE <= created <= SNAPSHOT_DEADLINE:
        raise IndependentVerificationError("snapshot creation time is outside its window")
    ledgers = snapshot["ledgers"]
    if not isinstance(ledgers, dict) or set(ledgers) != set(PROJECTS):
        raise IndependentVerificationError("snapshot ledger set differs")
    digests = [
        snapshot["designPublicationReceiptSHA256"],
        snapshot["modelAssetSourceManifestSHA256"],
        snapshot["fullAssetReceiptSHA256"], snapshot["corpusManifestSHA256"],
        *ledgers.values(),
    ]
    if any(not isinstance(item, str) or SHA256_LOWER.fullmatch(item) is None for item in digests):
        raise IndependentVerificationError("snapshot digest is invalid")
    return False


def _validate_ledger(
    project: str,
    value: Any,
    *,
    minimum: int,
    start: datetime | None,
    end: datetime | None,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < minimum:
        raise IndependentVerificationError(f"ledger is too short: {project}")
    result: list[dict[str, Any]] = []
    revisions: set[int] = set()
    pages: set[int] = set()
    previous: tuple[str, int] | None = None
    for item in value:
        if not isinstance(item, dict):
            raise IndependentVerificationError(f"ledger has non-object: {project}")
        timestamp, pageid, revid = item.get("timestamp"), item.get("pageid"), item.get("revid")
        parsed = _utc_seconds(timestamp, f"ledger timestamp {project}")
        if start is not None and parsed < start or end is not None and parsed >= end:
            raise IndependentVerificationError(f"ledger timestamp outside window: {project}")
        if type(pageid) is not int or pageid < 1 or type(revid) is not int or revid < 1:
            raise IndependentVerificationError(f"ledger identity invalid: {project}")
        identity = (timestamp, revid)
        if revid in revisions or pageid in pages or (previous is not None and identity <= previous):
            raise IndependentVerificationError(f"ledger is duplicate/unsorted: {project}")
        revisions.add(revid)
        pages.add(pageid)
        previous = identity
        result.append({"project": project, "timestamp": timestamp, "pageid": pageid, "revid": revid})
    return result


def _draw(
    snapshot_bytes: bytes,
    output: bytes,
    draw_index: int,
    population: int,
) -> dict[str, int | str]:
    if not snapshot_bytes or len(output) != 64 or population < 1:
        raise IndependentVerificationError("selection draw inputs are invalid")
    if type(draw_index) is not int or not 0 <= draw_index < 2**64:
        raise IndependentVerificationError("selection draw index is invalid")
    limit = 2**512 - (2**512 % population)
    counter = 0
    while counter < 2**64:
        digest = hashlib.sha512(
            SELECTION_DOMAIN
            + len(snapshot_bytes).to_bytes(8, "big")
            + snapshot_bytes
            + output
            + draw_index.to_bytes(8, "big")
            + counter.to_bytes(8, "big")
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate < limit:
            return {
                "counter": counter,
                "digestSHA512": digest.hex(),
                "populationSizeBefore": population,
                "selectedPosition": candidate % population,
            }
        counter += 1
    raise IndependentVerificationError("selection rejection loop exhausted uint64")


def derive_selection(
    snapshot_registration_bytes: bytes,
    output_value_hex: str,
    *,
    projects: Iterable[str],
    models: Iterable[str],
    ledgers: dict[str, bytes | Any],
    allow_known_answer_fixture: bool = False,
) -> dict[str, Any]:
    """Derive the sample without calling the producer protocol implementation."""

    snapshot = load_json_strict_bytes(snapshot_registration_bytes, label="snapshot registration")
    fixture = _validate_snapshot(snapshot, allow_fixture=allow_known_answer_fixture)
    if not isinstance(output_value_hex, str) or HEX64_BYTES.fullmatch(output_value_hex) is None:
        raise IndependentVerificationError("NIST outputValue is not 64 bytes")
    output = bytes.fromhex(output_value_hex)
    project_pool = list(projects)
    model_pool = list(models)
    for pool, label in ((project_pool, "projects"), (model_pool, "models")):
        if len(pool) != 3 or len(set(pool)) != 3 or any(not isinstance(x, str) or not x for x in pool):
            raise IndependentVerificationError(f"{label} must be three unique strings")
    if not fixture and (project_pool != snapshot["projects"] or model_pool != snapshot["models"]):
        raise IndependentVerificationError("selection caller differs from snapshot")
    if set(ledgers) != set(project_pool):
        raise IndependentVerificationError("selection ledger projects differ")
    checked: dict[str, list[dict[str, Any]]] = {}
    for project in project_pool:
        source = ledgers[project]
        if fixture:
            parsed, minimum, start, end = source, 16, None, None
        else:
            if not isinstance(source, bytes):
                raise IndependentVerificationError("normative ledger must be exact bytes")
            if sha256_bytes(source) != snapshot["ledgers"][project]:
                raise IndependentVerificationError(f"ledger digest differs: {project}")
            parsed = load_json_strict_bytes(source, label=f"ledger {project}")
            minimum, start, end = 64, CORPUS_START, CORPUS_END
        checked[project] = _validate_ledger(project, parsed, minimum=minimum, start=start, end=end)

    draws: list[dict[str, Any]] = []

    def take(pool: list[Any], index: int, kind: str) -> Any:
        draw = _draw(snapshot_registration_bytes, output, index, len(pool))
        selected = pool.pop(int(draw["selectedPosition"]))
        draws.append({"drawIndex": index, **draw, "kind": kind, "selected": selected})
        return selected

    corpus_a = take(project_pool, 0, "corpus")
    corpus_b = take(project_pool, 1, "corpus")
    selected_pages: dict[str, list[dict[str, Any]]] = {}
    index = 2
    for project in (corpus_a, corpus_b):
        pool = checked[project].copy()
        selected_pages[project] = []
        for _ in range(PAGES_PER_CELL):
            selected_pages[project].append(take(pool, index, "page"))
            index += 1
    execution_order = [take(model_pool, index, "model")]
    index += 1
    execution_order.append(take(model_pool, index, "model"))
    execution_order.extend(model_pool)
    return {
        "schemaVersion": SELECTION_SCHEMA,
        "suiteId": SUITE_ID,
        "snapshotRegistrationSHA256": sha256_bytes(snapshot_registration_bytes),
        "nistOutputValue": output.hex().upper(),
        "selectedCorpora": [corpus_a, corpus_b],
        "selectedPages": selected_pages,
        "modelExecutionOrder": execution_order,
        "draws": draws,
    }


def validate_worker_job(job: Any) -> None:
    fields = {
        "schemaVersion", "suiteId", "attemptId", "countsTowardScientificVerdict",
        "model", "selectedCorpora", "pages", "candidate", "seed",
    }
    if not isinstance(job, dict) or set(job) != fields:
        raise IndependentVerificationError("worker job fields differ")
    if job["schemaVersion"] != WORKER_JOB_SCHEMA or job["suiteId"] != SUITE_ID:
        raise IndependentVerificationError("worker job schema/suite differs")
    if job["countsTowardScientificVerdict"] is not True:
        raise IndependentVerificationError("worker job is not scientific")
    if not isinstance(job["attemptId"], str) or ATTEMPT_ID.fullmatch(job["attemptId"]) is None:
        raise IndependentVerificationError("worker attemptId is invalid")
    model = job["model"]
    if not isinstance(model, dict) or set(model) != {
        "key", "files", "layers", "vocabSize", "candidateBitsByLayer"
    }:
        raise IndependentVerificationError("worker model binding differs")
    _text(model["key"], "worker model key")
    _uint(model["vocabSize"], "worker vocabSize", 2**32)
    if model["vocabSize"] < 1:
        raise IndependentVerificationError("worker vocabSize must be positive")
    required_files = {
        "config.json", "generation_config.json", "merges.txt", "model.safetensors",
        "special_tokens_map.json", "tokenizer.json", "tokenizer_config.json", "vocab.json",
    }
    if not isinstance(model["files"], dict) or set(model["files"]) != required_files:
        raise IndependentVerificationError("worker model asset set differs")
    for name, receipt in model["files"].items():
        if not isinstance(receipt, dict) or set(receipt) != {"path", "bytes", "sha256"}:
            raise IndependentVerificationError(f"worker asset receipt differs: {name}")
        _portable_relative(receipt["path"], f"worker asset {name}")
        if type(receipt["bytes"]) is not int or not 1 <= receipt["bytes"] <= 2**31:
            raise IndependentVerificationError(f"worker asset bytes invalid: {name}")
        if not isinstance(receipt["sha256"], str) or SHA256_LOWER.fullmatch(receipt["sha256"]) is None:
            raise IndependentVerificationError(f"worker asset digest invalid: {name}")
    layers = model["layers"]
    schedule = model["candidateBitsByLayer"]
    if type(layers) is not int or layers < 3 or not isinstance(schedule, list) or len(schedule) != layers:
        raise IndependentVerificationError("worker layer schedule shape differs")
    if any(type(bits) is not int or bits not in {8, 9} for bits in schedule):
        raise IndependentVerificationError("worker layer schedule value differs")
    if job["candidate"] != {
        "backend": "voidtoken-v5", "groupSize": 128, "transformBlockSize": 128,
        "codeCompression": "zlib-9", "scaleCompression": "zlib-9", "signMode": "none",
    }:
        raise IndependentVerificationError("worker candidate differs")
    corpora, pages = job["selectedCorpora"], job["pages"]
    if not isinstance(corpora, list) or len(corpora) != 2 or len(set(corpora)) != 2:
        raise IndependentVerificationError("worker corpora differ")
    if not isinstance(pages, dict) or set(pages) != set(corpora):
        raise IndependentVerificationError("worker page set differs")
    for corpus in corpora:
        records = pages[corpus]
        if not isinstance(records, list) or len(records) != PAGES_PER_CELL:
            raise IndependentVerificationError("worker page count differs")
        revisions: set[int] = set()
        for index, page in enumerate(records):
            if not isinstance(page, dict) or set(page) != {
                "pageSelectionIndex", "pageRevisionId", "recordPath", "recordBytes", "recordSHA256"
            }:
                raise IndependentVerificationError("worker page binding fields differ")
            if page["pageSelectionIndex"] != index:
                raise IndependentVerificationError("worker page order differs")
            revid = page["pageRevisionId"]
            if type(revid) is not int or revid < 1 or revid in revisions:
                raise IndependentVerificationError("worker page revision differs")
            revisions.add(revid)
            _portable_relative(page["recordPath"], "worker corpus record")
            if type(page["recordBytes"]) is not int or not 1 <= page["recordBytes"] <= 128 * 1024 * 1024:
                raise IndependentVerificationError("worker record bytes invalid")
            if not isinstance(page["recordSHA256"], str) or SHA256_LOWER.fullmatch(page["recordSHA256"]) is None:
                raise IndependentVerificationError("worker record digest invalid")
    if type(job["seed"]) is not int or not 0 <= job["seed"] < 2**32:
        raise IndependentVerificationError("worker seed is outside uint32")


def _validate_raw_token(record: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion", "suiteId", "attemptId", "modelKey", "corpusProject",
        "pageRevisionId", "pageSelectionIndex", "predictionIndex", "targetTokenId",
        "baselineLossF32Bits", "candidateLossF32Bits", "baselineTop1TokenId",
        "candidateTop1TokenId",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise IndependentVerificationError("raw-token fields differ")
    if record["schemaVersion"] != RAW_TOKEN_SCHEMA:
        raise IndependentVerificationError("raw-token schema differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _text(record[field], f"raw token {field}")
    _uint(record["pageRevisionId"], "raw pageRevisionId")
    _uint(record["pageSelectionIndex"], "raw pageSelectionIndex", 15)
    _uint(record["predictionIndex"], "raw predictionIndex", 127)
    for field in ("targetTokenId", "baselineTop1TokenId", "candidateTop1TokenId"):
        _uint(record[field], f"raw {field}", 2**32 - 1)
    baseline = decode_float32_bits(record["baselineLossF32Bits"], label="baseline loss")
    candidate = decode_float32_bits(record["candidateLossF32Bits"], label="candidate loss")
    if baseline < 0 or candidate < 0:
        raise IndependentVerificationError("negative log-likelihood is negative")
    return record


def _validate_page_token(record: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion", "suiteId", "attemptId", "modelKey", "corpusProject",
        "pageRevisionId", "pageSelectionIndex", "vocabSize", "first512TokenIds",
        "first512StreamSHA256",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise IndependentVerificationError("page-token fields differ")
    if record["schemaVersion"] != PAGE_TOKEN_SCHEMA:
        raise IndependentVerificationError("page-token schema differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _text(record[field], f"page token {field}")
    _uint(record["pageRevisionId"], "page token revision")
    _uint(record["pageSelectionIndex"], "page token index", 15)
    vocab = _uint(record["vocabSize"], "page token vocabSize", 2**32)
    if vocab < 1:
        raise IndependentVerificationError("page token vocabSize is zero")
    token_ids = record["first512TokenIds"]
    if not isinstance(token_ids, list) or len(token_ids) != PAGE_TOKENS_PER_PAGE:
        raise IndependentVerificationError("page-token stream is not 512 IDs")
    for token_id in token_ids:
        _uint(token_id, "page token ID", 2**32 - 1)
        if token_id >= vocab:
            raise IndependentVerificationError("page token ID exceeds vocabulary")
    digest = record["first512StreamSHA256"]
    if not isinstance(digest, str) or SHA256_LOWER.fullmatch(digest) is None:
        raise IndependentVerificationError("page-token digest is invalid")
    if sha256_bytes(encode_token_id_stream(token_ids)) != digest:
        raise IndependentVerificationError("page-token digest does not bind exact IDs")
    return record


def extract_ledger_token_commitments(
    ledgers: dict[str, Any],
    *,
    models: list[str],
    vocabulary_sizes: dict[str, int],
    selected_revisions: dict[str, list[int]],
) -> dict[tuple[str, int, str], dict[str, Any]]:
    if set(ledgers) != set(selected_revisions):
        raise IndependentVerificationError("full-ledger project set differs")
    if set(vocabulary_sizes) != set(models) or len(models) != len(set(models)):
        raise IndependentVerificationError("full-ledger model commitments differ")
    selected: dict[tuple[str, int, str], dict[str, Any]] = {}
    for project, wanted in selected_revisions.items():
        records = ledgers[project]
        if not isinstance(records, list):
            raise IndependentVerificationError(f"full ledger is not an array: {project}")
        wanted_set = set(wanted)
        found: set[int] = set()
        observed: set[int] = set()
        for record in records:
            if not isinstance(record, dict):
                raise IndependentVerificationError("full ledger has non-object")
            revision = record.get("revid")
            if record.get("project") != project or type(revision) is not int or revision < 1 or revision in observed:
                raise IndependentVerificationError("full ledger revision identity differs")
            observed.add(revision)
            tokenizers = record.get("tokenizers")
            if not isinstance(tokenizers, dict) or list(tokenizers) != models:
                raise IndependentVerificationError("full ledger tokenizer order differs")
            for model in models:
                commitment = tokenizers[model]
                if not isinstance(commitment, dict) or set(commitment) != {
                    "tokenCount", "vocabSize", "completeStreamSHA256", "first512StreamSHA256"
                }:
                    raise IndependentVerificationError("full ledger token fields differ")
                if type(commitment["tokenCount"]) is not int or commitment["tokenCount"] < 512:
                    raise IndependentVerificationError("full ledger token count differs")
                if commitment["vocabSize"] != vocabulary_sizes[model]:
                    raise IndependentVerificationError("full ledger vocabulary differs")
                if any(
                    not isinstance(commitment[field], str)
                    or SHA256_LOWER.fullmatch(commitment[field]) is None
                    for field in ("completeStreamSHA256", "first512StreamSHA256")
                ):
                    raise IndependentVerificationError("full ledger token digest differs")
                if revision in wanted_set:
                    selected[(project, revision, model)] = {
                        "vocabSize": commitment["vocabSize"],
                        "first512StreamSHA256": commitment["first512StreamSHA256"],
                    }
            if revision in wanted_set:
                found.add(revision)
        if found != wanted_set:
            raise IndependentVerificationError(f"selected revisions absent: {project}")
    return selected


def verify_page_token_bindings(
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
    if not models or len(models) != len(set(models)) or not corpora or len(corpora) != len(set(corpora)):
        raise IndependentVerificationError("page-token model/corpus order differs")
    if set(vocabulary_sizes) != set(models):
        raise IndependentVerificationError("page-token vocabulary commitments differ")
    if any(
        type(vocabulary_sizes[model]) is not int
        or not 1 <= vocabulary_sizes[model] <= 2**32
        for model in models
    ):
        raise IndependentVerificationError("page-token vocabulary size is invalid")
    if set(selected_revisions) != set(corpora) or any(
        not isinstance(selected_revisions[corpus], list)
        or len(selected_revisions[corpus]) != 16
        or len(set(selected_revisions[corpus])) != 16
        or any(type(value) is not int or value < 1 for value in selected_revisions[corpus])
        for corpus in corpora
    ):
        raise IndependentVerificationError("page-token revision commitments differ")
    expected_order = [
        (model, corpus, index, revision)
        for model in models
        for corpus in corpora
        for index, revision in enumerate(selected_revisions[corpus])
    ]
    if set(ledger_token_commitments) != {
        (corpus, revision, model)
        for model, corpus, _index, revision in expected_order
    }:
        raise IndependentVerificationError("ledger token commitments are incomplete")
    records = [_validate_page_token(item) for item in page_tokens]
    observed = [
        (item["modelKey"], item["corpusProject"], item["pageSelectionIndex"], item["pageRevisionId"])
        for item in records
    ]
    if observed != expected_order:
        raise IndependentVerificationError("page-token order/coverage differs")
    by_page: dict[tuple[str, str, int], dict[str, Any]] = {}
    for item in records:
        if item["suiteId"] != suite_id or item["attemptId"] != attempt_id:
            raise IndependentVerificationError("page token has wrong suite/attempt")
        identity = (item["modelKey"], item["corpusProject"], item["pageSelectionIndex"])
        vocab = vocabulary_sizes.get(item["modelKey"])
        if vocab != item["vocabSize"]:
            raise IndependentVerificationError("page token vocabulary differs")
        ledger = ledger_token_commitments[(item["corpusProject"], item["pageRevisionId"], item["modelKey"])]
        if ledger != {
            "vocabSize": vocab,
            "first512StreamSHA256": item["first512StreamSHA256"],
        }:
            raise IndependentVerificationError("page tokens differ from full ledger")
        if identity in by_page:
            raise IndependentVerificationError("duplicate page-token identity")
        by_page[identity] = item
    raw_by_page: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for item in raw_tokens:
        record = _validate_raw_token(item)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise IndependentVerificationError("raw token has wrong suite/attempt")
        identity = (record["modelKey"], record["corpusProject"], record["pageSelectionIndex"])
        if identity not in by_page:
            raise IndependentVerificationError("raw token lacks page binding")
        raw_by_page[identity].append(record)
    for identity, page in by_page.items():
        raw = sorted(raw_by_page.get(identity, []), key=lambda item: item["predictionIndex"])
        if len(raw) != 128 or [item["predictionIndex"] for item in raw] != list(range(128)):
            raise IndependentVerificationError("raw-token page coverage differs")
        if any(item["pageRevisionId"] != page["pageRevisionId"] for item in raw):
            raise IndependentVerificationError("raw/page revision differs")
        for index, item in enumerate(raw):
            if any(item[field] >= page["vocabSize"] for field in (
                "targetTokenId", "baselineTop1TokenId", "candidateTop1TokenId"
            )):
                raise IndependentVerificationError("raw token ID exceeds vocabulary")
            if item["targetTokenId"] != page["first512TokenIds"][384 + index]:
                raise IndependentVerificationError("raw target differs from positions 384..511")
    binding = [
        {
            "modelKey": item["modelKey"], "corpusProject": item["corpusProject"],
            "pageRevisionId": item["pageRevisionId"], "pageSelectionIndex": item["pageSelectionIndex"],
            "vocabSize": item["vocabSize"], "first512StreamSHA256": item["first512StreamSHA256"],
        }
        for item in records
    ]
    return {
        "pages": len(records), "tokensPerPage": 512, "predictionsPerPage": 128,
        "bindingSHA256": sha256_bytes(canonical_json_bytes(binding)),
    }


def _validate_container(record: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion", "suiteId", "attemptId", "modelKey", "corpusProject",
        "pageRevisionId", "pageSelectionIndex", "layerIndex", "denseBF16Bytes",
        "containerBytes", "containerSHA256", "relativePath", "structuralReplay",
    }
    if not isinstance(record, dict) or set(record) != fields:
        raise IndependentVerificationError("container fields differ")
    if record["schemaVersion"] != CONTAINER_SCHEMA:
        raise IndependentVerificationError("container schema differs")
    for field in ("suiteId", "attemptId", "modelKey", "corpusProject"):
        _text(record[field], f"container {field}")
    _uint(record["pageRevisionId"], "container revision")
    _uint(record["pageSelectionIndex"], "container page index", 15)
    _uint(record["layerIndex"], "container layer", 4095)
    _uint(record["denseBF16Bytes"], "dense bytes")
    _uint(record["containerBytes"], "container bytes")
    if record["denseBF16Bytes"] < 1 or record["containerBytes"] < 1:
        raise IndependentVerificationError("container byte count is zero")
    if not isinstance(record["containerSHA256"], str) or SHA256_LOWER.fullmatch(record["containerSHA256"]) is None:
        raise IndependentVerificationError("container SHA-256 differs")
    _portable_relative(record["relativePath"], "container path")
    if record["structuralReplay"] is not True:
        raise IndependentVerificationError("container structural replay is false")
    return record


def _read_beneath(root: Path, relative: str, expected_size: int) -> bytes:
    path = _portable_relative(relative, "evidence path")
    root_abs = Path(os.path.abspath(os.fspath(root)))
    root_meta = os.lstat(root_abs)
    if stat.S_ISLNK(root_meta.st_mode) or not stat.S_ISDIR(root_meta.st_mode):
        raise IndependentVerificationError("evidence root is not a real directory")
    current = root_abs
    for part in path.parts:
        current = current / part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise IndependentVerificationError("evidence path contains symlink")
    metadata = os.lstat(current)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
        raise IndependentVerificationError("evidence file type/size differs")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(current, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
            raise IndependentVerificationError("opened evidence file changed")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise IndependentVerificationError("evidence file truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise IndependentVerificationError("evidence file grew during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_container_binary(
    record: dict[str, Any],
    *,
    evidence_root: Path,
    codec_root: Path,
    expected_bits: int,
) -> None:
    raw = _read_beneath(evidence_root, record["relativePath"], record["containerBytes"])
    if sha256_bytes(raw) != record["containerSHA256"]:
        raise IndependentVerificationError("container bytes do not match SHA-256")
    parsed = _parse_with_bound_codec(raw, codec_root)
    if parsed.container != raw:
        raise IndependentVerificationError("codec did not preserve canonical bytes")
    metadata = parsed.metadata
    if metadata.get("layerIndex") != record["layerIndex"] or metadata.get("bits") != expected_bits:
        raise IndependentVerificationError("container layer/bits differ")
    if metadata.get("groupSize") != 128 or metadata.get("transformBlockSize") != 128:
        raise IndependentVerificationError("container transform geometry differs")
    if metadata.get("codeCompression") != "zlib-9" or metadata.get("scaleCompression") != "zlib-9":
        raise IndependentVerificationError("container compression mode differs")
    if metadata.get("signMode") != "none":
        raise IndependentVerificationError("container sign mode differs")
    shape = metadata.get("shape")
    if not isinstance(shape, list) or len(shape) != 2 or any(type(x) is not int or x <= 0 for x in shape) or shape[0] != 383:
        raise IndependentVerificationError("container cache shape differs")
    if shape[0] * shape[1] * 2 != record["denseBF16Bytes"]:
        raise IndependentVerificationError("container dense-byte accounting differs")


def _codec_source_bytes(root: Path, relative: str) -> tuple[bytes, str]:
    canonical_root = Path(os.path.abspath(os.fspath(root)))
    relative_path = _portable_relative(relative, "codec module path")
    candidate = canonical_root.joinpath(*relative_path.parts)
    try:
        metadata = os.lstat(candidate)
    except OSError as error:
        raise IndependentVerificationError(f"codec module is absent: {relative}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 1 <= metadata.st_size <= 4 * 1024 * 1024
    ):
        raise IndependentVerificationError(f"codec module type/size differs: {relative}")
    return (
        _read_beneath(canonical_root, relative, metadata.st_size),
        os.fspath(candidate),
    )


def _parse_with_bound_codec(raw: bytes, codec_root: Path) -> Any:
    """Execute the two exact codec files, immune to ``sys.modules`` shadowing."""

    codecs_raw, codecs_filename = _codec_source_bytes(
        codec_root, "RealLLM/codecs.py"
    )
    voidtoken_raw, voidtoken_filename = _codec_source_bytes(
        codec_root, "RealLLM/voidtoken_v5.py"
    )
    prior = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "RealLLM" or name.startswith("RealLLM.")
    }
    for name in tuple(prior):
        del sys.modules[name]
    package = types.ModuleType("RealLLM")
    package.__file__ = os.fspath(Path(codec_root) / "RealLLM" / "__init__.py")
    package.__package__ = "RealLLM"
    package.__path__ = [os.fspath(Path(codec_root) / "RealLLM")]
    codecs_module = types.ModuleType("RealLLM.codecs")
    codecs_module.__file__ = codecs_filename
    codecs_module.__package__ = "RealLLM"
    voidtoken_module = types.ModuleType("RealLLM.voidtoken_v5")
    voidtoken_module.__file__ = voidtoken_filename
    voidtoken_module.__package__ = "RealLLM"
    try:
        sys.modules["RealLLM"] = package
        sys.modules["RealLLM.codecs"] = codecs_module
        exec(
            compile(codecs_raw, codecs_filename, "exec", dont_inherit=True),
            codecs_module.__dict__,
        )
        setattr(package, "codecs", codecs_module)
        sys.modules["RealLLM.voidtoken_v5"] = voidtoken_module
        exec(
            compile(voidtoken_raw, voidtoken_filename, "exec", dont_inherit=True),
            voidtoken_module.__dict__,
        )
        backend = voidtoken_module.__dict__.get("VoidTokenV5Backend")
        if backend is None or not callable(getattr(backend, "from_bytes", None)):
            raise IndependentVerificationError("bound codec backend is absent")
        return backend.from_bytes(raw)
    except IndependentVerificationError:
        raise
    except Exception as error:
        raise IndependentVerificationError(
            f"bound codec rejected container: {type(error).__name__}: {error}"
        ) from error
    finally:
        for name in tuple(sys.modules):
            if name == "RealLLM" or name.startswith("RealLLM."):
                del sys.modules[name]
        sys.modules.update(prior)


def _model_aggregate(deltas: list[float], matches: list[int]) -> dict[str, Any]:
    if len(deltas) != 32 or len(matches) != 32:
        raise IndependentVerificationError("aggregate requires 32 page blocks")
    if any(type(x) not in {int, float} or not math.isfinite(x) for x in deltas):
        raise IndependentVerificationError("aggregate delta is invalid")
    if any(type(x) is not int or not 0 <= x <= 128 for x in matches):
        raise IndependentVerificationError("aggregate match count is invalid")
    proportions = [value / 128 for value in matches]
    delta_upper = statistics.fmean(deltas) + MODEL_AGGREGATE_T * statistics.stdev(deltas) / math.sqrt(32)
    top1_lower = statistics.fmean(proportions) - MODEL_AGGREGATE_T * statistics.stdev(proportions) / math.sqrt(32)
    total = sum(matches)
    trials = 4096
    p = total / trials
    z = MODEL_AGGREGATE_Z
    wilson = (
        p + z * z / (2 * trials)
        - z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    ) / (1 + z * z / trials)
    passed = delta_upper <= 0.01 and top1_lower >= 0.99 and wilson >= 0.99
    return {
        "blocks": 32, "predictions": trials, "totalExactMatches": total,
        "deltaUpper": delta_upper, "top1Lower": top1_lower,
        "wilsonLower": wilson, "pass": passed,
    }


def evaluate_evidence(
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
    if len(models) != 3 or len(set(models)) != 3 or len(corpora) != 2 or len(set(corpora)) != 2:
        raise IndependentVerificationError("suite requires 3 models and 2 corpora")
    if set(layer_counts) != set(models) or set(bits_by_model) != set(models):
        raise IndependentVerificationError("model geometry is incomplete")
    if type(counts_toward_scientific_verdict) is not bool:
        raise IndependentVerificationError("scientific flag is not boolean")
    if evidence_root is None or codec_root is None:
        raise IndependentVerificationError(
            "independent evidence evaluation requires byte-level container replay"
        )
    if any(
        type(layer_counts[model]) is not int
        or layer_counts[model] < 1
        or len(bits_by_model[model]) != layer_counts[model]
        or any(type(bits) is not int or bits not in {8, 9} for bits in bits_by_model[model])
        for model in models
    ):
        raise IndependentVerificationError("model bit schedule differs")
    if selected_revisions is not None and (
        set(selected_revisions) != set(corpora)
        or any(
            not isinstance(selected_revisions[corpus], list)
            or len(selected_revisions[corpus]) != 16
            or len(set(selected_revisions[corpus])) != 16
            or any(type(value) is not int or value < 1 for value in selected_revisions[corpus])
            for corpus in corpora
        )
    ):
        raise IndependentVerificationError("selected revisions differ")

    token_cells: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    token_ids: set[tuple[str, str, int, int]] = set()
    revisions: dict[tuple[str, str, int], int] = {}
    for item in raw_tokens:
        record = _validate_raw_token(item)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise IndependentVerificationError("raw token suite/attempt differs")
        cell = (record["modelKey"], record["corpusProject"])
        if cell[0] not in models or cell[1] not in corpora:
            raise IndependentVerificationError("raw token cell is unregistered")
        identity = (*cell, record["pageSelectionIndex"], record["predictionIndex"])
        if identity in token_ids:
            raise IndependentVerificationError("duplicate raw-token identity")
        token_ids.add(identity)
        page = (*cell, record["pageSelectionIndex"])
        if page in revisions and revisions[page] != record["pageRevisionId"]:
            raise IndependentVerificationError("one page index has two revisions")
        revisions[page] = record["pageRevisionId"]
        token_cells[cell].append(record)
    if selected_revisions is not None:
        for model in models:
            for corpus in corpora:
                for index, revision in enumerate(selected_revisions[corpus]):
                    if revisions.get((model, corpus, index)) != revision:
                        raise IndependentVerificationError("raw revision differs from selection")

    container_cells: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    container_ids: set[tuple[str, str, int, int]] = set()
    paths: set[str] = set()
    for item in containers:
        record = _validate_container(item)
        if record["suiteId"] != suite_id or record["attemptId"] != attempt_id:
            raise IndependentVerificationError("container suite/attempt differs")
        cell = (record["modelKey"], record["corpusProject"])
        if cell[0] not in models or cell[1] not in corpora:
            raise IndependentVerificationError("container cell is unregistered")
        if record["layerIndex"] >= layer_counts[cell[0]]:
            raise IndependentVerificationError("container layer exceeds model")
        identity = (*cell, record["pageSelectionIndex"], record["layerIndex"])
        if identity in container_ids or record["relativePath"] in paths:
            raise IndependentVerificationError("duplicate container identity/path")
        container_ids.add(identity)
        paths.add(record["relativePath"])
        if revisions.get((*cell, record["pageSelectionIndex"])) != record["pageRevisionId"]:
            raise IndependentVerificationError("container revision differs from raw token")
        _verify_container_binary(
            record,
            evidence_root=evidence_root,
            codec_root=codec_root,
            expected_bits=bits_by_model[cell[0]][record["layerIndex"]],
        )
        container_cells[cell].append(record)

    expected_cells = {(model, corpus) for model in models for corpus in corpora}
    if set(token_cells) != expected_cells or set(container_cells) != expected_cells:
        raise IndependentVerificationError("evidence does not contain all six cells")
    cells: list[dict[str, Any]] = []
    page_metrics: dict[tuple[str, str, int], tuple[float, int]] = {}
    for model in models:
        for corpus in corpora:
            cell = (model, corpus)
            tokens = sorted(token_cells[cell], key=lambda item: (item["pageSelectionIndex"], item["predictionIndex"]))
            if len(tokens) != 2048 or [
                (item["pageSelectionIndex"], item["predictionIndex"]) for item in tokens
            ] != [(page, prediction) for page in range(16) for prediction in range(128)]:
                raise IndependentVerificationError("cell token coverage/order differs")
            deltas = [
                decode_float32_bits(item["candidateLossF32Bits"], label="candidate loss")
                - decode_float32_bits(item["baselineLossF32Bits"], label="baseline loss")
                for item in tokens
            ]
            matches = sum(item["baselineTop1TokenId"] == item["candidateTop1TokenId"] for item in tokens)
            for page in range(16):
                page_slice = tokens[page * 128:(page + 1) * 128]
                page_metrics[(model, corpus, page)] = (
                    math.fsum(
                        decode_float32_bits(item["candidateLossF32Bits"], label="candidate loss")
                        - decode_float32_bits(item["baselineLossF32Bits"], label="baseline loss")
                        for item in page_slice
                    ) / 128,
                    sum(item["baselineTop1TokenId"] == item["candidateTop1TokenId"] for item in page_slice),
                )
            packed = sorted(container_cells[cell], key=lambda item: (item["pageSelectionIndex"], item["layerIndex"]))
            expected = [(page, layer) for page in range(16) for layer in range(layer_counts[model])]
            if len(packed) != len(expected) or [(item["pageSelectionIndex"], item["layerIndex"]) for item in packed] != expected:
                raise IndependentVerificationError("cell container coverage/order differs")
            dense = sum(item["denseBF16Bytes"] for item in packed)
            compressed = sum(item["containerBytes"] for item in packed)
            ratio = dense / compressed
            delta = math.fsum(deltas) / 2048
            top1 = matches / 2048
            cells.append({
                "modelKey": model, "corpusProject": corpus, "pages": 16,
                "predictions": 2048, "denseBF16Bytes": dense,
                "containerBytes": compressed, "compressionRatioVsBF16": ratio,
                "deltaNLLNatPerToken": delta, "top1ExactMatches": matches,
                "top1Agreement": top1, "structuralReplay": True,
                "pass": ratio >= 2.0 and delta <= 0.01 and top1 >= 0.99,
            })
    aggregates: list[dict[str, Any]] = []
    for model in models:
        block_deltas, block_matches = [], []
        for corpus in corpora:
            for page in range(16):
                delta, matches = page_metrics[(model, corpus, page)]
                block_deltas.append(delta)
                block_matches.append(matches)
        aggregates.append({"modelKey": model, **_model_aggregate(block_deltas, block_matches)})
    verdict = "PASS" if all(item["pass"] for item in cells + aggregates) else "FAIL_GATES"
    return {
        "schemaVersion": INDEPENDENT_RESULT_SCHEMA, "suiteId": suite_id,
        "attemptId": attempt_id, "cells": cells, "modelAggregates": aggregates,
        "verdict": verdict,
        "countsTowardScientificVerdict": counts_toward_scientific_verdict,
    }


# Minimal, independent DER/X.509/RSA verifier.  It intentionally avoids both
# the producer NIST module and a shared crypto wrapper.
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
RSA_SIGNATURES = {
    "1.2.840.113549.1.1.5": ("sha1", bytes.fromhex("3021300906052b0e03021a05000414")),
    "1.2.840.113549.1.1.11": ("sha256", bytes.fromhex("3031300d060960864801650304020105000420")),
    "1.2.840.113549.1.1.12": ("sha384", bytes.fromhex("3041300d060960864801650304020205000430")),
    "1.2.840.113549.1.1.13": ("sha512", bytes.fromhex("3051300d060960864801650304020305000440")),
}
PULSE_DIGEST_INFO = RSA_SIGNATURES["1.2.840.113549.1.1.13"][1]


@dataclass(frozen=True)
class _DER:
    tag: int
    start: int
    body_start: int
    end: int

    def body(self, source: bytes) -> bytes:
        return source[self.body_start:self.end]

    def encoded(self, source: bytes) -> bytes:
        return source[self.start:self.end]


@dataclass(frozen=True)
class _RSAKey:
    modulus: int
    exponent: int

    @property
    def width(self) -> int:
        return (self.modulus.bit_length() + 7) // 8


@dataclass(frozen=True)
class _Certificate:
    der_sha256: str
    tbs: bytes
    signature_oid: str
    signature: bytes
    issuer: bytes
    subject: bytes
    not_before: datetime
    not_after: datetime
    public_key: _RSAKey
    basic_constraints_present: bool
    is_ca: bool
    path_length: int | None
    key_usage_present: bool
    digital_signature: bool
    key_cert_sign: bool
    extended_key_usages: tuple[str, ...]
    dns_names: tuple[str, ...]


@dataclass(frozen=True)
class _TrustRecord:
    certificate_id: str
    chain: tuple[_Certificate, ...]
    chain_verified: bool

    @property
    def leaf(self) -> _Certificate:
        return self.chain[0]


@dataclass(frozen=True)
class IndependentTrustBundle:
    manifest_sha256: str
    fixture_only: bool
    records: Mapping[str, _TrustRecord]


def _der_node(source: bytes, offset: int) -> tuple[_DER, int]:
    if type(source) is not bytes or not 0 <= offset < len(source):
        raise IndependentVerificationError("DER node is truncated")
    start = offset
    tag = source[offset]
    offset += 1
    if tag & 0x1F == 0x1F or offset >= len(source):
        raise IndependentVerificationError("DER tag/length is unsupported")
    first = source[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        width = first & 0x7F
        if width == 0 or width > 4 or offset + width > len(source):
            raise IndependentVerificationError("DER length is invalid")
        encoded_length = source[offset:offset + width]
        if encoded_length[0] == 0:
            raise IndependentVerificationError("DER length is not minimal")
        length = int.from_bytes(encoded_length, "big")
        if length < 0x80:
            raise IndependentVerificationError("DER long length is not minimal")
        offset += width
    end = offset + length
    if end > len(source):
        raise IndependentVerificationError("DER body is truncated")
    return _DER(tag, start, offset, end), end


def _der_root(source: bytes, expected_tag: int = 0x30) -> _DER:
    node, end = _der_node(source, 0)
    if node.tag != expected_tag or end != len(source):
        raise IndependentVerificationError("DER root framing differs")
    return node


def _der_children(source: bytes, parent: _DER) -> list[_DER]:
    result: list[_DER] = []
    offset = parent.body_start
    while offset < parent.end:
        child, offset = _der_node(source, offset)
        result.append(child)
    if offset != parent.end:
        raise IndependentVerificationError("DER child framing differs")
    return result


def _der_integer(source: bytes, node: _DER) -> int:
    value = node.body(source)
    if node.tag != 0x02 or not value or value[0] & 0x80:
        raise IndependentVerificationError("DER INTEGER is invalid")
    if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
        raise IndependentVerificationError("DER INTEGER is not minimal")
    return int.from_bytes(value, "big")


def _der_boolean(source: bytes, node: _DER) -> bool:
    value = node.body(source)
    if node.tag != 0x01 or value not in {b"\x00", b"\xff"}:
        raise IndependentVerificationError("DER BOOLEAN is invalid/non-canonical")
    return value == b"\xff"


def _der_oid(source: bytes, node: _DER) -> str:
    value = node.body(source)
    if node.tag != 0x06 or not value:
        raise IndependentVerificationError("DER OID is invalid")
    first = value[0]
    components = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    in_component = False
    for byte in value[1:]:
        if not in_component and byte == 0x80:
            raise IndependentVerificationError("DER OID is not minimal")
        in_component = True
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            components.append(current)
            current = 0
            in_component = False
    if in_component:
        raise IndependentVerificationError("DER OID is truncated")
    return ".".join(str(value) for value in components)


def _algorithm(source: bytes, node: _DER) -> str:
    if node.tag != 0x30:
        raise IndependentVerificationError("algorithm identifier is not SEQUENCE")
    children = _der_children(source, node)
    if not children:
        raise IndependentVerificationError("algorithm identifier is empty")
    return _der_oid(source, children[0])


def _certificate_time(source: bytes, node: _DER) -> datetime:
    try:
        text = node.body(source).decode("ascii", errors="strict")
        if node.tag == 0x17 and re.fullmatch(r"\d{12}Z", text):
            year = int(text[:2]) + (2000 if int(text[:2]) < 50 else 1900)
            return datetime.strptime(str(year) + text[2:], "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        if node.tag == 0x18 and re.fullmatch(r"\d{14}Z", text):
            return datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except (UnicodeDecodeError, ValueError) as error:
        raise IndependentVerificationError("certificate time is invalid") from error
    raise IndependentVerificationError("certificate time format differs")


def _parse_certificate_extensions(
    source: bytes, wrapper: _DER
) -> tuple[
    bool,
    bool,
    int | None,
    bool,
    bool,
    bool,
    tuple[str, ...],
    tuple[str, ...],
]:
    wrapped = _der_children(source, wrapper)
    if wrapper.tag != 0xA3 or len(wrapped) != 1 or wrapped[0].tag != 0x30:
        raise IndependentVerificationError("X.509 extensions wrapper differs")
    extensions = _der_children(source, wrapped[0])
    if not extensions:
        raise IndependentVerificationError("X.509 extension list is empty")
    seen: set[str] = set()
    basic_present = False
    is_ca = False
    path_length: int | None = None
    key_usage_present = False
    digital_signature = False
    key_cert_sign = False
    extended_key_usages: tuple[str, ...] = ()
    dns_names: tuple[str, ...] = ()
    understood = {"2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17"}
    for extension in extensions:
        if extension.tag != 0x30:
            raise IndependentVerificationError("X.509 extension is not a SEQUENCE")
        fields = _der_children(source, extension)
        if len(fields) not in {2, 3}:
            raise IndependentVerificationError("X.509 extension fields differ")
        oid = _der_oid(source, fields[0])
        if oid in seen:
            raise IndependentVerificationError("duplicate X.509 extension")
        seen.add(oid)
        critical = False
        value_index = 1
        if len(fields) == 3:
            critical = _der_boolean(source, fields[1])
            if not critical:
                raise IndependentVerificationError(
                    "explicit false X.509 critical flag is non-canonical"
                )
            value_index = 2
        value_node = fields[value_index]
        if value_node.tag != 0x04:
            raise IndependentVerificationError("X.509 extnValue is not OCTET STRING")
        encoded_value = value_node.body(source)
        if critical and oid not in understood:
            raise IndependentVerificationError(
                f"unsupported critical X.509 extension: {oid}"
            )
        if oid == "2.5.29.19":
            basic_present = True
            items = _der_children(encoded_value, _der_root(encoded_value))
            if len(items) > 2:
                raise IndependentVerificationError("BasicConstraints fields differ")
            offset = 0
            if items and items[0].tag == 0x01:
                is_ca = _der_boolean(encoded_value, items[0])
                offset = 1
            if len(items) > offset:
                path_length = _der_integer(encoded_value, items[offset])
                offset += 1
            if offset != len(items) or path_length is not None and not is_ca:
                raise IndependentVerificationError("BasicConstraints is inconsistent")
        elif oid == "2.5.29.15":
            key_usage_present = True
            bit_node = _der_root(encoded_value, expected_tag=0x03)
            bits = bit_node.body(encoded_value)
            if len(bits) < 2 or bits[0] > 7:
                raise IndependentVerificationError("KeyUsage BIT STRING differs")
            unused = bits[0]
            payload = bits[1:]
            if unused and payload[-1] & ((1 << unused) - 1):
                raise IndependentVerificationError("KeyUsage unused bits are nonzero")
            digital_signature = bool(payload[0] & 0x80)
            key_cert_sign = bool(payload[0] & 0x04)
        elif oid == "2.5.29.37":
            sequence = _der_children(encoded_value, _der_root(encoded_value))
            if not sequence:
                raise IndependentVerificationError("ExtendedKeyUsage is empty")
            extended_key_usages = tuple(
                _der_oid(encoded_value, item) for item in sequence
            )
            if len(set(extended_key_usages)) != len(extended_key_usages):
                raise IndependentVerificationError("ExtendedKeyUsage repeats an OID")
        elif oid == "2.5.29.17":
            names = _der_children(encoded_value, _der_root(encoded_value))
            observed_dns: list[str] = []
            for name in names:
                if name.tag == 0x82:
                    try:
                        dns_name = name.body(encoded_value).decode(
                            "ascii", errors="strict"
                        ).lower()
                    except UnicodeDecodeError as error:
                        raise IndependentVerificationError(
                            "SubjectAltName dNSName is not ASCII"
                        ) from error
                    if (
                        not dns_name
                        or "*" in dns_name
                        or re.fullmatch(
                            r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
                            dns_name,
                        )
                        is None
                    ):
                        raise IndependentVerificationError(
                            "SubjectAltName dNSName is invalid"
                        )
                    observed_dns.append(dns_name)
            if len(set(observed_dns)) != len(observed_dns):
                raise IndependentVerificationError("SubjectAltName repeats a dNSName")
            dns_names = tuple(observed_dns)
    return (
        basic_present,
        is_ca,
        path_length,
        key_usage_present,
        digital_signature,
        key_cert_sign,
        extended_key_usages,
        dns_names,
    )


def _parse_certificate(der: bytes) -> _Certificate:
    if not der or len(der) > 1024 * 1024:
        raise IndependentVerificationError("certificate is empty/oversized")
    certificate = _der_children(der, _der_root(der))
    if len(certificate) != 3 or certificate[0].tag != 0x30 or certificate[2].tag != 0x03:
        raise IndependentVerificationError("X.509 certificate framing differs")
    tbs, outer_algorithm, signature_node = certificate
    signature_body = signature_node.body(der)
    if not signature_body or signature_body[0] != 0:
        raise IndependentVerificationError("certificate signature bit string differs")
    signature_oid = _algorithm(der, outer_algorithm)
    fields = _der_children(der, tbs)
    if not fields or fields[0].tag != 0xA0:
        raise IndependentVerificationError("X.509 v3 version field is absent")
    version_fields = _der_children(der, fields[0])
    if len(version_fields) != 1 or _der_integer(der, version_fields[0]) != 2:
        raise IndependentVerificationError("certificate is not X.509 v3")
    index = 1
    if len(fields) < index + 6:
        raise IndependentVerificationError("TBSCertificate is incomplete")
    _der_integer(der, fields[index])
    if _algorithm(der, fields[index + 1]) != signature_oid:
        raise IndependentVerificationError("certificate signature algorithms disagree")
    issuer, validity, subject, spki = fields[index + 2:index + 6]
    validity_items = _der_children(der, validity)
    if validity.tag != 0x30 or len(validity_items) != 2:
        raise IndependentVerificationError("certificate validity framing differs")
    spki_items = _der_children(der, spki)
    if spki.tag != 0x30 or len(spki_items) != 2 or _algorithm(der, spki_items[0]) != RSA_ENCRYPTION_OID:
        raise IndependentVerificationError("certificate public key is not RSA")
    bit_string = spki_items[1].body(der)
    if spki_items[1].tag != 0x03 or not bit_string or bit_string[0] != 0:
        raise IndependentVerificationError("RSA public-key bit string differs")
    rsa_source = bit_string[1:]
    rsa_fields = _der_children(rsa_source, _der_root(rsa_source))
    if len(rsa_fields) != 2:
        raise IndependentVerificationError("RSA public key fields differ")
    key = _RSAKey(_der_integer(rsa_source, rsa_fields[0]), _der_integer(rsa_source, rsa_fields[1]))
    if key.modulus.bit_length() < 2048 or key.exponent < 3 or key.exponent % 2 == 0:
        raise IndependentVerificationError("RSA public key is too small/invalid")
    trailing = fields[index + 6:]
    extension_nodes = [item for item in trailing if item.tag == 0xA3]
    if len(extension_nodes) != 1 or any(
        item.tag not in {0x81, 0x82, 0xA3} for item in trailing
    ):
        raise IndependentVerificationError("certificate extension framing differs")
    extension_state = _parse_certificate_extensions(der, extension_nodes[0])
    return _Certificate(
        sha256_bytes(der), tbs.encoded(der), signature_oid, signature_body[1:],
        issuer.encoded(der), subject.encoded(der),
        _certificate_time(der, validity_items[0]),
        _certificate_time(der, validity_items[1]), key, *extension_state,
    )


def _rsa_verify(key: _RSAKey, signature: bytes, digest: bytes, prefix: bytes) -> None:
    if len(signature) != key.width:
        raise IndependentVerificationError("RSA signature/key widths differ")
    representative = int.from_bytes(signature, "big")
    if representative >= key.modulus:
        raise IndependentVerificationError("RSA signature representative is invalid")
    decoded = pow(representative, key.exponent, key.modulus).to_bytes(key.width, "big")
    digest_info = prefix + digest
    padding = key.width - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    if padding < 8 or not hmac.compare_digest(decoded, expected):
        raise IndependentVerificationError("RSA PKCS#1 v1.5 verification failed")


def _verify_certificate_signature(certificate: _Certificate, issuer_key: _RSAKey) -> None:
    parameters = RSA_SIGNATURES.get(certificate.signature_oid)
    if parameters is None:
        raise IndependentVerificationError("certificate signature algorithm unsupported")
    digest_name, prefix = parameters
    _rsa_verify(issuer_key, certificate.signature, hashlib.new(digest_name, certificate.tbs).digest(), prefix)


def _pem_der(pem: bytes) -> bytes:
    try:
        text = pem.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise IndependentVerificationError("certificate PEM is not ASCII") from error
    match = re.fullmatch(
        r"\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)"
        r"\s*-----END CERTIFICATE-----\s*", text,
    )
    if match is None:
        raise IndependentVerificationError("PEM must contain one certificate")
    try:
        return base64.b64decode("".join(match.group(1).split()), validate=True)
    except (ValueError, binascii.Error) as error:
        raise IndependentVerificationError("certificate PEM base64 differs") from error


def _read_trust_commitment(root: Path, value: Any, *, require_sha512: bool) -> bytes:
    fields = {"relativePath", "bytes", "sha256"} | ({"sha512"} if require_sha512 else set())
    if not isinstance(value, dict) or set(value) != fields:
        raise IndependentVerificationError("trust-file commitment fields differ")
    if type(value["bytes"]) is not int or not 1 <= value["bytes"] <= 16 * 1024 * 1024:
        raise IndependentVerificationError("trust-file byte count is invalid")
    raw = _read_beneath(root, value["relativePath"], value["bytes"])
    if not isinstance(value["sha256"], str) or sha256_bytes(raw) != value["sha256"]:
        raise IndependentVerificationError("trust-file SHA-256 differs")
    if require_sha512 and hashlib.sha512(raw).hexdigest() != value["sha512"]:
        raise IndependentVerificationError("trust-file SHA-512 differs")
    return raw


def load_independent_trust_bundle(
    manifest_path: Path,
    *,
    expected_time: datetime,
    expected_manifest_sha256: str | None,
    expected_root_der_sha256: Sequence[str] | None = None,
    allow_known_answer_fixture: bool = False,
) -> IndependentTrustBundle:
    if not isinstance(expected_time, datetime) or expected_time.tzinfo is None:
        raise IndependentVerificationError("trust time must be timezone-aware")
    expected_time = expected_time.astimezone(timezone.utc)
    metadata = manifest_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= 16 * 1024 * 1024:
        raise IndependentVerificationError("trust manifest is not a bounded regular file")
    manifest_raw = _read_beneath(manifest_path.parent, manifest_path.name, metadata.st_size)
    manifest_digest = sha256_bytes(manifest_raw)
    if expected_manifest_sha256 is not None:
        if not isinstance(expected_manifest_sha256, str) or SHA256_LOWER.fullmatch(expected_manifest_sha256) is None or not hmac.compare_digest(manifest_digest, expected_manifest_sha256):
            raise IndependentVerificationError("trust manifest commitment differs")
    manifest = load_json_strict_bytes(manifest_raw, label="NIST trust manifest")
    if not isinstance(manifest, dict) or set(manifest) != {"schemaVersion", "status", "fixtureOnly", "certificates"}:
        raise IndependentVerificationError("trust manifest fields differ")
    if canonical_json_bytes(manifest) != manifest_raw:
        raise IndependentVerificationError("trust manifest is not canonical JSON")
    if manifest["schemaVersion"] != TRUST_SCHEMA or type(manifest["fixtureOnly"]) is not bool:
        raise IndependentVerificationError("trust manifest schema/fixture flag differs")
    fixture = manifest["fixtureOnly"]
    if fixture and not allow_known_answer_fixture:
        raise IndependentVerificationError("fixture trust bundle is forbidden")
    if not fixture and expected_manifest_sha256 is None:
        raise IndependentVerificationError("normative trust bundle is not precommitted")
    if fixture:
        if expected_root_der_sha256 not in (None, (), []):
            raise IndependentVerificationError(
                "historical fixture cannot claim a normative root pin"
            )
        root_pins: frozenset[str] = frozenset()
    else:
        if (
            not isinstance(expected_root_der_sha256, (list, tuple))
            or len(expected_root_der_sha256) != 1
            or any(
                not isinstance(value, str)
                or SHA256_LOWER.fullmatch(value) is None
                for value in expected_root_der_sha256
            )
        ):
            raise IndependentVerificationError(
                "normative NIST trust requires one registered root DER SHA-256"
            )
        if tuple(expected_root_der_sha256) != (
            REGISTERED_NIST_TRUST_ROOT_DER_SHA256,
        ):
            raise IndependentVerificationError(
                "normative NIST root pin differs from the registered public root"
            )
        root_pins = frozenset(expected_root_der_sha256)
    expected_status = "KNOWN_ANSWER_FIXTURE_ONLY" if fixture else "FROZEN_OFFLINE_TRUST_BUNDLE"
    if manifest["status"] != expected_status:
        raise IndependentVerificationError("trust manifest status differs")
    specifications = manifest["certificates"]
    if not isinstance(specifications, dict) or not specifications:
        raise IndependentVerificationError("trust manifest has no certificates")
    records: dict[str, _TrustRecord] = {}
    for certificate_id, specification in specifications.items():
        if not isinstance(certificate_id, str) or HEX64_BYTES.fullmatch(certificate_id) is None:
            raise IndependentVerificationError("certificate ID differs")
        if not isinstance(specification, dict) or set(specification) != {"chainPolicy", "pem", "chain"}:
            raise IndependentVerificationError("certificate specification fields differ")
        pem = _read_trust_commitment(manifest_path.parent, specification["pem"], require_sha512=False)
        chain_specs = specification["chain"]
        if not isinstance(chain_specs, list) or not chain_specs:
            raise IndependentVerificationError("certificate chain is empty")
        chain_der = [_read_trust_commitment(manifest_path.parent, item, require_sha512=True) for item in chain_specs]
        if len({hashlib.sha512(item).digest() for item in chain_der}) != len(chain_der):
            raise IndependentVerificationError("certificate chain repeats an item")
        if _pem_der(pem) != chain_der[0] or hashlib.sha512(chain_der[0]).hexdigest() != certificate_id.lower():
            raise IndependentVerificationError("leaf PEM/DER/certificateId differ")
        chain = tuple(_parse_certificate(item) for item in chain_der)
        if fixture:
            if specification["chainPolicy"] != "fixture-leaf-pin-only" or len(chain) != 1:
                raise IndependentVerificationError("fixture chain policy differs")
            if not chain[0].not_before <= expected_time <= chain[0].not_after:
                raise IndependentVerificationError("fixture certificate is not valid")
            chain_verified = False
        else:
            if specification["chainPolicy"] != "offline-x509-rsa-pkcs1" or len(chain) < 2:
                raise IndependentVerificationError("normative chain policy differs")
            if chain[-1].der_sha256 not in root_pins:
                raise IndependentVerificationError(
                    "NIST trust anchor differs from registered public root DER"
                )
            for index, certificate in enumerate(chain):
                if not certificate.not_before <= expected_time <= certificate.not_after:
                    raise IndependentVerificationError("certificate is not valid at pulse time")
                if index >= 1:
                    if (
                        not certificate.basic_constraints_present
                        or not certificate.is_ca
                        or not certificate.key_usage_present
                        or not certificate.key_cert_sign
                    ):
                        raise IndependentVerificationError(
                            "certificate issuer lacks CA/keyCertSign authority"
                        )
                    subordinate_ca_count = sum(
                        item.is_ca for item in chain[1:index]
                    )
                    if (
                        certificate.path_length is not None
                        and subordinate_ca_count > certificate.path_length
                    ):
                        raise IndependentVerificationError(
                            "certificate pathLenConstraint is exceeded"
                        )
                issuer = chain[index + 1] if index + 1 < len(chain) else certificate
                if certificate.issuer != issuer.subject:
                    raise IndependentVerificationError("certificate issuer/subject differs")
                _verify_certificate_signature(certificate, issuer.public_key)
            chain_verified = True
        normalized = certificate_id.lower()
        if normalized in records:
            raise IndependentVerificationError("duplicate certificateId")
        records[normalized] = _TrustRecord(normalized, chain, chain_verified)
    return IndependentTrustBundle(manifest_digest, fixture, MappingProxyType(records))


def _u32be(value: Any, label: str) -> bytes:
    if type(value) is not int or not 0 <= value < 2**32:
        raise IndependentVerificationError(f"{label} is outside uint32")
    return struct.pack(">I", value)


def _u64be(value: Any, label: str) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise IndependentVerificationError(f"{label} is outside uint64")
    return struct.pack(">Q", value)


def _length32(value: bytes) -> bytes:
    if len(value) >= 2**32:
        raise IndependentVerificationError("NIST field is too long")
    return struct.pack(">I", len(value)) + value


def _string32(value: Any, label: str) -> bytes:
    return _length32(_text(value, label).encode("utf-8", errors="strict"))


def _hex64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or HEX64_BYTES.fullmatch(value) is None:
        raise IndependentVerificationError(f"{label} is not 64 hex bytes")
    return bytes.fromhex(value)


def _pulse_time(value: Any) -> datetime:
    if not isinstance(value, str) or UTC_MILLISECONDS.fullmatch(value) is None:
        raise IndependentVerificationError("NIST timestamp format differs")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise IndependentVerificationError("NIST timestamp is not real") from error


def _unsigned_pulse(
    pulse: Mapping[str, Any], *, expected_version: str
) -> bytes:
    fields = {
        "uri", "version", "cipherSuite", "period", "certificateId", "chainIndex",
        "pulseIndex", "timeStamp", "localRandomValue", "external", "listValues",
        "precommitmentValue", "statusCode", "signatureValue", "outputValue",
    }
    if not isinstance(pulse, dict) or set(pulse) != fields:
        raise IndependentVerificationError("NIST pulse fields differ")
    if (
        pulse["version"] != expected_version
        or pulse["cipherSuite"] != REGISTERED_PULSE_CIPHER_SUITE
        or pulse["period"] != REGISTERED_PULSE_PERIOD_MILLISECONDS
    ):
        raise IndependentVerificationError("NIST pulse version/profile differs")
    parsed_uri = urlsplit(pulse["uri"] if isinstance(pulse["uri"], str) else "")
    expected_path = f"/beacon/2.0/chain/{pulse['chainIndex']}/pulse/{pulse['pulseIndex']}"
    if (
        parsed_uri.scheme != "https" or parsed_uri.hostname != "beacon.nist.gov"
        or parsed_uri.port not in (None, 443) or parsed_uri.username is not None
        or parsed_uri.password is not None or parsed_uri.path != expected_path
        or parsed_uri.query or parsed_uri.fragment
    ):
        raise IndependentVerificationError("NIST pulse URI differs from chain/index")
    _pulse_time(pulse["timeStamp"])
    external = pulse["external"]
    if not isinstance(external, dict) or set(external) != {"sourceId", "statusCode", "value"}:
        raise IndependentVerificationError("NIST external fields differ")
    list_values = pulse["listValues"]
    kinds = ("previous", "hour", "day", "month", "year")
    if not isinstance(list_values, list) or len(list_values) != len(kinds):
        raise IndependentVerificationError("NIST listValues count differs")
    encoded_lists: list[bytes] = []
    for item, kind in zip(list_values, kinds):
        if not isinstance(item, dict) or set(item) != {"uri", "type", "value"}:
            raise IndependentVerificationError("NIST listValue fields differ")
        if item["type"] != kind or item["uri"] is not None and not isinstance(item["uri"], str):
            raise IndependentVerificationError("NIST listValue type/order differs")
        encoded_lists.append(_length32(_hex64(item["value"], f"listValue.{kind}")))
    return b"".join((
        _string32(pulse["uri"], "uri"), _string32(pulse["version"], "version"),
        _u32be(pulse["cipherSuite"], "cipherSuite"), _u32be(pulse["period"], "period"),
        _length32(_hex64(pulse["certificateId"], "certificateId")),
        _u64be(pulse["chainIndex"], "chainIndex"), _u64be(pulse["pulseIndex"], "pulseIndex"),
        _string32(pulse["timeStamp"], "timeStamp"),
        _length32(_hex64(pulse["localRandomValue"], "localRandomValue")),
        _length32(_hex64(external["sourceId"], "external.sourceId")),
        _u32be(external["statusCode"], "external.statusCode"),
        _length32(_hex64(external["value"], "external.value")),
        *encoded_lists,
        _length32(_hex64(pulse["precommitmentValue"], "precommitmentValue")),
        _u32be(pulse["statusCode"], "statusCode"),
    ))


def _validate_archived_http(header_bytes: bytes, body: bytes) -> datetime:
    if not header_bytes.endswith(b"\r\n\r\n") or b"\x00" in header_bytes:
        raise IndependentVerificationError("NIST headers are not exact CRLF framing")
    lines = header_bytes[:-4].split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [\x20-\x7e]*", lines[0]) is None:
        raise IndependentVerificationError("NIST status line is invalid")
    if int(lines[0].split(b" ", 2)[1]) != 200:
        raise IndependentVerificationError("NIST archived response is not 200")
    headers: dict[str, list[str]] = {}
    for raw in lines[1:]:
        if not raw or raw[:1] in b" \t" or b":" not in raw:
            raise IndependentVerificationError("NIST header line is malformed")
        name, raw_value = raw.split(b":", 1)
        if re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise IndependentVerificationError("NIST header name is invalid")
        headers.setdefault(name.decode("ascii").lower(), []).append(raw_value.strip(b" \t").decode("latin-1"))
    if "transfer-encoding" in headers:
        raise IndependentVerificationError("transfer-coded NIST archive is forbidden")
    lengths = headers.get("content-length", [])
    if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) != len(body):
        raise IndependentVerificationError("NIST Content-Length differs")
    dates = headers.get("date", [])
    if len(dates) != 1:
        raise IndependentVerificationError("NIST Date header count differs")
    try:
        parsed = parsedate_to_datetime(dates[0])
    except (TypeError, ValueError) as error:
        raise IndependentVerificationError("NIST Date header is invalid") from error
    if parsed.tzinfo is None:
        raise IndependentVerificationError("NIST Date lacks timezone")
    return parsed.astimezone(timezone.utc)


def verify_nist_response(
    *,
    request_uri: str,
    response_headers: bytes,
    response_body: bytes,
    trust_bundle: IndependentTrustBundle,
    expected_unix_milliseconds: int = TARGET_UNIX_MILLISECONDS,
    allow_known_answer_fixture: bool = False,
) -> dict[str, Any]:
    if type(expected_unix_milliseconds) is not int or expected_unix_milliseconds < 0:
        raise IndependentVerificationError("NIST target milliseconds invalid")
    expected_uri = "https://beacon.nist.gov/beacon/2.0/pulse/time/" + str(expected_unix_milliseconds)
    if request_uri != expected_uri:
        raise IndependentVerificationError("NIST request URI differs")
    server_date = _validate_archived_http(response_headers, response_body)
    expected_time = datetime.fromtimestamp(expected_unix_milliseconds // 1000, tz=timezone.utc) + timedelta(milliseconds=expected_unix_milliseconds % 1000)
    if server_date < expected_time:
        raise IndependentVerificationError("NIST HTTP Date precedes pulse")
    value = load_json_strict_bytes(response_body, label="NIST pulse")
    if not isinstance(value, dict) or set(value) != {"pulse"} or not isinstance(value["pulse"], dict):
        raise IndependentVerificationError("NIST response does not contain exactly one pulse")
    pulse = value["pulse"]
    expected_version = (
        HISTORICAL_FIXTURE_PULSE_VERSION
        if trust_bundle.fixture_only
        else REGISTERED_PULSE_VERSION
    )
    unsigned = _unsigned_pulse(pulse, expected_version=expected_version)
    expected_timestamp = expected_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expected_unix_milliseconds % 1000:03d}Z"
    pulse_time = _pulse_time(pulse["timeStamp"])
    if pulse["timeStamp"] != expected_timestamp or pulse_time != expected_time:
        raise IndependentVerificationError("NIST returned nearest/non-exact pulse")
    certificate_id = pulse["certificateId"].lower()
    record = trust_bundle.records.get(certificate_id)
    if record is None:
        raise IndependentVerificationError("NIST certificate is not frozen")
    if trust_bundle.fixture_only and not allow_known_answer_fixture:
        raise IndependentVerificationError("fixture NIST trust is forbidden")
    if not record.chain_verified and not allow_known_answer_fixture:
        raise IndependentVerificationError("NIST certificate chain is unverified")
    if not record.leaf.not_before <= pulse_time <= record.leaf.not_after:
        raise IndependentVerificationError("NIST leaf is invalid at pulse time")
    if not record.leaf.key_usage_present or not record.leaf.digital_signature:
        raise IndependentVerificationError(
            "NIST leaf lacks digitalSignature key usage"
        )
    if not record.leaf.basic_constraints_present or record.leaf.is_ca:
        raise IndependentVerificationError(
            "NIST signing leaf BasicConstraints is absent/not CA=false"
        )
    if record.leaf.dns_names != ("engine.beacon.nist.gov",):
        raise IndependentVerificationError(
            "NIST leaf is not bound to engine.beacon.nist.gov"
        )
    signature_hex = pulse["signatureValue"]
    if not isinstance(signature_hex, str) or len(signature_hex) > 8192 or HEX_SIGNATURE.fullmatch(signature_hex) is None:
        raise IndependentVerificationError("NIST signature is invalid hex")
    signature = bytes.fromhex(signature_hex)
    digest = hashlib.sha512(unsigned).digest()
    _rsa_verify(record.leaf.public_key, signature, digest, PULSE_DIGEST_INFO)
    output = _hex64(pulse["outputValue"], "outputValue")
    if not hmac.compare_digest(hashlib.sha512(unsigned + signature).digest(), output):
        raise IndependentVerificationError("NIST output construction differs")
    return {
        "schemaVersion": NIST_VERIFY_SCHEMA,
        "status": "VERIFIED_KNOWN_ANSWER_FIXTURE" if trust_bundle.fixture_only else "VERIFIED_FROZEN_NIST_PULSE",
        "countsTowardScientificVerdict": not trust_bundle.fixture_only,
        "requestURI": request_uri,
        "responseDate": server_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "responseHeadersSHA256": sha256_bytes(response_headers),
        "responseBodyBytes": len(response_body),
        "responseBodySHA256": sha256_bytes(response_body),
        "expectedUnixMilliseconds": expected_unix_milliseconds,
        "pulseURI": pulse["uri"], "timeStamp": pulse["timeStamp"],
        "pulseVersion": pulse["version"],
        "cipherSuite": pulse["cipherSuite"],
        "periodMilliseconds": pulse["period"],
        "certificateId": certificate_id,
        "certificateChainVerified": record.chain_verified,
        "trustBundleManifestSHA256": trust_bundle.manifest_sha256,
        "signedBytesSHA512": digest.hex(), "outputValue": output.hex().upper(),
        "signatureVerified": True, "outputConstructionVerified": True,
        "exactTimestampVerified": True, "responseDateNotBeforePulseVerified": True,
    }


def canonical_nist_verification_bytes(value: Mapping[str, Any]) -> bytes:
    fields = {
        "schemaVersion", "status", "countsTowardScientificVerdict", "requestURI",
        "responseDate", "responseHeadersSHA256", "responseBodyBytes", "responseBodySHA256",
        "expectedUnixMilliseconds", "pulseURI", "timeStamp", "certificateId",
        "pulseVersion", "cipherSuite", "periodMilliseconds",
        "certificateChainVerified", "trustBundleManifestSHA256", "signedBytesSHA512",
        "outputValue", "signatureVerified", "outputConstructionVerified",
        "exactTimestampVerified", "responseDateNotBeforePulseVerified",
    }
    if not isinstance(value, Mapping) or set(value) != fields or value["schemaVersion"] != NIST_VERIFY_SCHEMA:
        raise IndependentVerificationError("NIST verification record fields/schema differ")
    fixture = value["status"] == "VERIFIED_KNOWN_ANSWER_FIXTURE"
    if value["status"] not in {"VERIFIED_KNOWN_ANSWER_FIXTURE", "VERIFIED_FROZEN_NIST_PULSE"}:
        raise IndependentVerificationError("NIST verification status differs")
    if value["countsTowardScientificVerdict"] is not (not fixture) or value["certificateChainVerified"] is not (not fixture):
        raise IndependentVerificationError("NIST verification fixture truth flags differ")
    expected_version = (
        HISTORICAL_FIXTURE_PULSE_VERSION if fixture else REGISTERED_PULSE_VERSION
    )
    if (
        value["pulseVersion"] != expected_version
        or value["cipherSuite"] != REGISTERED_PULSE_CIPHER_SUITE
        or value["periodMilliseconds"]
        != REGISTERED_PULSE_PERIOD_MILLISECONDS
    ):
        raise IndependentVerificationError("NIST verification pulse profile differs")
    if any(value[field] is not True for field in (
        "signatureVerified", "outputConstructionVerified", "exactTimestampVerified",
        "responseDateNotBeforePulseVerified",
    )):
        raise IndependentVerificationError("NIST verification truth flags differ")
    milliseconds = value["expectedUnixMilliseconds"]
    if type(milliseconds) is not int or milliseconds < 0:
        raise IndependentVerificationError("NIST verification target differs")
    expected_request = "https://beacon.nist.gov/beacon/2.0/pulse/time/" + str(milliseconds)
    expected_time = datetime.fromtimestamp(milliseconds // 1000, tz=timezone.utc) + timedelta(milliseconds=milliseconds % 1000)
    expected_timestamp = expected_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{milliseconds % 1000:03d}Z"
    if value["requestURI"] != expected_request or value["timeStamp"] != expected_timestamp:
        raise IndependentVerificationError("NIST verification endpoint/timestamp differs")
    if type(value["responseBodyBytes"]) is not int or value["responseBodyBytes"] < 0:
        raise IndependentVerificationError("NIST verification body size differs")
    if any(not isinstance(value[field], str) or SHA256_LOWER.fullmatch(value[field]) is None for field in (
        "responseHeadersSHA256", "responseBodySHA256", "trustBundleManifestSHA256",
    )):
        raise IndependentVerificationError("NIST verification SHA-256 differs")
    if any(not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{128}", value[field]) is None for field in (
        "certificateId", "signedBytesSHA512",
    )):
        raise IndependentVerificationError("NIST verification SHA-512 differs")
    if not isinstance(value["outputValue"], str) or re.fullmatch(r"[0-9A-F]{128}", value["outputValue"]) is None:
        raise IndependentVerificationError("NIST verification outputValue differs")
    if not isinstance(value["pulseURI"], str) or not isinstance(value["responseDate"], str):
        raise IndependentVerificationError("NIST verification URI/Date differs")
    return canonical_json_bytes(dict(value))


__all__ = [
    "IndependentVerificationError", "IndependentTrustBundle", "TARGET_ENDPOINT",
    "TARGET_UNIX_MILLISECONDS", "canonical_json_bytes", "load_json_strict_bytes",
    "decode_float32_bits", "encode_token_id_stream", "derive_selection",
    "validate_worker_job", "extract_ledger_token_commitments",
    "verify_page_token_bindings", "evaluate_evidence",
    "load_independent_trust_bundle", "verify_nist_response",
    "canonical_nist_verification_bytes",
]
