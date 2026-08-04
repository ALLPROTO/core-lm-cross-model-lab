#!/usr/bin/env python3
"""Networkless, one-model worker for the frozen blind-v4 experiment.

After the durable attempt marker and verified NIST selection, the supervisor
creates a canonical job for one registered model.  This worker then reads each
verified model/corpus asset exactly once into owned byte buffers, loads
safetensors without mmap or pickle, evaluates all 32 selected real pages, and
writes page-token/raw-token/container evidence.  It has no download path and
never calls ``from_pretrained``.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any


# These must be fixed before importing NumPy, Torch, tokenizers, or Transformers.
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


V4_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V4_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v4.cache_adapter import (  # noqa: E402
    build_dynamic_cache,
    flatten_kv_numpy,
    geometry_from_config,
)
from v4.evidence import (  # noqa: E402
    CONTAINER_SCHEMA,
    PAGE_TOKEN_SCHEMA,
    RAW_TOKEN_SCHEMA,
    canonical_json_line,
    float32_to_bits,
    token_id_stream,
)
from v4.mediawiki_snapshot import parse_record  # noqa: E402
from v4.development_corpus import (  # noqa: E402
    CorpusSentence,
    DATASET_ID as DEVELOPMENT_DATASET_ID,
    DevelopmentCorpusError,
    SENTENCE_COUNT as DEVELOPMENT_DATASET_SENTENCES,
    SOURCE_BYTES as DEVELOPMENT_DATASET_BYTES,
    SOURCE_SHA256 as DEVELOPMENT_DATASET_SHA256,
    parse_corpus as parse_development_corpus,
    parse_record as parse_development_corpus_record,
    serialize_record as serialize_development_corpus_record,
)
from v4.protocol import canonical_json_bytes, load_json_strict  # noqa: E402


PREFILL_TOKENS = 383
PREDICTION_TOKENS = 128
PAGE_TOKENS = 512
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
ATTEMPT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")
SCIENTIFIC_JOB_SCHEMA = "corelm-crossmodel-livewiki-v4-worker-job-v1"
SCIENTIFIC_SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v4-author-verified"
DEVELOPMENT_JOB_SCHEMA = (
    "corelm-crossmodel-v4-real-e2e-development-worker-job-v1"
)
DEVELOPMENT_SUMMARY_SCHEMA = (
    "corelm-crossmodel-v4-real-e2e-development-worker-summary-v1"
)
DEVELOPMENT_SUITE_ID = "corelm-voidtoken-crossmodel-v4-author-verified-development-e2e"
DEVELOPMENT_RUN_ID = re.compile(r"development-e2e-[0-9a-f]{64}\Z")
DEVELOPMENT_RAW_TOKEN_SCHEMA = (
    "corelm-crossmodel-v4-real-e2e-development-raw-token-v1"
)
DEVELOPMENT_PAGE_TOKEN_SCHEMA = (
    "corelm-crossmodel-v4-real-e2e-development-page-token-v1"
)
DEVELOPMENT_CONTAINER_SCHEMA = (
    "corelm-crossmodel-v4-real-e2e-development-container-v1"
)
DEVELOPMENT_DATASET_PATH = "inputs/corpus/en_pud-ud-test.conllu"
DEVELOPMENT_MODEL_BINDINGS = {
    "gpt-neo-125m": {
        "layers": 12,
        "vocabSize": 50257,
        "files": {
            "config.json": (1007, "dace197ce91788731063527367b0a6766d7d3a4ab72c671fabf16dbbf9037e16"),
            "generation_config.json": (119, "a7996263aa24aca6c74d9edfe19dbb3af742c572ada10f73c88c3a5e30ba5c14"),
            "merges.txt": (456318, "1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5"),
            "model.safetensors": (525979192, "52738cbfb54e25a232598242f60ef19ee193d36090b98fe649b10c02724b3521"),
            "special_tokens_map.json": (357, "a00e1f660c842693e7f667898759c24eb538c2dbb09b91c22dbde1b45d4cdee8"),
            "tokenizer.json": (2107652, "f6ed3d307010c244c22aeffbde05f419cf277c23e64cf98b673cac5449cfeff5"),
            "tokenizer_config.json": (727, "fd1d9aed595c7ad9e64cf65c74e94bddc9dc1608e178a4f60380c8373813f30f"),
            "vocab.json": (898669, "03087853bc70c618b66e7c7a43e787d2db4c469416beac9a483e53dad1f72f27"),
        },
    },
    "smollm2-360m": {
        "layers": 32,
        "vocabSize": 49152,
        "files": {
            "config.json": (689, "34f7801487078de7e434e19162c497e5cc6ff397080e40e8586627cb68a5168a"),
            "generation_config.json": (111, "2056c988e990b0d13670f63f2f3b87b3b6d07edaf7a3416998ba27dab2d8a059"),
            "merges.txt": (466391, "0b54e8aa4e53d5383e2e4bc635a56b43f9647f7b13832d5d9ecd8f82dac4f510"),
            "model.safetensors": (723674912, "7aaff6661428bed033abba9522bec81938678642cca3181fe752b6ca9e1e540f"),
            "special_tokens_map.json": (831, "e786b595b9a23148bf1630df78d9037a048ea671e48bfd3549a1e3c233742bb3"),
            "tokenizer.json": (2104556, "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c"),
            "tokenizer_config.json": (3658, "4bb9af56a342753d39374f4016a16574cab299fe088e896f425ce3c433f61424"),
            "vocab.json": (800662, "82b84012e3add4d01d12ba14442026e49b8cbbaead1f79ecf3d919784f82dc79"),
        },
    },
    "tiny-starcoder-py": {
        "layers": 20,
        "vocabSize": 49152,
        "files": {
            "config.json": (1030, "5961dd4e9a1f649c509cee1a4936cda489b165dc38b33127d39623a8f13490a5"),
            "generation_config.json": (111, "368f15f9c335d48e1a585440037c77022af6b867303dc8fe9ee01e8fc86c1617"),
            "merges.txt": (441848, "74b0a4bc1a97ebc1d227f69231b18574374ba052fb945b0fa0aa91d3c32504a2"),
            "model.safetensors": (656601304, "15fa942f055b618d5ca6283f5c27278a475ff12e53dc704b9658ffd5160d4021"),
            "special_tokens_map.json": (532, "0823292e24ea07b89317e9ede9d08da2a1b6c014290c06908a7ad04f1efd6719"),
            "tokenizer.json": (2057395, "42b5a37ba11199f024f2b8873e1ecba98da33166e16f700bf7cb2304b0a5583f"),
            "tokenizer_config.json": (677, "95684c52ad9a970dbbb17576ee2237cb62902c1eff6804c7c91a4d6219a4a6d7"),
            "vocab.json": (776993, "20175afb9f164fad4829aca2279f8df7eeff1e2e3f671378aaa287a740aff09f"),
        },
    },
}


class WorkerError(RuntimeError):
    """Raised when a model worker cannot produce valid scientific evidence."""


def _guard_development_output_root(path: Path) -> None:
    """Keep development evidence out of every scientific/repository namespace."""

    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
    except TypeError as error:
        raise WorkerError("development output root is invalid") from error
    cursor = absolute
    suffix: list[str] = []
    while not cursor.exists():
        if cursor == cursor.parent:
            raise WorkerError("development output root has no existing ancestor")
        suffix.append(cursor.name)
        cursor = cursor.parent
    try:
        canonical = cursor.resolve(strict=True).joinpath(*reversed(suffix))
        project = PROJECT_ROOT.resolve(strict=True)
    except OSError as error:
        raise WorkerError("development output root cannot be resolved") from error
    if canonical == project or canonical.is_relative_to(project):
        raise WorkerError("development output root must be outside the repository")
    if any(part.endswith(".one-shot-result") for part in canonical.parts):
        raise WorkerError(
            "development output root must not occupy a scientific result namespace"
        )
    if absolute.exists() and absolute.is_symlink():
        raise WorkerError("development output root must not be a symlink")


def _deny_network_audit(event: str, _arguments: tuple[Any, ...]) -> None:
    if event.startswith("socket."):
        raise WorkerError(f"network access is forbidden in the inference child: {event}")


def install_network_denial() -> None:
    """Deny socket creation both by monkey-patch and by CPython audit hook."""

    sys.addaudithook(_deny_network_audit)

    class DeniedSocket:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise WorkerError("network access is forbidden in the inference child")

    socket.socket = DeniedSocket  # type: ignore[assignment]
    socket.create_connection = DeniedSocket  # type: ignore[assignment]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WorkerError(f"{label} is not a canonical relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or str(relative) != value
        or any(part in {"", "."} for part in relative.parts)
    ):
        raise WorkerError(f"{label} escapes its frozen root")
    return relative


def _read_once_beneath(
    root: Path,
    relative_value: Any,
    *,
    expected_bytes: int,
    expected_sha256: str,
    maximum_bytes: int,
) -> bytes:
    relative = _safe_relative(relative_value, "asset path")
    if (
        type(expected_bytes) is not int
        or expected_bytes < 1
        or expected_bytes > maximum_bytes
        or not isinstance(expected_sha256, str)
        or HEX_64.fullmatch(expected_sha256) is None
    ):
        raise WorkerError("asset commitment is invalid")
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(absolute_root, directory_flags)
    except OSError as error:
        raise WorkerError("frozen asset root cannot be opened safely") from error
    try:
        for component in relative.parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise WorkerError("asset parent is not a directory")
            os.close(descriptor)
            descriptor = next_descriptor
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(relative.parts[-1], file_flags, dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_bytes:
                raise WorkerError("asset byte count or file type differs")
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            remaining = expected_bytes
            while remaining:
                chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise WorkerError("asset was truncated while being read")
                chunks.append(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_descriptor)
            identity = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
            )
            if identity(before) != identity(after):
                raise WorkerError("asset changed while being read")
            if digest.hexdigest() != expected_sha256:
                raise WorkerError("asset SHA-256 differs from its frozen commitment")
            return b"".join(chunks)
        finally:
            os.close(file_descriptor)
    except OSError as error:
        raise WorkerError("asset path contains a symlink or missing component") from error
    finally:
        os.close(descriptor)


def _decode_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkerError(f"{label} is invalid strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise WorkerError(f"{label} must contain a JSON object")
    return value


def validate_job(job: Any) -> None:
    common = {
        "schemaVersion",
        "suiteId",
        "countsTowardScientificVerdict",
        "model",
        "selectedCorpora",
        "pages",
        "candidate",
        "seed",
    }
    if not isinstance(job, dict):
        raise WorkerError("worker job fields differ from the frozen contract")
    schema = job.get("schemaVersion")
    development = schema == DEVELOPMENT_JOB_SCHEMA
    expected = set(common)
    if development:
        expected.update(
            {
                "runId",
                "usedForCandidateSelectionOrTuning",
                "scientificAttemptStateCreated",
                "nistUsed",
                "futureCorpusUsed",
                "controlConfigurationSHA256",
                "sourceDataset",
            }
        )
    else:
        expected.add("attemptId")
    if not isinstance(job, dict) or set(job) != expected:
        raise WorkerError("worker job fields differ from the frozen contract")
    if schema not in {SCIENTIFIC_JOB_SCHEMA, DEVELOPMENT_JOB_SCHEMA}:
        raise WorkerError("worker job schemaVersion differs")
    if development:
        if job["suiteId"] != DEVELOPMENT_SUITE_ID:
            raise WorkerError("development worker suiteId differs")
        if (
            job["countsTowardScientificVerdict"] is not False
            or job["usedForCandidateSelectionOrTuning"] is not False
            or job["scientificAttemptStateCreated"] is not False
            or job["nistUsed"] is not False
            or job["futureCorpusUsed"] is not False
        ):
            raise WorkerError("development worker boundary flags differ")
        if (
            not isinstance(job["runId"], str)
            or DEVELOPMENT_RUN_ID.fullmatch(job["runId"]) is None
        ):
            raise WorkerError("development worker run identity is invalid")
        if (
            not isinstance(job["controlConfigurationSHA256"], str)
            or HEX_64.fullmatch(job["controlConfigurationSHA256"]) is None
            or job["runId"]
            != "development-e2e-" + job["controlConfigurationSHA256"]
        ):
            raise WorkerError("development control configuration identity is invalid")
        if job["sourceDataset"] != {
            "path": DEVELOPMENT_DATASET_PATH,
            "bytes": DEVELOPMENT_DATASET_BYTES,
            "sha256": DEVELOPMENT_DATASET_SHA256,
        }:
            raise WorkerError("development source dataset binding differs")
    else:
        if job["suiteId"] != SCIENTIFIC_SUITE_ID:
            raise WorkerError("worker job suiteId differs")
        if job["countsTowardScientificVerdict"] is not True:
            raise WorkerError("normative worker refuses non-scientific or fixture jobs")
        if (
            not isinstance(job["attemptId"], str)
            or ATTEMPT_ID.fullmatch(job["attemptId"]) is None
        ):
            raise WorkerError("worker attemptId is invalid")
    model = job["model"]
    model_fields = {"key", "files", "layers", "vocabSize", "candidateBitsByLayer"}
    if not isinstance(model, dict) or set(model) != model_fields:
        raise WorkerError("worker model binding fields differ")
    if not isinstance(model["key"], str) or not model["key"]:
        raise WorkerError("worker model key is invalid")
    if type(model["vocabSize"]) is not int or not 1 <= model["vocabSize"] <= 2**32:
        raise WorkerError("worker model vocabulary size is invalid")
    files = model["files"]
    required_files = {
        "config.json",
        "generation_config.json",
        "merges.txt",
        "model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    }
    if not isinstance(files, dict) or set(files) != required_files:
        raise WorkerError("worker model asset set differs")
    for filename, specification in files.items():
        if not isinstance(specification, dict) or set(specification) != {
            "path",
            "bytes",
            "sha256",
        }:
            raise WorkerError(f"worker asset binding differs: {filename}")
        _safe_relative(specification["path"], f"worker asset {filename}")
    layers = model["layers"]
    schedule = model["candidateBitsByLayer"]
    if (
        type(layers) is not int
        or layers < 3
        or not isinstance(schedule, list)
        or len(schedule) != layers
        or any(type(bits) is not int or bits not in {8, 9} for bits in schedule)
    ):
        raise WorkerError("worker model layer schedule differs")
    if development:
        binding = DEVELOPMENT_MODEL_BINDINGS.get(model["key"])
        if binding is None:
            raise WorkerError("development worker model identity differs")
        expected_schedule = [
            9 if index in {0, binding["layers"] // 3} else 8
            for index in range(binding["layers"])
        ]
        if (
            model["layers"] != binding["layers"]
            or model["vocabSize"] != binding["vocabSize"]
            or schedule != expected_schedule
        ):
            raise WorkerError("development worker model geometry differs")
        for filename, (expected_bytes, expected_sha256) in binding["files"].items():
            if files[filename] != {
                "path": f"models/{model['key']}/{filename}",
                "bytes": expected_bytes,
                "sha256": expected_sha256,
            }:
                raise WorkerError(
                    f"development worker model asset differs: {model['key']}/{filename}"
                )
    candidate = job["candidate"]
    if candidate != {
        "backend": "voidtoken-v5",
        "groupSize": 128,
        "transformBlockSize": 128,
        "codeCompression": "zlib-9",
        "scaleCompression": "zlib-9",
        "signMode": "none",
    }:
        raise WorkerError("worker candidate differs from the frozen profile")
    corpora = job["selectedCorpora"]
    pages = job["pages"]
    if development:
        if (
            corpora != [DEVELOPMENT_DATASET_ID]
            or not isinstance(pages, dict)
            or list(pages) != [DEVELOPMENT_DATASET_ID]
        ):
            raise WorkerError("development worker dataset binding differs")
    elif (
        not isinstance(corpora, list)
        or len(corpora) != 2
        or len(set(corpora)) != 2
        or not isinstance(pages, dict)
        or set(pages) != set(corpora)
    ):
        raise WorkerError("worker selected corpus binding differs")
    for corpus in corpora:
        records = pages[corpus]
        expected_records = 32 if development else 16
        if not isinstance(records, list) or len(records) != expected_records:
            raise WorkerError("worker corpus page count differs")
        revisions: set[int] = set()
        previous_sentence_end = 0
        for page_index, page in enumerate(records):
            page_fields = (
                {
                    "pageSelectionIndex",
                    "sourceSliceIndex",
                    "sentenceStart",
                    "sentenceEnd",
                    "recordPath",
                    "recordBytes",
                    "recordSHA256",
                }
                if development
                else {
                    "pageSelectionIndex",
                    "pageRevisionId",
                    "recordPath",
                    "recordBytes",
                    "recordSHA256",
                }
            )
            if not isinstance(page, dict) or set(page) != page_fields:
                raise WorkerError("worker page binding fields differ")
            if page["pageSelectionIndex"] != page_index:
                raise WorkerError("worker pages are not in selection order")
            if development:
                if (
                    page["sourceSliceIndex"] != page_index
                    or type(page["sentenceStart"]) is not int
                    or type(page["sentenceEnd"]) is not int
                    or page["sentenceStart"]
                    != DEVELOPMENT_DATASET_SENTENCES * page_index // 32
                    or page["sentenceEnd"]
                    != DEVELOPMENT_DATASET_SENTENCES * (page_index + 1) // 32
                    or page["sentenceStart"] != previous_sentence_end
                    or page["recordPath"]
                    != f"records/ud-english-pud/slice-{page_index:02d}.bin"
                ):
                    raise WorkerError("development worker sentence range differs")
                previous_sentence_end = page["sentenceEnd"]
            else:
                if type(page["pageRevisionId"]) is not int or page["pageRevisionId"] < 1:
                    raise WorkerError("worker page revision is invalid")
                if page["pageRevisionId"] in revisions:
                    raise WorkerError("worker corpus contains a duplicate revision")
                revisions.add(page["pageRevisionId"])
            _safe_relative(page["recordPath"], "worker corpus record")
        if (
            development
            and previous_sentence_end != DEVELOPMENT_DATASET_SENTENCES
        ):
            raise WorkerError("development worker dataset coverage differs")
    if type(job["seed"]) is not int or not 0 <= job["seed"] < 2**32:
        raise WorkerError("worker seed is outside uint32")


def load_frozen_inputs(job: dict[str, Any], snapshot_root: Path):
    development = job["schemaVersion"] == DEVELOPMENT_JOB_SCHEMA
    development_sentences: tuple[CorpusSentence, ...] | None = None
    if development:
        source = job["sourceDataset"]
        dataset_raw = _read_once_beneath(
            snapshot_root,
            source["path"],
            expected_bytes=source["bytes"],
            expected_sha256=source["sha256"],
            maximum_bytes=16 * 1024 * 1024,
        )
        try:
            development_sentences = parse_development_corpus(dataset_raw)
        except DevelopmentCorpusError as error:
            raise WorkerError("development PUD source parsing failed") from error
        if len(development_sentences) != DEVELOPMENT_DATASET_SENTENCES:
            raise WorkerError("development PUD sentence count differs")
    model_bytes: dict[str, bytes] = {}
    for filename, specification in sorted(job["model"]["files"].items()):
        maximum = 2 * 1024 * 1024 * 1024 if filename == "model.safetensors" else 32 * 1024 * 1024
        model_bytes[filename] = _read_once_beneath(
            snapshot_root,
            specification["path"],
            expected_bytes=specification["bytes"],
            expected_sha256=specification["sha256"],
            maximum_bytes=maximum,
        )
    corpus_bytes: dict[str, list[tuple[dict[str, Any], bytes]]] = {}
    for corpus in job["selectedCorpora"]:
        values: list[tuple[dict[str, Any], bytes]] = []
        for page in job["pages"][corpus]:
            record_bytes = _read_once_beneath(
                snapshot_root,
                page["recordPath"],
                expected_bytes=page["recordBytes"],
                expected_sha256=page["recordSHA256"],
                maximum_bytes=64 * 1024 * 1024,
            )
            if development:
                if development_sentences is None:
                    raise WorkerError("development source dataset was not loaded")
                expected_content = "\n\n".join(
                    sentence.text
                    for sentence in development_sentences[
                        page["sentenceStart"] : page["sentenceEnd"]
                    ]
                )
                try:
                    parsed = parse_development_corpus_record(record_bytes)
                    expected_record = serialize_development_corpus_record(
                        sentence_start=page["sentenceStart"],
                        sentence_end=page["sentenceEnd"],
                        content=expected_content,
                    )
                except DevelopmentCorpusError as error:
                    raise WorkerError(
                        "development PUD record parsing failed"
                    ) from error
                if (
                    parsed["datasetId"] != corpus
                    or parsed["sentenceStart"] != page["sentenceStart"]
                    or parsed["sentenceEnd"] != page["sentenceEnd"]
                    or parsed["content"] != expected_content
                    or record_bytes != expected_record
                    or page["sourceSliceIndex"] != page["pageSelectionIndex"]
                ):
                    raise WorkerError(
                        "development PUD identity differs from worker job"
                    )
                raw_input = parsed["content"].encode("utf-8", errors="strict")
            else:
                parsed = parse_record(record_bytes)
                if (
                    parsed["project"] != corpus
                    or parsed["revid"] != page["pageRevisionId"]
                ):
                    raise WorkerError("collected record identity differs from worker job")
                raw_input = (
                    parsed["title"] + "\n\n" + parsed["content"]
                ).encode("utf-8", errors="strict")
            values.append((page, raw_input))
        corpus_bytes[corpus] = values
    return model_bytes, corpus_bytes


def load_model_and_tokenizer(model_bytes: dict[str, bytes]):
    import torch
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

    config_object = _decode_json_bytes(model_bytes["config.json"], "model config")
    model_type = config_object.get("model_type")
    classes = {
        "gpt_neo": (GPTNeoConfig, GPTNeoForCausalLM),
        "llama": (LlamaConfig, LlamaForCausalLM),
        "gpt_bigcode": (GPTBigCodeConfig, GPTBigCodeForCausalLM),
    }
    if model_type not in classes:
        raise WorkerError(f"unsupported registered model_type: {model_type!r}")
    config_class, model_class = classes[model_type]
    config = config_class.from_dict(config_object)
    config._attn_implementation = "eager"
    config.use_cache = True
    model = model_class(config).float().cpu()
    state = load_safetensors(model_bytes["model.safetensors"])
    missing, unexpected = model.load_state_dict(state, strict=False, assign=False)
    allowed_missing = {"lm_head.weight"}
    if set(missing) - allowed_missing:
        raise WorkerError(f"model weights are incomplete: {sorted(set(missing) - allowed_missing)}")
    allowed_unexpected = re.compile(
        r"transformer\.h\.\d+\.attn(?:\.attention)?\.(?:bias|masked_bias)\Z"
    )
    if any(allowed_unexpected.fullmatch(value) is None for value in unexpected):
        raise WorkerError(f"model weights contain unexpected tensors: {unexpected}")
    model.tie_weights()
    if "lm_head.weight" in missing:
        output = model.get_output_embeddings()
        inputs = model.get_input_embeddings()
        if output is None or inputs is None or output.weight.data_ptr() != inputs.weight.data_ptr():
            raise WorkerError("missing lm_head weight was not restored by exact tying")
    del state
    del model_bytes["model.safetensors"]
    gc.collect()
    model.eval()
    for parameter in model.parameters():
        if parameter.device.type != "cpu" or parameter.dtype != torch.float32:
            raise WorkerError("model execution weights are not CPU float32")
        if not torch.isfinite(parameter).all():
            raise WorkerError("model weights contain a non-finite value")
    tokenizer = Tokenizer.from_str(model_bytes["tokenizer.json"].decode("utf-8", errors="strict"))
    return model, tokenizer, config_object


def extract_cache_layers(cache: Any, geometry: dict[str, int | str], torch_module: Any):
    import numpy as np

    if not hasattr(cache, "layers") or len(cache.layers) != int(geometry["layers"]):
        raise WorkerError("model returned an unexpected DynamicCache layer count")
    original: list[np.ndarray] = []
    canonical: list[np.ndarray] = []
    for layer_index, layer in enumerate(cache.layers):
        keys = layer.keys.detach().float().cpu()
        values = layer.values.detach().float().cpu()
        expected = (
            1,
            int(geometry["kvHeads"]),
            PREFILL_TOKENS,
            int(geometry["headDimension"]),
        )
        if tuple(keys.shape) != expected or tuple(values.shape) != expected:
            raise WorkerError(
                f"model cache shape differs at layer {layer_index}: {tuple(keys.shape)}"
            )
        flattened = flatten_kv_numpy(
            keys.numpy(), values.numpy(), geometry, tokens=PREFILL_TOKENS
        )
        original.append(flattened)
        canonical_tensor = torch_module.from_numpy(flattened).to(torch_module.bfloat16)
        canonical.append(
            np.ascontiguousarray(canonical_tensor.float().numpy(), dtype=np.float32)
        )
    return original, canonical


def continuation_logits(
    model: Any,
    input_ids: Any,
    cache: Any,
    *,
    model_type: str,
    torch_module: Any,
) -> Any:
    cached_tokens = int(cache.get_seq_length())
    continuation_tokens = int(input_ids.shape[1])
    positions = torch_module.arange(
        cached_tokens,
        cached_tokens + continuation_tokens,
        dtype=torch_module.long,
        device="cpu",
    )
    kwargs: dict[str, Any] = {
        "past_key_values": cache,
        "attention_mask": torch_module.ones(
            (1, cached_tokens + continuation_tokens), dtype=torch_module.long
        ),
        "position_ids": positions.unsqueeze(0),
        "use_cache": False,
        "return_dict": True,
        "logits_to_keep": 0,
    }
    if model_type == "llama":
        kwargs["cache_position"] = positions
    with torch_module.inference_mode():
        logits = model(input_ids, **kwargs).logits.float().cpu()
    if logits.shape[:2] != (1, PREDICTION_TOKENS) or not torch_module.isfinite(logits).all():
        raise WorkerError("continuation logits are non-finite or have an invalid shape")
    return logits


class EvidenceWriter:
    def __init__(
        self,
        output_root: Path,
        *,
        suite_id: str,
        run_or_attempt_id: str,
        model_key: str,
        development: bool = False,
    ) -> None:
        self.root = output_root
        self.suite_id = suite_id
        self.run_or_attempt_id = run_or_attempt_id
        self.model_key = model_key
        self.development = development
        self.raw_partial = output_root / "raw-token-evidence.jsonl.partial"
        self.container_partial = output_root / "container-evidence.jsonl.partial"
        self.page_token_partial = output_root / "page-token-evidence.jsonl.partial"
        output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.raw_handle = self.raw_partial.open("xb")
        self.container_handle = self.container_partial.open("xb")
        self.page_token_handle = self.page_token_partial.open("xb")

    def append_raw(self, record: dict[str, Any]) -> None:
        self.raw_handle.write(canonical_json_line(record))

    def append_container(self, record: dict[str, Any]) -> None:
        self.container_handle.write(canonical_json_line(record))

    def append_page_token(self, record: dict[str, Any]) -> None:
        self.page_token_handle.write(canonical_json_line(record))

    def write_container(
        self,
        *,
        corpus: str,
        page_index: int,
        source_identity: int,
        layer_index: int,
        dense_bytes: int,
        container: bytes,
    ) -> None:
        source_component = (
            f"slice-{source_identity:02d}"
            if self.development
            else f"revision-{source_identity}"
        )
        relative = (
            PurePosixPath("containers")
            / self.model_key
            / corpus
            / source_component
            / f"layer-{layer_index:02d}.vtl5"
        )
        destination = self.root.joinpath(*relative.parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(container)
            handle.flush()
            os.fsync(handle.fileno())
        identity = (
            {
                "schemaVersion": DEVELOPMENT_CONTAINER_SCHEMA,
                "suiteId": self.suite_id,
                "runId": self.run_or_attempt_id,
                "modelKey": self.model_key,
                "datasetId": corpus,
                "sourceSliceIndex": source_identity,
                "pageSelectionIndex": page_index,
            }
            if self.development
            else {
                "schemaVersion": CONTAINER_SCHEMA,
                "suiteId": self.suite_id,
                "attemptId": self.run_or_attempt_id,
                "modelKey": self.model_key,
                "corpusProject": corpus,
                "pageRevisionId": source_identity,
                "pageSelectionIndex": page_index,
            }
        )
        self.append_container(
            {
                **identity,
                "layerIndex": layer_index,
                "denseBF16Bytes": dense_bytes,
                "containerBytes": len(container),
                "containerSHA256": sha256_bytes(container),
                "relativePath": str(relative),
                "structuralReplay": True,
            }
        )

    def finish(self) -> tuple[Path, Path, Path]:
        for handle in (self.raw_handle, self.container_handle, self.page_token_handle):
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        raw_final = self.root / "raw-token-evidence.jsonl"
        container_final = self.root / "container-evidence.jsonl"
        page_token_final = self.root / "page-token-evidence.jsonl"
        os.replace(self.raw_partial, raw_final)
        os.replace(self.container_partial, container_final)
        os.replace(self.page_token_partial, page_token_final)
        directory = os.open(
            self.root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return raw_final, container_final, page_token_final

    def close_after_failure(self) -> None:
        for handle in (self.raw_handle, self.container_handle, self.page_token_handle):
            try:
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()


def evaluate_page(
    raw_input: bytes,
    *,
    corpus: str,
    page_index: int,
    source_identity: int,
    job: dict[str, Any],
    model: Any,
    tokenizer: Any,
    config_object: dict[str, Any],
    geometry: dict[str, int | str],
    writer: EvidenceWriter,
    codec_root: Path,
) -> dict[str, Any]:
    import numpy as np
    import torch
    import torch.nn.functional as functional

    text = raw_input.decode("utf-8", errors="strict")
    encoded = tokenizer.encode(text, add_special_tokens=False)
    token_ids = encoded.ids
    if len(token_ids) < PAGE_TOKENS:
        raise WorkerError("selected corpus record has fewer than 512 model tokens")
    token_ids = token_ids[:PAGE_TOKENS]
    vocabulary_size = job["model"]["vocabSize"]
    if any(type(value) is not int or not 0 <= value < vocabulary_size for value in token_ids):
        raise WorkerError("tokenizer produced an ID outside the frozen vocabulary")
    development = job["schemaVersion"] == DEVELOPMENT_JOB_SCHEMA
    evidence_identity = (
        {
            "suiteId": job["suiteId"],
            "runId": job["runId"],
            "modelKey": job["model"]["key"],
            "datasetId": corpus,
            "sourceSliceIndex": source_identity,
            "pageSelectionIndex": page_index,
        }
        if development
        else {
            "suiteId": job["suiteId"],
            "attemptId": job["attemptId"],
            "modelKey": job["model"]["key"],
            "corpusProject": corpus,
            "pageRevisionId": source_identity,
            "pageSelectionIndex": page_index,
        }
    )
    writer.append_page_token(
        {
            "schemaVersion": (
                DEVELOPMENT_PAGE_TOKEN_SCHEMA if development else PAGE_TOKEN_SCHEMA
            ),
            **evidence_identity,
            "vocabSize": vocabulary_size,
            "first512TokenIds": token_ids,
            "first512StreamSHA256": sha256_bytes(token_id_stream(token_ids)),
        }
    )
    ids = torch.tensor([token_ids], dtype=torch.long)
    prefix_ids = ids[:, :PREFILL_TOKENS]
    continuation_ids = ids[:, PREFILL_TOKENS:-1]
    targets = ids[:, PREFILL_TOKENS + 1 :]
    with torch.inference_mode():
        prefill = model(
            prefix_ids,
            use_cache=True,
            return_dict=True,
            logits_to_keep=1,
        )
    original, canonical = extract_cache_layers(
        prefill.past_key_values, geometry, torch
    )
    direct_logits = continuation_logits(
        model,
        continuation_ids,
        prefill.past_key_values,
        model_type=str(config_object["model_type"]),
        torch_module=torch,
    )
    rebuilt_original = build_dynamic_cache(
        original,
        geometry,
        model_config=model.config,
        device="cpu",
        torch_module=torch,
        tokens=PREFILL_TOKENS,
    )
    rebuilt_logits = continuation_logits(
        model,
        continuation_ids,
        rebuilt_original,
        model_type=str(config_object["model_type"]),
        torch_module=torch,
    )
    if not torch.equal(direct_logits, rebuilt_logits):
        maximum = float((direct_logits - rebuilt_logits).abs().max().item())
        raise WorkerError(
            f"real-model flatten/rebuild changed exact logits: maxAbs={maximum!r}"
        )
    baseline_cache = build_dynamic_cache(
        canonical,
        geometry,
        model_config=model.config,
        device="cpu",
        torch_module=torch,
        tokens=PREFILL_TOKENS,
    )
    baseline_logits = continuation_logits(
        model,
        continuation_ids,
        baseline_cache,
        model_type=str(config_object["model_type"]),
        torch_module=torch,
    )

    codec_text = str(codec_root)
    if codec_text not in sys.path:
        sys.path.insert(0, codec_text)
    from RealLLM.voidtoken_v5 import VoidTokenV5Backend

    reconstructed: list[np.ndarray] = []
    schedule = job["model"]["candidateBitsByLayer"]
    candidate = job["candidate"]
    container_bytes = 0
    dense_bytes = 0
    for layer_index, trajectory in enumerate(canonical):
        representation = VoidTokenV5Backend.encode(
            trajectory,
            bits=schedule[layer_index],
            group_size=candidate["groupSize"],
            transform_block_size=candidate["transformBlockSize"],
            layer_index=layer_index,
            scale_compression=candidate["scaleCompression"],
            code_compression=candidate["codeCompression"],
            sign_mode=candidate["signMode"],
        )
        container = representation.to_bytes()
        parsed = VoidTokenV5Backend.from_bytes(container)
        if parsed.container != container or not np.array_equal(
            parsed.reconstructed, representation.reconstructed
        ):
            raise WorkerError("VTL5 structural replay changed canonical bytes")
        layer_dense = int(trajectory.size) * 2
        writer.write_container(
            corpus=corpus,
            page_index=page_index,
            source_identity=source_identity,
            layer_index=layer_index,
            dense_bytes=layer_dense,
            container=container,
        )
        reconstructed.append(
            np.ascontiguousarray(parsed.reconstructed, dtype=np.float32)
        )
        dense_bytes += layer_dense
        container_bytes += len(container)
    candidate_cache = build_dynamic_cache(
        reconstructed,
        geometry,
        model_config=model.config,
        device="cpu",
        torch_module=torch,
        tokens=PREFILL_TOKENS,
    )
    candidate_logits = continuation_logits(
        model,
        continuation_ids,
        candidate_cache,
        model_type=str(config_object["model_type"]),
        torch_module=torch,
    )
    vocabulary = int(candidate_logits.shape[-1])
    if vocabulary != vocabulary_size:
        raise WorkerError("model logits vocabulary differs from the frozen vocabulary")
    baseline_losses = functional.cross_entropy(
        baseline_logits.reshape(-1, vocabulary), targets.reshape(-1), reduction="none"
    ).float()
    candidate_losses = functional.cross_entropy(
        candidate_logits.reshape(-1, vocabulary), targets.reshape(-1), reduction="none"
    ).float()
    baseline_top1 = baseline_logits.argmax(dim=-1).reshape(-1)
    candidate_top1 = candidate_logits.argmax(dim=-1).reshape(-1)
    targets_flat = targets.reshape(-1)
    if any(
        value.numel() != PREDICTION_TOKENS
        for value in (baseline_losses, candidate_losses, baseline_top1, candidate_top1)
    ):
        raise WorkerError("per-token evidence does not contain exactly 128 predictions")
    for prediction_index in range(PREDICTION_TOKENS):
        writer.append_raw(
            {
                "schemaVersion": (
                    DEVELOPMENT_RAW_TOKEN_SCHEMA if development else RAW_TOKEN_SCHEMA
                ),
                **evidence_identity,
                "predictionIndex": prediction_index,
                "targetTokenId": int(targets_flat[prediction_index].item()),
                "baselineLossF32Bits": float32_to_bits(
                    float(baseline_losses[prediction_index].item())
                ),
                "candidateLossF32Bits": float32_to_bits(
                    float(candidate_losses[prediction_index].item())
                ),
                "baselineTop1TokenId": int(baseline_top1[prediction_index].item()),
                "candidateTop1TokenId": int(candidate_top1[prediction_index].item()),
            }
        )
    page_delta = math.fsum(
        float(candidate_losses[index].item()) - float(baseline_losses[index].item())
        for index in range(PREDICTION_TOKENS)
    ) / PREDICTION_TOKENS
    page_matches = int((baseline_top1 == candidate_top1).sum().item())
    del (
        ids,
        prefix_ids,
        continuation_ids,
        targets,
        prefill,
        original,
        canonical,
        direct_logits,
        rebuilt_original,
        rebuilt_logits,
        baseline_cache,
        baseline_logits,
        reconstructed,
        candidate_cache,
        candidate_logits,
        baseline_losses,
        candidate_losses,
        baseline_top1,
        candidate_top1,
    )
    gc.collect()
    summary_identity = (
        {
            "datasetId": corpus,
            "pageSelectionIndex": page_index,
            "sourceSliceIndex": source_identity,
        }
        if development
        else {
            "corpusProject": corpus,
            "pageSelectionIndex": page_index,
            "pageRevisionId": source_identity,
        }
    )
    return {
        **summary_identity,
        "denseBF16Bytes": dense_bytes,
        "containerBytes": container_bytes,
        "compressionRatioVsBF16": dense_bytes / container_bytes,
        "deltaNLLNatPerToken": page_delta,
        "top1ExactMatches": page_matches,
    }


def run(job_path: Path, snapshot_root: Path, codec_root: Path, output_root: Path) -> Path:
    job = load_json_strict(job_path)
    validate_job(job)
    if job["schemaVersion"] == DEVELOPMENT_JOB_SCHEMA:
        _guard_development_output_root(output_root)
    install_network_denial()
    import numpy as np
    import torch

    torch.manual_seed(job["seed"])
    np.random.seed(job["seed"])
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True, warn_only=False)
    model_bytes, corpus_bytes = load_frozen_inputs(job, snapshot_root)
    model, tokenizer, config_object = load_model_and_tokenizer(model_bytes)
    observed_config_vocabulary = config_object.get("vocab_size")
    observed_tokenizer_vocabulary = tokenizer.get_vocab_size(with_added_tokens=True)
    if (
        observed_config_vocabulary != job["model"]["vocabSize"]
        or observed_tokenizer_vocabulary != job["model"]["vocabSize"]
    ):
        raise WorkerError("owned model/tokenizer vocabulary differs from the frozen design")
    geometry = geometry_from_config(config_object)
    if int(geometry["layers"]) != job["model"]["layers"]:
        raise WorkerError("observed model geometry differs from its frozen layer count")
    development = job["schemaVersion"] == DEVELOPMENT_JOB_SCHEMA
    run_or_attempt_id = job["runId"] if development else job["attemptId"]
    writer = EvidenceWriter(
        output_root,
        suite_id=job["suiteId"],
        run_or_attempt_id=run_or_attempt_id,
        model_key=job["model"]["key"],
        development=development,
    )
    pages: list[dict[str, Any]] = []
    started = time.monotonic_ns()
    try:
        for corpus in job["selectedCorpora"]:
            for page, raw in corpus_bytes[corpus]:
                pages.append(
                    evaluate_page(
                        raw,
                        corpus=corpus,
                        page_index=page["pageSelectionIndex"],
                        source_identity=(
                            page["sourceSliceIndex"]
                            if development
                            else page["pageRevisionId"]
                        ),
                        job=job,
                        model=model,
                        tokenizer=tokenizer,
                        config_object=config_object,
                        geometry=geometry,
                        writer=writer,
                        codec_root=codec_root,
                    )
                )
                print(
                    f"{job['model']['key']}: {corpus} page "
                    f"{page['pageSelectionIndex'] + 1}/"
                    f"{32 if development else 16} complete",
                    flush=True,
                )
        raw_path, container_path, page_token_path = writer.finish()
    except BaseException:
        writer.close_after_failure()
        raise
    summary = {
        "schemaVersion": (
            DEVELOPMENT_SUMMARY_SCHEMA
            if development
            else "corelm-crossmodel-livewiki-v4-worker-summary-v1"
        ),
        "suiteId": job["suiteId"],
        ("runId" if development else "attemptId"): run_or_attempt_id,
        "modelKey": job["model"]["key"],
        "geometry": geometry,
        "pages": pages,
        "rawTokenEvidence": {
            "path": raw_path.name,
            "bytes": raw_path.stat().st_size,
            "sha256": sha256_bytes(raw_path.read_bytes()),
        },
        "containerEvidence": {
            "path": container_path.name,
            "bytes": container_path.stat().st_size,
            "sha256": sha256_bytes(container_path.read_bytes()),
        },
        "pageTokenEvidence": {
            "path": page_token_path.name,
            "bytes": page_token_path.stat().st_size,
            "sha256": sha256_bytes(page_token_path.read_bytes()),
        },
        "durationNanoseconds": time.monotonic_ns() - started,
        "networkUsed": False,
        "modelLoad": "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained",
        "countsTowardScientificVerdict": not development,
    }
    if development:
        summary.update(
            {
                "usedForCandidateSelectionOrTuning": False,
                "scientificAttemptStateCreated": False,
                "nistUsed": False,
                "futureCorpusUsed": False,
                "controlConfigurationSHA256": job["controlConfigurationSHA256"],
            }
        )
    summary_path = output_root / "worker-summary.json"
    with summary_path.open("xb") as handle:
        handle.write(canonical_json_bytes(summary) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    return summary_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--codec-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    summary = run(
        arguments.job,
        arguments.snapshot_root,
        arguments.codec_root,
        arguments.output_root,
    )
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
