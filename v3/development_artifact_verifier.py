"""Strict offline semantic verifier for the real-data development E2E archive.

This module deliberately does not import the producer or the real-model replay
implementation.  It re-opens the archived bytes, independently parses the
pinned UD English PUD CoNLL-U source, reconstructs the deterministic records
and jobs, validates every evidence stream and VTL5 envelope,
and recomputes every digest published by the independent replay summary.

The verifier does not claim to replace a fresh model inference.  It proves that
the archived PASS report is internally bound to the exact pinned dataset,
model-asset receipt, jobs, token/loss evidence, containers, worker summaries,
and consolidated evidence bytes that the real-model replay attested to.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence


class DevelopmentArtifactVerificationError(ValueError):
    """The development archive is malformed or semantically inconsistent."""


MODEL_KEYS = ("gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py")
MODEL_FILES = (
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
)
SUITE_ID = "corelm-voidtoken-crossmodel-v3-author-verified-development-e2e"
DATASET_ID = "UniversalDependencies/UD_English-PUD:r2.18:test"
DATASET_PATH = "inputs/corpus/en_pud-ud-test.conllu"
FULL_ASSET_RECEIPT_PATH = "inputs/model-assets.full-rehash.json"
DATASET_BYTES = 1_386_858
DATASET_SHA256 = "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa"
DATASET_SENTENCES = 1_000
DATASET_REPOSITORY = "UniversalDependencies/UD_English-PUD"
DATASET_RELEASE_TAG = "r2.18"
DATASET_REVISION = "e173a1be1b442faf34e7d5a502189ad5d9d1e197"
DATASET_TREE = "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde"
DATASET_SPLIT = "test"
DATASET_FILE = "en_pud-ud-test.conllu"
JOINED_TEXT_BYTES = 112_419
JOINED_TEXT_SHA256 = "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea"
RECORD_MAGIC = b"CORELM-UD-ENGLISH-PUD-R2.18-DEVELOPMENT-RECORD\0"
CORPUS_MANIFEST_PATH = "inputs/development-corpus.draft.json"
LICENSE_SOURCE_PATH = "inputs/LICENSES/source-evidence.json"
LICENSE_MATRIX_PATH = "inputs/LICENSES/ASSET_LICENSES.md"
PUD_README_PATH = "inputs/LICENSES/upstream/ud-english-pud-r2.18-README.md"
PUD_LICENSE_PATH = "inputs/LICENSES/upstream/ud-english-pud-r2.18-LICENSE.txt"
PUD_ATTRIBUTION_PATH = "inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md"
PUD_README_BYTES = 6_986
PUD_README_SHA256 = "9558eb70a6565a40e2ecf06d0f38c9f6117de0f0f8bc5021805bdce51ee0d67f"
PUD_LICENSE_BYTES = 19_556
PUD_LICENSE_SHA256 = "b278eb53fe50b8bb7fa0d90fb8536c35fdcaa80f9d63812cb51db539555d2a89"
PUD_ATTRIBUTION_BYTES = 2_056
PUD_ATTRIBUTION_SHA256 = "296ebce07660b5f37cf99729f0a2be86d5e183021149a9993e9db0f59ddcb9da"
PAGES_PER_MODEL = 32
PAGE_TOKENS = 512
PREFILL_TOKENS = 383
PREDICTIONS_PER_PAGE = 128
RAW_TOKEN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-raw-token-v1"
PAGE_TOKEN_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-page-token-v1"
CONTAINER_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-container-v1"
WORKER_SUMMARY_SCHEMA = (
    "corelm-crossmodel-v3-real-e2e-development-worker-summary-v1"
)
JOB_SCHEMA = "corelm-crossmodel-v3-real-e2e-development-worker-job-v1"
ASSET_RECEIPT_SCHEMA = "corelm-crossmodel-livewiki-v3-asset-receipt-v1"
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
FLOAT32_BITS = re.compile(r"[0-9a-f]{8}\Z")
CONLLU_TOKEN_ID = re.compile(r"[1-9][0-9]*(?:-[1-9][0-9]*|\.[1-9][0-9]*)?\Z")

MODEL_IDENTITIES: dict[str, dict[str, Any]] = {
    "gpt-neo-125m": {
        "repository": "EleutherAI/gpt-neo-125m",
        "revision": "21def0189f5705e2521767faed922f1f15e7d7db",
        "layers": 12,
        "vocabSize": 50_257,
    },
    "smollm2-360m": {
        "repository": "HuggingFaceTB/SmolLM2-360M",
        "revision": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
        "layers": 32,
        "vocabSize": 49_152,
    },
    "tiny-starcoder-py": {
        "repository": "bigcode/tiny_starcoder_py",
        "revision": "8547527bef0bc927268c1653cce6948c5c242dd1",
        "layers": 20,
        "vocabSize": 49_152,
    },
}

MODEL_GEOMETRIES: dict[str, dict[str, Any]] = {
    "gpt-neo-125m": {
        "modelType": "gpt_neo",
        "attentionLayout": "mixed-global-local",
        "layers": 12,
        "attentionHeads": 12,
        "kvHeads": 12,
        "headDimension": 64,
        "hiddenSize": 768,
        "trajectoryWidth": 1_536,
    },
    "smollm2-360m": {
        "modelType": "llama",
        "attentionLayout": "grouped-query",
        "layers": 32,
        "attentionHeads": 15,
        "kvHeads": 5,
        "headDimension": 64,
        "hiddenSize": 960,
        "trajectoryWidth": 640,
    },
    "tiny-starcoder-py": {
        "modelType": "gpt_bigcode",
        "attentionLayout": "multi-query",
        "layers": 20,
        "attentionHeads": 12,
        "kvHeads": 1,
        "headDimension": 64,
        "hiddenSize": 768,
        "trajectoryWidth": 128,
    },
}

CANDIDATE = {
    "backend": "voidtoken-v5",
    "groupSize": 128,
    "transformBlockSize": 128,
    "codeCompression": "zlib-9",
    "scaleCompression": "zlib-9",
    "signMode": "none",
}

ReadBound = Callable[[str, int], bytes]


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise DevelopmentArtifactVerificationError(
            "value is not canonical finite JSON"
        ) from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DevelopmentArtifactVerificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise DevelopmentArtifactVerificationError(f"non-finite JSON value: {value}")


def _strict_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except DevelopmentArtifactVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DevelopmentArtifactVerificationError(f"invalid JSON: {label}") from error


def _canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise DevelopmentArtifactVerificationError(
            f"canonical JSON lacks terminal LF: {label}"
        )
    value = _strict_json(raw[:-1], label=label)
    if not isinstance(value, dict) or _canonical_json_bytes(value) + b"\n" != raw:
        raise DevelopmentArtifactVerificationError(
            f"non-canonical JSON object: {label}"
        )
    return value


def _canonical_jsonl(raw: bytes, *, label: str) -> list[dict[str, Any]]:
    if not raw or not raw.endswith(b"\n"):
        raise DevelopmentArtifactVerificationError(
            f"canonical JSONL lacks terminal LF: {label}"
        )
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise DevelopmentArtifactVerificationError(
                f"blank JSONL line: {label}:{line_number}"
            )
        value = _strict_json(line, label=f"{label}:{line_number}")
        if not isinstance(value, dict) or _canonical_json_bytes(value) != line:
            raise DevelopmentArtifactVerificationError(
                f"non-canonical JSONL object: {label}:{line_number}"
            )
        values.append(value)
    return values


def _safe_relative(value: Any, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DevelopmentArtifactVerificationError(f"invalid relative path: {label}")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise DevelopmentArtifactVerificationError(f"unsafe relative path: {label}")
    return relative


def _normalise_inventory(
    value: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    items = value.values() if isinstance(value, Mapping) else value
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {"path", "bytes", "sha256"}:
            raise DevelopmentArtifactVerificationError(
                "development artifact inventory record differs"
            )
        path = item["path"]
        _safe_relative(path, label="artifact inventory")
        if (
            path in result
            or type(item["bytes"]) is not int
            or item["bytes"] < 1
            or not isinstance(item["sha256"], str)
            or HEX_64.fullmatch(item["sha256"]) is None
        ):
            raise DevelopmentArtifactVerificationError(
                "development artifact inventory commitment differs"
            )
        result[path] = dict(item)
    return result


def _filesystem_reader(
    root: Path, inventory: Mapping[str, Mapping[str, Any]]
) -> ReadBound:
    absolute_root = Path(os.path.abspath(os.fspath(root)))

    def read(relative_value: str, maximum_bytes: int) -> bytes:
        relative = _safe_relative(relative_value, label="development artifact")
        commitment = inventory.get(relative.as_posix())
        if commitment is None:
            raise DevelopmentArtifactVerificationError(
                f"development artifact is absent: {relative}"
            )
        if (
            type(maximum_bytes) is not int
            or maximum_bytes < 1
            or commitment["bytes"] > maximum_bytes
        ):
            raise DevelopmentArtifactVerificationError(
                f"development artifact exceeds byte bound: {relative}"
            )
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            directory = os.open(absolute_root, directory_flags)
        except OSError as error:
            raise DevelopmentArtifactVerificationError(
                "development artifact root cannot be opened safely"
            ) from error
        try:
            for component in relative.parts[:-1]:
                next_directory = os.open(
                    component, directory_flags, dir_fd=directory
                )
                metadata = os.fstat(next_directory)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_directory)
                    raise DevelopmentArtifactVerificationError(
                        "development artifact parent is not a directory"
                    )
                os.close(directory)
                directory = next_directory
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(relative.parts[-1], flags, dir_fd=directory)
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size != commitment["bytes"]
                    or before.st_size > maximum_bytes
                ):
                    raise DevelopmentArtifactVerificationError(
                        f"development artifact metadata differs: {relative}"
                    )
                chunks: list[bytes] = []
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise DevelopmentArtifactVerificationError(
                            f"development artifact was truncated: {relative}"
                        )
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
                    raise DevelopmentArtifactVerificationError(
                        f"development artifact changed while reading: {relative}"
                    )
                if digest.hexdigest() != commitment["sha256"]:
                    raise DevelopmentArtifactVerificationError(
                        f"development artifact SHA-256 differs: {relative}"
                    )
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise DevelopmentArtifactVerificationError(
                f"development artifact path is unsafe or absent: {relative}"
            ) from error
        finally:
            os.close(directory)

    return read


def _checked_reader(
    reader: ReadBound, inventory: Mapping[str, Mapping[str, Any]]
) -> ReadBound:
    def read(relative: str, maximum_bytes: int) -> bytes:
        commitment = inventory.get(relative)
        if commitment is None:
            raise DevelopmentArtifactVerificationError(
                f"development artifact is absent: {relative}"
            )
        raw = reader(relative, maximum_bytes)
        if not isinstance(raw, bytes):
            raise DevelopmentArtifactVerificationError(
                f"development artifact reader returned non-bytes: {relative}"
            )
        if (
            len(raw) != commitment["bytes"]
            or len(raw) > maximum_bytes
            or _sha256(raw) != commitment["sha256"]
        ):
            raise DevelopmentArtifactVerificationError(
                f"development artifact differs from inventory: {relative}"
            )
        return raw

    return read


def _record_field(value: str) -> bytes:
    raw = value.encode("utf-8", errors="strict")
    return struct.pack(">Q", len(raw)) + raw


def _serialize_record(
    *, sentence_start: int, sentence_end: int, content: str
) -> bytes:
    if (
        type(sentence_start) is not int
        or type(sentence_end) is not int
        or sentence_start < 0
        or sentence_end <= sentence_start
        or sentence_end > DATASET_SENTENCES
    ):
        raise DevelopmentArtifactVerificationError("PUD sentence range is invalid")
    if not isinstance(content, str) or not content:
        raise DevelopmentArtifactVerificationError("PUD record content is empty")
    return b"".join(
        (
            RECORD_MAGIC,
            _record_field(DATASET_ID),
            _record_field(DATASET_REPOSITORY),
            _record_field(DATASET_RELEASE_TAG),
            _record_field(DATASET_REVISION),
            _record_field(DATASET_TREE),
            _record_field(DATASET_SPLIT),
            _record_field(DATASET_FILE),
            _record_field(DATASET_SHA256),
            _record_field(JOINED_TEXT_SHA256),
            struct.pack(">Q", sentence_start),
            struct.pack(">Q", sentence_end),
            _record_field(content),
        )
    )


def _token_stream(token_ids: Sequence[int]) -> bytes:
    if any(type(item) is not int or not 0 <= item <= 2**32 - 1 for item in token_ids):
        raise DevelopmentArtifactVerificationError("token stream contains non-uint32 ID")
    return struct.pack("<Q", len(token_ids)) + b"".join(
        struct.pack("<I", item) for item in token_ids
    )


def _float32(value: Any, *, label: str) -> float:
    if not isinstance(value, str) or FLOAT32_BITS.fullmatch(value) is None:
        raise DevelopmentArtifactVerificationError(f"{label} is not float32 bits")
    result = struct.unpack(">f", bytes.fromhex(value))[0]
    if not math.isfinite(result) or result < 0.0:
        raise DevelopmentArtifactVerificationError(f"{label} is not finite non-negative")
    return float(result)


def _digest_record(value: Any, *, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"bytes", "sha256"}
        or type(value["bytes"]) is not int
        or value["bytes"] < 1
        or not isinstance(value["sha256"], str)
        or HEX_64.fullmatch(value["sha256"]) is None
    ):
        raise DevelopmentArtifactVerificationError(f"{label} commitment differs")
    return dict(value)


def _decode_dataset(raw: bytes) -> list[dict[str, str]]:
    """Independently parse the exact pinned CoNLL-U source.

    This intentionally duplicates the producer's parsing contract instead of
    importing it.  The verifier accepts strict UTF-8, LF-only bytes, exactly
    one ``sent_id`` and one ``text`` comment before token rows in every block,
    and ten-column CoNLL-U token rows.
    """

    if len(raw) != DATASET_BYTES or _sha256(raw) != DATASET_SHA256:
        raise DevelopmentArtifactVerificationError("pinned PUD bytes differ")
    if (
        raw.startswith(b"\xef\xbb\xbf")
        or b"\r" in raw
        or b"\x00" in raw
        or not raw.endswith(b"\n\n")
        or raw.endswith(b"\n\n\n")
    ):
        raise DevelopmentArtifactVerificationError("pinned PUD byte framing differs")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentArtifactVerificationError(
            "pinned PUD source is not strict UTF-8"
        ) from error

    blocks = raw[:-2].split(b"\n\n")
    if len(blocks) != DATASET_SENTENCES or any(not block for block in blocks):
        raise DevelopmentArtifactVerificationError("pinned PUD block count differs")
    sentences: list[dict[str, str]] = []
    sent_ids: set[str] = set()
    for index, block in enumerate(blocks):
        try:
            lines = block.decode("utf-8", errors="strict").split("\n")
        except UnicodeDecodeError as error:
            raise DevelopmentArtifactVerificationError(
                f"PUD sentence block is not strict UTF-8: {index}"
            ) from error
        if not lines or any(not line for line in lines):
            raise DevelopmentArtifactVerificationError(
                f"PUD sentence block is malformed: {index}"
            )
        sent_id_values: list[str] = []
        text_values: list[str] = []
        token_seen = False
        syntactic_tokens = 0
        for line in lines:
            if line.startswith("#"):
                if token_seen or not line.startswith("# "):
                    raise DevelopmentArtifactVerificationError(
                        f"PUD sentence metadata placement differs: {index}"
                    )
                if line.startswith("# sent_id"):
                    if not line.startswith("# sent_id = "):
                        raise DevelopmentArtifactVerificationError(
                            f"PUD sent_id metadata is malformed: {index}"
                        )
                    sent_id_values.append(line.removeprefix("# sent_id = "))
                if line.startswith("# text"):
                    if not line.startswith("# text = "):
                        raise DevelopmentArtifactVerificationError(
                            f"PUD text metadata is malformed: {index}"
                        )
                    text_values.append(line.removeprefix("# text = "))
                continue
            token_seen = True
            fields = line.split("\t")
            if len(fields) != 10 or CONLLU_TOKEN_ID.fullmatch(fields[0]) is None:
                raise DevelopmentArtifactVerificationError(
                    f"PUD token row is malformed: {index}"
                )
            if "-" not in fields[0] and "." not in fields[0]:
                syntactic_tokens += 1
        if (
            len(sent_id_values) != 1
            or len(text_values) != 1
            or not sent_id_values[0]
            or sent_id_values[0].strip() != sent_id_values[0]
            or sent_id_values[0] in sent_ids
            or not text_values[0]
            or syntactic_tokens == 0
        ):
            raise DevelopmentArtifactVerificationError(
                f"PUD sentence metadata differs: {index}"
            )
        sent_ids.add(sent_id_values[0])
        sentences.append(
            {
                "sentId": sent_id_values[0],
                "text": text_values[0],
                "blockSHA256": _sha256(block),
            }
        )

    joined = b"\n\n".join(
        sentence["text"].encode("utf-8", errors="strict")
        for sentence in sentences
    )
    if len(joined) != JOINED_TEXT_BYTES or _sha256(joined) != JOINED_TEXT_SHA256:
        raise DevelopmentArtifactVerificationError("joined PUD text differs")
    return sentences


def _read_input_binding(
    plan: Mapping[str, Any],
    reader: ReadBound,
    *,
    binding: str,
    path: str,
    maximum_bytes: int,
) -> bytes:
    bindings = plan.get("inputBindings")
    commitment = bindings.get(binding) if isinstance(bindings, Mapping) else None
    expected = _digest_record(commitment, label=f"input binding {binding}")
    raw = reader(path, maximum_bytes)
    if expected != {"bytes": len(raw), "sha256": _sha256(raw)}:
        raise DevelopmentArtifactVerificationError(
            f"input binding bytes differ: {binding}"
        )
    return raw


def _validate_pud_inputs(
    *,
    plan: Mapping[str, Any],
    reader: ReadBound,
    dataset_raw: bytes,
    sentences: Sequence[Mapping[str, str]],
) -> None:
    """Verify the corpus manifest, decode bindings, and archived rights bytes."""

    bindings = plan.get("inputBindings")
    if not isinstance(bindings, Mapping):
        raise DevelopmentArtifactVerificationError("input bindings are absent")
    dataset_digest = {"bytes": DATASET_BYTES, "sha256": DATASET_SHA256}
    joined = b"\n\n".join(
        sentence["text"].encode("utf-8", errors="strict")
        for sentence in sentences
    )
    if (
        bindings.get("developmentDataset") != dataset_digest
        or bindings.get("joinedCorpusText")
        != {"bytes": JOINED_TEXT_BYTES, "sha256": JOINED_TEXT_SHA256}
        or bindings.get("conlluDecode")
        != {
            "parser": "strict-stdlib-conllu-text-v1",
            "sentences": DATASET_SENTENCES,
            "sourceConlluSHA256": DATASET_SHA256,
        }
        or len(dataset_raw) != DATASET_BYTES
        or _sha256(dataset_raw) != DATASET_SHA256
        or len(joined) != JOINED_TEXT_BYTES
        or _sha256(joined) != JOINED_TEXT_SHA256
    ):
        raise DevelopmentArtifactVerificationError("PUD decode binding differs")

    manifest_raw = _read_input_binding(
        plan,
        reader,
        binding="developmentCorpusManifest",
        path=CORPUS_MANIFEST_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    manifest = _strict_json(manifest_raw, label="development corpus manifest")
    expected_manifest_fields = {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-development-corpus-v1",
        "status": "PINNED_REAL_CORPUS_WITH_EXPLICIT_REDISTRIBUTION_LICENSE",
        "queriedAtUTC": "2026-08-03T23:02:05Z",
        "datasetId": DATASET_ID,
        "repository": DATASET_REPOSITORY,
        "revision": DATASET_REVISION,
        "tree": DATASET_TREE,
        "releaseTag": DATASET_RELEASE_TAG,
        "split": DATASET_SPLIT,
        "splitPurpose": (
            "upstream test split reused only as a non-scientific development "
            "control; it is not a blind scientific test result"
        ),
        "file": DATASET_FILE,
        "format": "CoNLL-U",
        "bytes": DATASET_BYTES,
        "sha256": DATASET_SHA256,
        "sourceURL": (
            "https://raw.githubusercontent.com/UniversalDependencies/"
            f"UD_English-PUD/{DATASET_REVISION}/{DATASET_FILE}"
        ),
        "rows": DATASET_SENTENCES,
        "rowExtraction": (
            "exactly one '# text = ' value from each LF-delimited CoNLL-U "
            "sentence block; prefix removed; text otherwise unchanged"
        ),
        "joinedTextBytes": JOINED_TEXT_BYTES,
        "joinedTextSHA256": JOINED_TEXT_SHA256,
        "contentSynthetic": False,
        "license": "CC-BY-SA-3.0",
    }
    if not isinstance(manifest, dict) or any(
        manifest.get(key) != value for key, value in expected_manifest_fields.items()
    ):
        raise DevelopmentArtifactVerificationError(
            "development corpus manifest identity differs"
        )
    if manifest.get("readme") != {
        "path": "README.md",
        "bytes": PUD_README_BYTES,
        "sha256": PUD_README_SHA256,
        "url": (
            "https://raw.githubusercontent.com/UniversalDependencies/"
            f"UD_English-PUD/{DATASET_REVISION}/README.md"
        ),
    } or manifest.get("licenseFile") != {
        "path": "LICENSE.txt",
        "bytes": PUD_LICENSE_BYTES,
        "sha256": PUD_LICENSE_SHA256,
        "url": (
            "https://raw.githubusercontent.com/UniversalDependencies/"
            f"UD_English-PUD/{DATASET_REVISION}/LICENSE.txt"
        ),
    } or manifest.get("redistributionObligations") != {
        "attributionRequired": True,
        "shareAlikeRequired": True,
        "licenseNoticeRequired": True,
        "upstreamWarranty": "none",
    }:
        raise DevelopmentArtifactVerificationError(
            "development corpus rights manifest differs"
        )

    source_raw = _read_input_binding(
        plan,
        reader,
        binding="licenseSourceEvidence",
        path=LICENSE_SOURCE_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    matrix_raw = _read_input_binding(
        plan,
        reader,
        binding="assetLicenseMatrix",
        path=LICENSE_MATRIX_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    readme_raw = _read_input_binding(
        plan,
        reader,
        binding="udEnglishPudReadme",
        path=PUD_README_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    license_raw = _read_input_binding(
        plan,
        reader,
        binding="udEnglishPudLicense",
        path=PUD_LICENSE_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    attribution_raw = _read_input_binding(
        plan,
        reader,
        binding="udEnglishPudAttribution",
        path=PUD_ATTRIBUTION_PATH,
        maximum_bytes=4 * 1024 * 1024,
    )
    if (
        len(readme_raw) != PUD_README_BYTES
        or _sha256(readme_raw) != PUD_README_SHA256
        or len(license_raw) != PUD_LICENSE_BYTES
        or _sha256(license_raw) != PUD_LICENSE_SHA256
        or len(attribution_raw) != PUD_ATTRIBUTION_BYTES
        or _sha256(attribution_raw) != PUD_ATTRIBUTION_SHA256
    ):
        raise DevelopmentArtifactVerificationError("PUD rights bytes differ")

    source = _strict_json(source_raw, label="license source evidence")
    expected_sources = {
        "UD English PUD development corpus README": {
            "component": "UD English PUD development corpus README",
            "repository": DATASET_REPOSITORY,
            "revision": DATASET_REVISION,
            "relativePath": "README.md",
            "archivedPath": "upstream/ud-english-pud-r2.18-README.md",
            "archivedEncoding": "identity",
            "url": (
                "https://raw.githubusercontent.com/UniversalDependencies/"
                f"UD_English-PUD/{DATASET_REVISION}/README.md"
            ),
            "bytes": PUD_README_BYTES,
            "sha256": PUD_README_SHA256,
            "declaredLicense": "CC-BY-SA-3.0",
        },
        "UD English PUD development corpus license": {
            "component": "UD English PUD development corpus license",
            "repository": DATASET_REPOSITORY,
            "revision": DATASET_REVISION,
            "relativePath": "LICENSE.txt",
            "archivedPath": "upstream/ud-english-pud-r2.18-LICENSE.txt",
            "archivedEncoding": "identity",
            "url": (
                "https://raw.githubusercontent.com/UniversalDependencies/"
                f"UD_English-PUD/{DATASET_REVISION}/LICENSE.txt"
            ),
            "bytes": PUD_LICENSE_BYTES,
            "sha256": PUD_LICENSE_SHA256,
            "declaredLicense": "CC-BY-SA-3.0",
        },
    }
    observed_sources: dict[str, Any] = {}
    source_items = source.get("sources") if isinstance(source, dict) else None
    if (
        not isinstance(source, dict)
        or source.get("schemaVersion")
        != "corelm-crossmodel-livewiki-v2-license-source-evidence-v1"
        or source.get("status") != "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED"
        or not isinstance(source_items, list)
    ):
        raise DevelopmentArtifactVerificationError("PUD source evidence differs")
    for item in source_items:
        component = item.get("component") if isinstance(item, dict) else None
        if component in expected_sources:
            if component in observed_sources:
                raise DevelopmentArtifactVerificationError(
                    "PUD source evidence is duplicated"
                )
            observed_sources[component] = item
    try:
        readme_text = readme_raw.decode("utf-8", errors="strict")
        license_text = license_raw.decode("utf-8", errors="strict")
        attribution_text = attribution_raw.decode("utf-8", errors="strict")
        matrix_text = matrix_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentArtifactVerificationError(
            "PUD rights evidence is not strict UTF-8"
        ) from error
    if (
        observed_sources != expected_sources
        or readme_text.count("License: CC BY-SA 3.0") != 1
        or readme_text.count("Includes text: yes") != 1
        or readme_text.count(
            "GOOGLE MAKES THEM AVAILABLE TO YOU under CC-BY-SA 3.0"
        )
        != 1
        or "https://creativecommons.org/licenses/by-sa/3.0/" not in license_text
        or "Attribution-ShareAlike 3.0" not in license_text
        or DATASET_RELEASE_TAG not in attribution_text
        or DATASET_REVISION not in attribution_text
        or DATASET_TREE not in attribution_text
        or DATASET_SHA256 not in attribution_text
        or "No endorsement" not in attribution_text
        or "UD English PUD" not in matrix_text
        or "CC BY-SA 3.0" not in matrix_text
        or "without added restrictions" not in matrix_text
    ):
        raise DevelopmentArtifactVerificationError(
            "PUD rights declaration or attribution differs"
        )


def _validate_asset_receipt(plan: Mapping[str, Any], raw: bytes) -> None:
    receipt = _canonical_line(raw, label="archived full asset receipt")
    if (
        receipt.get("schemaVersion") != ASSET_RECEIPT_SCHEMA
        or receipt.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED"
        or receipt.get("countsTowardScientificVerdict") is not False
        or receipt.get("networkUsed") is not False
        or receipt.get("modelInferenceUsed") is not False
        or receipt.get("assetLayout")
        != "<asset-root>/<model-key>/<manifest-relative-file>"
        or receipt.get("fileCount") != len(MODEL_KEYS) * len(MODEL_FILES)
        or receipt.get("fullSafetensorsBytesLocallyVerified") is not True
    ):
        raise DevelopmentArtifactVerificationError("full asset receipt boundary differs")
    receipt_models = receipt.get("models")
    plan_models = plan.get("models")
    if (
        not isinstance(receipt_models, dict)
        or tuple(receipt_models) != MODEL_KEYS
        or not isinstance(plan_models, list)
        or [item.get("key") if isinstance(item, dict) else None for item in plan_models]
        != list(MODEL_KEYS)
    ):
        raise DevelopmentArtifactVerificationError("model order differs")
    private = plan.get("privateFiles")
    if not isinstance(private, list):
        raise DevelopmentArtifactVerificationError("private input inventory is absent")
    private_by_path: dict[str, Mapping[str, Any]] = {}
    for item in private:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise DevelopmentArtifactVerificationError("private input record differs")
        if item["path"] in private_by_path:
            raise DevelopmentArtifactVerificationError("duplicate private input path")
        private_by_path[item["path"]] = item
    for model in plan_models:
        key = model["key"]
        identity = MODEL_IDENTITIES[key]
        receipt_model = receipt_models[key]
        if (
            not isinstance(receipt_model, dict)
            or receipt_model.get("repository") != identity["repository"]
            or receipt_model.get("revision") != identity["revision"]
            or model.get("repository") != identity["repository"]
            or model.get("revision") != identity["revision"]
            or model.get("layers") != identity["layers"]
            or model.get("vocabSize") != identity["vocabSize"]
            or not isinstance(receipt_model.get("files"), dict)
            or tuple(receipt_model["files"]) != MODEL_FILES
            or not isinstance(model.get("files"), dict)
            or tuple(model["files"]) != MODEL_FILES
        ):
            raise DevelopmentArtifactVerificationError(
                f"model/receipt identity differs: {key}"
            )
        for filename in MODEL_FILES:
            receipt_file = _digest_record(
                receipt_model["files"][filename],
                label=f"receipt model asset {key}/{filename}",
            )
            plan_file = model["files"][filename]
            expected_path = f"models/{key}/{filename}"
            if (
                not isinstance(plan_file, Mapping)
                or set(plan_file) != {"path", "bytes", "sha256"}
                or plan_file.get("path") != expected_path
                or {name: plan_file[name] for name in ("bytes", "sha256")}
                != receipt_file
                or private_by_path.get(expected_path)
                != {"path": expected_path, **receipt_file, "role": "model-asset"}
            ):
                raise DevelopmentArtifactVerificationError(
                    f"model asset is not bound to full receipt: {key}/{filename}"
                )


def _reconstruct_records(
    *,
    plan: Mapping[str, Any],
    report: Mapping[str, Any],
    sentences: Sequence[Mapping[str, str]],
) -> list[dict[str, Any]]:
    bindings = plan.get("inputBindings")
    if not isinstance(bindings, dict) or report.get("inputs") != bindings:
        raise DevelopmentArtifactVerificationError("report/plan input bindings differ")
    pages_root = plan.get("pages")
    if not isinstance(pages_root, dict) or set(pages_root) != {DATASET_ID}:
        raise DevelopmentArtifactVerificationError("development page corpus differs")
    pages = pages_root[DATASET_ID]
    if not isinstance(pages, list) or len(pages) != PAGES_PER_MODEL:
        raise DevelopmentArtifactVerificationError("development page count differs")
    private = plan.get("privateFiles")
    if not isinstance(private, list):
        raise DevelopmentArtifactVerificationError("private input inventory is absent")
    private_by_path = {
        item.get("path"): item for item in private if isinstance(item, Mapping)
    }
    if private_by_path.get(DATASET_PATH) != {
        "path": DATASET_PATH,
        "bytes": DATASET_BYTES,
        "sha256": DATASET_SHA256,
        "role": "development-corpus-source",
    }:
        raise DevelopmentArtifactVerificationError(
            "private PUD source binding differs"
        )
    record_commitments: list[dict[str, Any]] = []
    previous_end = 0
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or set(page) != {
            "pageSelectionIndex",
            "sourceSliceIndex",
            "sentenceStart",
            "sentenceEnd",
            "recordPath",
            "recordBytes",
            "recordSHA256",
            "inputTextBytes",
            "inputTextSHA256",
        }:
            raise DevelopmentArtifactVerificationError("development page fields differ")
        start = len(sentences) * index // PAGES_PER_MODEL
        end = len(sentences) * (index + 1) // PAGES_PER_MODEL
        path = f"records/ud-english-pud/slice-{index:02d}.bin"
        content = "\n\n".join(
            sentence["text"] for sentence in sentences[start:end]
        )
        content_raw = content.encode("utf-8", errors="strict")
        record_raw = _serialize_record(
            sentence_start=start,
            sentence_end=end,
            content=content,
        )
        expected_page = {
            "pageSelectionIndex": index,
            "sourceSliceIndex": index,
            "sentenceStart": start,
            "sentenceEnd": end,
            "recordPath": path,
            "recordBytes": len(record_raw),
            "recordSHA256": _sha256(record_raw),
            "inputTextBytes": len(content_raw),
            "inputTextSHA256": _sha256(content_raw),
        }
        if page != expected_page or start != previous_end:
            raise DevelopmentArtifactVerificationError(
                f"PUD record reconstruction differs: slice {index}"
            )
        previous_end = end
        if private_by_path.get(path) != {
            "path": path,
            "bytes": len(record_raw),
            "sha256": _sha256(record_raw),
            "role": "development-corpus-record",
        }:
            raise DevelopmentArtifactVerificationError(
                f"private PUD record binding differs: slice {index}"
            )
        record_commitments.append(
            {
                "datasetId": DATASET_ID,
                "sourceSliceIndex": index,
                "sentenceStart": start,
                "sentenceEnd": end,
                "bytes": len(record_raw),
                "sha256": _sha256(record_raw),
            }
        )
    if previous_end != len(sentences):
        raise DevelopmentArtifactVerificationError("PUD sentence coverage differs")
    return record_commitments


def _expected_job(plan: Mapping[str, Any], model_key: str) -> dict[str, Any]:
    models = plan["models"]
    model = next(item for item in models if item["key"] == model_key)
    pages = {
        DATASET_ID: [
            {
                "pageSelectionIndex": page["pageSelectionIndex"],
                "sourceSliceIndex": page["sourceSliceIndex"],
                "sentenceStart": page["sentenceStart"],
                "sentenceEnd": page["sentenceEnd"],
                "recordPath": page["recordPath"],
                "recordBytes": page["recordBytes"],
                "recordSHA256": page["recordSHA256"],
            }
            for page in plan["pages"][DATASET_ID]
        ]
    }
    return {
        "schemaVersion": JOB_SCHEMA,
        "suiteId": SUITE_ID,
        "runId": plan["runId"],
        "countsTowardScientificVerdict": False,
        "usedForCandidateSelectionOrTuning": False,
        "scientificAttemptStateCreated": False,
        "nistUsed": False,
        "futureCorpusUsed": False,
        "controlConfigurationSHA256": plan["controlConfigurationSHA256"],
        "sourceDataset": {
            "path": DATASET_PATH,
            "bytes": DATASET_BYTES,
            "sha256": DATASET_SHA256,
        },
        "model": {
            "key": model_key,
            "files": model["files"],
            "layers": model["layers"],
            "vocabSize": model["vocabSize"],
            "candidateBitsByLayer": model["candidateBitsByLayer"],
        },
        "selectedCorpora": [DATASET_ID],
        "pages": pages,
        "candidate": dict(CANDIDATE),
        "seed": 0,
    }


def _validate_jobs(
    plan: Mapping[str, Any], reader: ReadBound
) -> dict[str, dict[str, Any]]:
    commitments = plan.get("jobs")
    if not isinstance(commitments, dict) or tuple(commitments) != MODEL_KEYS:
        raise DevelopmentArtifactVerificationError("development job order differs")
    jobs: dict[str, dict[str, Any]] = {}
    for model_key in MODEL_KEYS:
        commitment = commitments[model_key]
        expected_path = f"jobs/{model_key}.json"
        if (
            not isinstance(commitment, Mapping)
            or set(commitment) != {"path", "bytes", "sha256"}
            or commitment.get("path") != expected_path
        ):
            raise DevelopmentArtifactVerificationError(
                f"development job commitment differs: {model_key}"
            )
        raw = reader(expected_path, 16 * 1024 * 1024)
        if {
            "path": expected_path,
            "bytes": len(raw),
            "sha256": _sha256(raw),
        } != dict(commitment):
            raise DevelopmentArtifactVerificationError(
                f"development job bytes differ: {model_key}"
            )
        job = _canonical_line(raw, label=f"development job {model_key}")
        if job != _expected_job(plan, model_key):
            raise DevelopmentArtifactVerificationError(
                f"development job semantics differ: {model_key}"
            )
        jobs[model_key] = job
    return jobs


def _decompress_canonical(stored: bytes, expected_bytes: int, *, label: str) -> bytes:
    if expected_bytes < 0 or expected_bytes > 256 * 1024 * 1024:
        raise DevelopmentArtifactVerificationError(f"invalid decoded size: {label}")
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(stored, expected_bytes + 1)
        if len(raw) > expected_bytes or decompressor.unconsumed_tail:
            raise DevelopmentArtifactVerificationError(
                f"decoded VTL5 stream exceeds bound: {label}"
            )
        raw += decompressor.flush(expected_bytes + 1 - len(raw))
    except zlib.error as error:
        raise DevelopmentArtifactVerificationError(
            f"invalid compressed VTL5 stream: {label}"
        ) from error
    if (
        len(raw) != expected_bytes
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
        or zlib.compress(raw, level=9) != stored
    ):
        raise DevelopmentArtifactVerificationError(
            f"non-canonical zlib-9 VTL5 stream: {label}"
        )
    return raw


def _decode_container_metadata(
    raw: bytes,
    *,
    model_key: str,
    layer_index: int,
    bits: int,
    trajectory_width: int,
) -> dict[str, Any]:
    if len(raw) < 8 or len(raw) > 256 * 1024 * 1024:
        raise DevelopmentArtifactVerificationError("VTL5 container size differs")
    magic, metadata_length = struct.unpack_from("<4sI", raw)
    if magic != b"VTL5" or metadata_length > 1024 * 1024:
        raise DevelopmentArtifactVerificationError("VTL5 header differs")
    metadata_end = 8 + metadata_length
    if metadata_end > len(raw):
        raise DevelopmentArtifactVerificationError("VTL5 metadata is truncated")
    metadata_raw = raw[8:metadata_end]
    metadata = _strict_json(metadata_raw, label="VTL5 metadata")
    if not isinstance(metadata, dict) or _canonical_json_bytes(metadata) != metadata_raw:
        raise DevelopmentArtifactVerificationError("VTL5 metadata is not canonical")
    fields = {
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
    if set(metadata) != fields:
        raise DevelopmentArtifactVerificationError("VTL5 metadata fields differ")
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
        "signMode": "none",
        "packing": (
            "lsb-first-v1"
            if bits <= 8
            else "byte-low-plus-lsb-high-fields-v1"
        ),
    }
    if any(metadata.get(field) != value for field, value in expected_strings.items()):
        raise DevelopmentArtifactVerificationError(
            f"VTL5 registered profile differs: {model_key}/{layer_index}"
        )
    if trajectory_width % 128:
        raise DevelopmentArtifactVerificationError("VTL5 trajectory width differs")
    groups = trajectory_width // 128
    scale_count = PREFILL_TOKENS * groups
    code_count = PREFILL_TOKENS * trajectory_width
    scale_bytes = scale_count * 2
    packed_bytes = (code_count * bits + 7) // 8
    expected_values = {
        "bits": bits,
        "layerIndex": layer_index,
        "groupSize": 128,
        "transformBlockSize": 128,
        "shape": [PREFILL_TOKENS, trajectory_width],
        "groupsPerRow": groups,
        "scaleCount": scale_count,
        "codeCount": code_count,
        "scaleBytes": scale_bytes,
        "packedBytes": packed_bytes,
    }
    if any(metadata.get(field) != value for field, value in expected_values.items()):
        raise DevelopmentArtifactVerificationError(
            f"VTL5 geometry differs: {model_key}/{layer_index}"
        )
    for field in ("inputSha256", "payloadSha256", "reconstructionSha256"):
        if not isinstance(metadata[field], str) or HEX_64.fullmatch(metadata[field]) is None:
            raise DevelopmentArtifactVerificationError(f"VTL5 digest differs: {field}")
    for field in ("storedScaleBytes", "storedCodeBytes", "payloadBytes"):
        if type(metadata[field]) is not int or metadata[field] < 1:
            raise DevelopmentArtifactVerificationError(f"VTL5 byte field differs: {field}")
    if metadata["payloadBytes"] != (
        metadata["storedScaleBytes"] + metadata["storedCodeBytes"]
    ):
        raise DevelopmentArtifactVerificationError("VTL5 payload accounting differs")
    payload = raw[metadata_end:]
    if len(payload) != metadata["payloadBytes"] or _sha256(payload) != metadata[
        "payloadSha256"
    ]:
        raise DevelopmentArtifactVerificationError("VTL5 payload commitment differs")
    scales = _decompress_canonical(
        payload[: metadata["storedScaleBytes"]],
        scale_bytes,
        label="scales",
    )
    _decompress_canonical(
        payload[metadata["storedScaleBytes"] :],
        packed_bytes,
        label="codes",
    )
    # A half-precision scale must be finite, non-negative, and not negative zero.
    for offset in range(0, len(scales), 2):
        value = struct.unpack_from("<e", scales, offset)[0]
        if not math.isfinite(value) or value < 0.0 or (
            value == 0.0 and scales[offset + 1] & 0x80
        ):
            raise DevelopmentArtifactVerificationError("VTL5 scale differs")
    return metadata


def _validate_page_tokens(
    records: list[dict[str, Any]],
    *,
    plan: Mapping[str, Any],
    model_key: str,
    vocab_size: int,
) -> list[list[int]]:
    if len(records) != PAGES_PER_MODEL:
        raise DevelopmentArtifactVerificationError(
            f"page-token evidence count differs: {model_key}"
        )
    fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "modelKey",
        "datasetId",
        "sourceSliceIndex",
        "pageSelectionIndex",
        "vocabSize",
        "first512TokenIds",
        "first512StreamSHA256",
    }
    streams: list[list[int]] = []
    for index, record in enumerate(records):
        token_ids = record.get("first512TokenIds") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or set(record) != fields
            or record.get("schemaVersion") != PAGE_TOKEN_SCHEMA
            or record.get("suiteId") != SUITE_ID
            or record.get("runId") != plan["runId"]
            or record.get("modelKey") != model_key
            or record.get("datasetId") != DATASET_ID
            or record.get("sourceSliceIndex") != index
            or record.get("pageSelectionIndex") != index
            or record.get("vocabSize") != vocab_size
            or not isinstance(token_ids, list)
            or len(token_ids) != PAGE_TOKENS
            or any(
                type(item) is not int or not 0 <= item < vocab_size
                for item in token_ids
            )
            or record.get("first512StreamSHA256") != _sha256(_token_stream(token_ids))
        ):
            raise DevelopmentArtifactVerificationError(
                f"page-token evidence differs: {model_key}/{index}"
            )
        streams.append(token_ids)
    return streams


def _validate_raw_tokens(
    records: list[dict[str, Any]],
    *,
    plan: Mapping[str, Any],
    model_key: str,
    vocab_size: int,
    token_streams: Sequence[Sequence[int]],
) -> list[list[dict[str, Any]]]:
    expected_count = PAGES_PER_MODEL * PREDICTIONS_PER_PAGE
    if len(records) != expected_count:
        raise DevelopmentArtifactVerificationError(
            f"raw-token evidence count differs: {model_key}"
        )
    fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "modelKey",
        "datasetId",
        "sourceSliceIndex",
        "pageSelectionIndex",
        "predictionIndex",
        "targetTokenId",
        "baselineLossF32Bits",
        "candidateLossF32Bits",
        "baselineTop1TokenId",
        "candidateTop1TokenId",
    }
    grouped: list[list[dict[str, Any]]] = []
    cursor = 0
    for page_index in range(PAGES_PER_MODEL):
        page: list[dict[str, Any]] = []
        for prediction_index in range(PREDICTIONS_PER_PAGE):
            record = records[cursor]
            cursor += 1
            expected_target_index = PREFILL_TOKENS + 1 + prediction_index
            if expected_target_index >= len(token_streams[page_index]):
                raise DevelopmentArtifactVerificationError(
                    "token geometry cannot supply every prediction target"
                )
            if (
                not isinstance(record, dict)
                or set(record) != fields
                or record.get("schemaVersion") != RAW_TOKEN_SCHEMA
                or record.get("suiteId") != SUITE_ID
                or record.get("runId") != plan["runId"]
                or record.get("modelKey") != model_key
                or record.get("datasetId") != DATASET_ID
                or record.get("sourceSliceIndex") != page_index
                or record.get("pageSelectionIndex") != page_index
                or record.get("predictionIndex") != prediction_index
                or record.get("targetTokenId")
                != token_streams[page_index][expected_target_index]
                or type(record.get("baselineTop1TokenId")) is not int
                or not 0 <= record["baselineTop1TokenId"] < vocab_size
                or type(record.get("candidateTop1TokenId")) is not int
                or not 0 <= record["candidateTop1TokenId"] < vocab_size
            ):
                raise DevelopmentArtifactVerificationError(
                    f"raw-token identity differs: {model_key}/{page_index}/{prediction_index}"
                )
            _float32(record["baselineLossF32Bits"], label="baseline loss")
            _float32(record["candidateLossF32Bits"], label="candidate loss")
            page.append(record)
        grouped.append(page)
    return grouped


def _validate_containers(
    records: list[dict[str, Any]],
    *,
    plan: Mapping[str, Any],
    model_key: str,
    model: Mapping[str, Any],
    geometry: Mapping[str, Any],
    reader: ReadBound,
) -> tuple[list[list[dict[str, Any]]], list[dict[str, Any]]]:
    layers = model["layers"]
    expected_count = PAGES_PER_MODEL * layers
    if len(records) != expected_count:
        raise DevelopmentArtifactVerificationError(
            f"container evidence count differs: {model_key}"
        )
    fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "modelKey",
        "datasetId",
        "sourceSliceIndex",
        "pageSelectionIndex",
        "layerIndex",
        "denseBF16Bytes",
        "containerBytes",
        "containerSHA256",
        "relativePath",
        "structuralReplay",
    }
    grouped: list[list[dict[str, Any]]] = []
    byte_set: list[dict[str, Any]] = []
    cursor = 0
    for page_index in range(PAGES_PER_MODEL):
        page: list[dict[str, Any]] = []
        for layer_index in range(layers):
            record = records[cursor]
            cursor += 1
            relative = (
                f"containers/{model_key}/{DATASET_ID}/slice-{page_index:02d}/"
                f"layer-{layer_index:02d}.vtl5"
            )
            dense_bytes = PREFILL_TOKENS * geometry["trajectoryWidth"] * 2
            if (
                not isinstance(record, dict)
                or set(record) != fields
                or record.get("schemaVersion") != CONTAINER_SCHEMA
                or record.get("suiteId") != SUITE_ID
                or record.get("runId") != plan["runId"]
                or record.get("modelKey") != model_key
                or record.get("datasetId") != DATASET_ID
                or record.get("sourceSliceIndex") != page_index
                or record.get("pageSelectionIndex") != page_index
                or record.get("layerIndex") != layer_index
                or record.get("denseBF16Bytes") != dense_bytes
                or type(record.get("containerBytes")) is not int
                or record["containerBytes"] < 1
                or not isinstance(record.get("containerSHA256"), str)
                or HEX_64.fullmatch(record["containerSHA256"]) is None
                or record.get("relativePath") != relative
                or record.get("structuralReplay") is not True
            ):
                raise DevelopmentArtifactVerificationError(
                    f"container evidence differs: {model_key}/{page_index}/{layer_index}"
                )
            raw = reader(relative, 256 * 1024 * 1024)
            if len(raw) != record["containerBytes"] or _sha256(raw) != record[
                "containerSHA256"
            ]:
                raise DevelopmentArtifactVerificationError(
                    f"container bytes differ: {model_key}/{page_index}/{layer_index}"
                )
            metadata = _decode_container_metadata(
                raw,
                model_key=model_key,
                layer_index=layer_index,
                bits=model["candidateBitsByLayer"][layer_index],
                trajectory_width=geometry["trajectoryWidth"],
            )
            enriched = {
                **record,
                "inputSHA256": metadata["inputSha256"],
                "reconstructionSHA256": metadata["reconstructionSha256"],
            }
            page.append(enriched)
            byte_set.append(
                {
                    "relativePath": relative,
                    "bytes": len(raw),
                    "sha256": _sha256(raw),
                }
            )
        grouped.append(page)
    return grouped, byte_set


def _validate_worker_summary(
    summary: dict[str, Any],
    *,
    plan: Mapping[str, Any],
    model_key: str,
    model: Mapping[str, Any],
    geometry: Mapping[str, Any],
    raw_by_page: Sequence[Sequence[Mapping[str, Any]]],
    containers_by_page: Sequence[Sequence[Mapping[str, Any]]],
    raw_bytes: bytes,
    page_bytes: bytes,
    container_bytes: bytes,
) -> None:
    fields = {
        "schemaVersion",
        "suiteId",
        "runId",
        "modelKey",
        "geometry",
        "pages",
        "rawTokenEvidence",
        "containerEvidence",
        "pageTokenEvidence",
        "durationNanoseconds",
        "networkUsed",
        "modelLoad",
        "countsTowardScientificVerdict",
        "usedForCandidateSelectionOrTuning",
        "scientificAttemptStateCreated",
        "nistUsed",
        "futureCorpusUsed",
        "controlConfigurationSHA256",
    }
    if (
        set(summary) != fields
        or summary.get("schemaVersion") != WORKER_SUMMARY_SCHEMA
        or summary.get("suiteId") != SUITE_ID
        or summary.get("runId") != plan["runId"]
        or summary.get("modelKey") != model_key
        or summary.get("geometry") != geometry
        or type(summary.get("durationNanoseconds")) is not int
        or summary["durationNanoseconds"] <= 0
        or summary.get("networkUsed") is not False
        or summary.get("modelLoad")
        != "verified-owned-bytes-no-mmap-no-pickle-no-from_pretrained"
        or summary.get("countsTowardScientificVerdict") is not False
        or summary.get("usedForCandidateSelectionOrTuning") is not False
        or summary.get("scientificAttemptStateCreated") is not False
        or summary.get("nistUsed") is not False
        or summary.get("futureCorpusUsed") is not False
        or summary.get("controlConfigurationSHA256")
        != plan["controlConfigurationSHA256"]
    ):
        raise DevelopmentArtifactVerificationError(
            f"worker summary boundary differs: {model_key}"
        )
    commitments = {
        "rawTokenEvidence": ("raw-token-evidence.jsonl", raw_bytes),
        "containerEvidence": ("container-evidence.jsonl", container_bytes),
        "pageTokenEvidence": ("page-token-evidence.jsonl", page_bytes),
    }
    for field, (filename, raw) in commitments.items():
        if summary.get(field) != {
            "path": filename,
            "bytes": len(raw),
            "sha256": _sha256(raw),
        }:
            raise DevelopmentArtifactVerificationError(
                f"worker evidence commitment differs: {model_key}/{field}"
            )
    pages = summary.get("pages")
    if not isinstance(pages, list) or len(pages) != PAGES_PER_MODEL:
        raise DevelopmentArtifactVerificationError(
            f"worker page summary count differs: {model_key}"
        )
    page_fields = {
        "datasetId",
        "pageSelectionIndex",
        "sourceSliceIndex",
        "denseBF16Bytes",
        "containerBytes",
        "compressionRatioVsBF16",
        "deltaNLLNatPerToken",
        "top1ExactMatches",
    }
    for index, page in enumerate(pages):
        raw_records = raw_by_page[index]
        container_records = containers_by_page[index]
        dense_bytes = sum(item["denseBF16Bytes"] for item in container_records)
        encoded_bytes = sum(item["containerBytes"] for item in container_records)
        delta = math.fsum(
            _float32(item["candidateLossF32Bits"], label="candidate loss")
            - _float32(item["baselineLossF32Bits"], label="baseline loss")
            for item in raw_records
        ) / PREDICTIONS_PER_PAGE
        matches = sum(
            item["baselineTop1TokenId"] == item["candidateTop1TokenId"]
            for item in raw_records
        )
        expected = {
            "datasetId": DATASET_ID,
            "pageSelectionIndex": index,
            "sourceSliceIndex": index,
            "denseBF16Bytes": dense_bytes,
            "containerBytes": encoded_bytes,
            "compressionRatioVsBF16": dense_bytes / encoded_bytes,
            "deltaNLLNatPerToken": delta,
            "top1ExactMatches": matches,
        }
        if not isinstance(page, dict) or set(page) != page_fields or page != expected:
            raise DevelopmentArtifactVerificationError(
                f"worker page metrics differ: {model_key}/{index}"
            )


def _model_file_digest(model: Mapping[str, Any]) -> str:
    values = [
        {
            "filename": filename,
            "bytes": model["files"][filename]["bytes"],
            "sha256": model["files"][filename]["sha256"],
        }
        for filename in MODEL_FILES
    ]
    return _sha256(_canonical_json_bytes(values))


def _verify_model(
    *,
    model_key: str,
    plan: Mapping[str, Any],
    report: Mapping[str, Any],
    reader: ReadBound,
    record_commitments: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    model = next(item for item in plan["models"] if item["key"] == model_key)
    identity = MODEL_IDENTITIES[model_key]
    geometry = MODEL_GEOMETRIES[model_key]
    expected_schedule = [
        9 if index in {0, identity["layers"] // 3} else 8
        for index in range(identity["layers"])
    ]
    if (
        model.get("layers") != identity["layers"]
        or model.get("vocabSize") != identity["vocabSize"]
        or model.get("candidateBitsByLayer") != expected_schedule
    ):
        raise DevelopmentArtifactVerificationError(
            f"model geometry/schedule differs: {model_key}"
        )
    worker_prefix = f"workers/{model_key}"
    raw_bytes = reader(f"{worker_prefix}/raw-token-evidence.jsonl", 128 * 1024 * 1024)
    container_bytes = reader(
        f"{worker_prefix}/container-evidence.jsonl", 64 * 1024 * 1024
    )
    page_bytes = reader(
        f"{worker_prefix}/page-token-evidence.jsonl", 16 * 1024 * 1024
    )
    raw_records = _canonical_jsonl(
        raw_bytes, label=f"raw-token evidence {model_key}"
    )
    container_records = _canonical_jsonl(
        container_bytes, label=f"container evidence {model_key}"
    )
    page_records = _canonical_jsonl(
        page_bytes, label=f"page-token evidence {model_key}"
    )
    token_streams = _validate_page_tokens(
        page_records,
        plan=plan,
        model_key=model_key,
        vocab_size=model["vocabSize"],
    )
    raw_by_page = _validate_raw_tokens(
        raw_records,
        plan=plan,
        model_key=model_key,
        vocab_size=model["vocabSize"],
        token_streams=token_streams,
    )
    containers_by_page, container_byte_set = _validate_containers(
        container_records,
        plan=plan,
        model_key=model_key,
        model=model,
        geometry=geometry,
        reader=reader,
    )
    summary_raw = reader(f"{worker_prefix}/worker-summary.json", 16 * 1024 * 1024)
    worker_summary = _canonical_line(
        summary_raw, label=f"worker summary {model_key}"
    )
    _validate_worker_summary(
        worker_summary,
        plan=plan,
        model_key=model_key,
        model=model,
        geometry=geometry,
        raw_by_page=raw_by_page,
        containers_by_page=containers_by_page,
        raw_bytes=raw_bytes,
        page_bytes=page_bytes,
        container_bytes=container_bytes,
    )
    page_summaries: list[dict[str, Any]] = []
    for page_index in range(PAGES_PER_MODEL):
        page = plan["pages"][DATASET_ID][page_index]
        container_commitments = [
            {
                "layerIndex": record["layerIndex"],
                "relativePath": record["relativePath"],
                "containerBytes": record["containerBytes"],
                "containerSHA256": record["containerSHA256"],
                "inputSHA256": record["inputSHA256"],
                "reconstructionSHA256": record["reconstructionSHA256"],
            }
            for record in containers_by_page[page_index]
        ]
        page_summaries.append(
            {
                "datasetId": DATASET_ID,
                "sourceSliceIndex": page_index,
                "sentenceStart": page["sentenceStart"],
                "sentenceEnd": page["sentenceEnd"],
                "predictions": PREDICTIONS_PER_PAGE,
                "containers": model["layers"],
                "tokenStreamSHA256": page_records[page_index][
                    "first512StreamSHA256"
                ],
                "containerCommitmentsSHA256": _sha256(
                    _canonical_json_bytes(container_commitments)
                ),
            }
        )
    recomputed = {
        "modelKey": model_key,
        "modelFileSetSHA256": _model_file_digest(model),
        "weightSHA256": model["files"]["model.safetensors"]["sha256"],
        "tokenizerSHA256": model["files"]["tokenizer.json"]["sha256"],
        "corpusRecordSetSHA256": _sha256(
            _canonical_json_bytes(list(record_commitments))
        ),
        "rawTokenEvidenceSHA256": _sha256(raw_bytes),
        "pageTokenEvidenceSHA256": _sha256(page_bytes),
        "containerEvidenceSHA256": _sha256(container_bytes),
        "containerByteSetSHA256": _sha256(
            _canonical_json_bytes(container_byte_set)
        ),
        "pageReplaySHA256": _sha256(_canonical_json_bytes(page_summaries)),
        "replayedPages": PAGES_PER_MODEL,
        "replayedPredictions": PAGES_PER_MODEL * PREDICTIONS_PER_PAGE,
        "replayedContainers": PAGES_PER_MODEL * model["layers"],
        "exactTokenIds": True,
        "exactLossFloat32Bits": True,
        "exactTop1TokenIds": True,
        "allContainerInputsBoundToBaselineCache": True,
    }
    replay = report.get("independentReplay")
    replay_models = replay.get("models") if isinstance(replay, dict) else None
    if not isinstance(replay_models, list):
        raise DevelopmentArtifactVerificationError("independent replay models are absent")
    claimed = next(
        (
            item
            for item in replay_models
            if isinstance(item, dict) and item.get("modelKey") == model_key
        ),
        None,
    )
    if claimed != recomputed:
        raise DevelopmentArtifactVerificationError(
            f"independent replay digests differ from evidence: {model_key}"
        )
    return recomputed, {
        "raw": raw_bytes,
        "container": container_bytes,
        "page": page_bytes,
    }


def _validate_replay_aggregate(
    report: Mapping[str, Any], recomputed: Sequence[Mapping[str, Any]]
) -> None:
    replay = report.get("independentReplay")
    if not isinstance(replay, dict):
        raise DevelopmentArtifactVerificationError("independent replay is absent")
    claimed_models = replay.get("models")
    if (
        not isinstance(claimed_models, list)
        or [item.get("modelKey") if isinstance(item, dict) else None for item in claimed_models]
        != list(MODEL_KEYS)
        or claimed_models != list(recomputed)
        or replay.get("modelOrder") != list(MODEL_KEYS)
        or replay.get("selectedCorpora") != [DATASET_ID]
        or replay.get("totalReplayedPages")
        != len(MODEL_KEYS) * PAGES_PER_MODEL
        or replay.get("totalReplayedPredictions")
        != len(MODEL_KEYS) * PAGES_PER_MODEL * PREDICTIONS_PER_PAGE
        or replay.get("totalReplayedContainers")
        != sum(item["replayedContainers"] for item in recomputed)
        or replay.get("exactTokenIds") is not True
        or replay.get("exactLossFloat32Bits") is not True
        or replay.get("exactTop1TokenIds") is not True
        or replay.get("allContainerInputsBoundToBaselineCache") is not True
        or replay.get("replayComplete") is not True
    ):
        raise DevelopmentArtifactVerificationError(
            "independent replay aggregate differs from evidence"
        )
    digest = replay.get("contentSHA256")
    if not isinstance(digest, str) or HEX_64.fullmatch(digest) is None:
        raise DevelopmentArtifactVerificationError("independent replay digest is invalid")
    payload = dict(replay)
    del payload["contentSHA256"]
    if _sha256(_canonical_json_bytes(payload)) != digest:
        raise DevelopmentArtifactVerificationError(
            "independent replay content digest differs"
        )


def verify_artifact_semantics(
    root: Path,
    plan: Mapping[str, Any],
    report: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]],
    read_bound: ReadBound | None = None,
) -> dict[str, Any]:
    """Recompute the semantic commitments of one completed development archive.

    ``read_bound`` is an optional integration hook with signature
    ``read_bound(relative_path, maximum_bytes) -> bytes``.  Regardless of the
    hook, this function rechecks returned bytes against ``inventory``.  Without
    a hook it performs no-follow, stable descriptor reads beneath ``root``.
    """

    try:
        if not isinstance(plan, Mapping) or not isinstance(report, Mapping):
            raise DevelopmentArtifactVerificationError("plan/report must be objects")
        if (
            plan.get("suiteId") != SUITE_ID
            or report.get("suiteId") != SUITE_ID
            or plan.get("runId") != report.get("runId")
            or report.get("controlConfigurationSHA256")
            != plan.get("controlConfigurationSHA256")
            or plan.get("modelExecutionOrder") != list(MODEL_KEYS)
            or plan.get("selectedCorpora") != [DATASET_ID]
            or plan.get("candidate") != CANDIDATE
            or PAGE_TOKENS
            != PREFILL_TOKENS + PREDICTIONS_PER_PAGE + 1
        ):
            raise DevelopmentArtifactVerificationError(
                "development plan/report boundary differs"
            )
        inventory_by_path = _normalise_inventory(inventory)
        base_reader = (
            read_bound
            if read_bound is not None
            else _filesystem_reader(root, inventory_by_path)
        )
        reader = _checked_reader(base_reader, inventory_by_path)
        receipt_raw = reader(FULL_ASSET_RECEIPT_PATH, 64 * 1024 * 1024)
        _validate_asset_receipt(plan, receipt_raw)
        dataset_raw = reader(DATASET_PATH, 16 * 1024 * 1024)
        sentences = _decode_dataset(dataset_raw)
        _validate_pud_inputs(
            plan=plan,
            reader=reader,
            dataset_raw=dataset_raw,
            sentences=sentences,
        )
        record_commitments = _reconstruct_records(
            plan=plan,
            report=report,
            sentences=sentences,
        )
        _validate_jobs(plan, reader)
        recomputed: list[dict[str, Any]] = []
        streams: dict[str, list[bytes]] = {"raw": [], "container": [], "page": []}
        for model_key in MODEL_KEYS:
            model_result, model_streams = _verify_model(
                model_key=model_key,
                plan=plan,
                report=report,
                reader=reader,
                record_commitments=record_commitments,
            )
            recomputed.append(model_result)
            for kind in streams:
                streams[kind].append(model_streams[kind])
        combined_paths = {
            "raw": "raw-token-evidence.jsonl",
            "container": "container-evidence.jsonl",
            "page": "page-token-evidence.jsonl",
        }
        for kind, relative in combined_paths.items():
            combined = reader(relative, 512 * 1024 * 1024)
            expected = b"".join(streams[kind])
            if combined != expected:
                raise DevelopmentArtifactVerificationError(
                    f"consolidated {kind} evidence is not exact model-order concatenation"
                )
        _validate_replay_aggregate(report, recomputed)
        return {
            "status": "VERIFIED_DEVELOPMENT_ARTIFACT_SEMANTICS",
            "datasetSHA256": DATASET_SHA256,
            "datasetSentences": len(sentences),
            "recordSetSHA256": _sha256(
                _canonical_json_bytes(record_commitments)
            ),
            "models": {item["modelKey"]: item for item in recomputed},
            "totalPages": len(MODEL_KEYS) * PAGES_PER_MODEL,
            "totalPredictions": (
                len(MODEL_KEYS) * PAGES_PER_MODEL * PREDICTIONS_PER_PAGE
            ),
            "totalContainers": sum(
                item["replayedContainers"] for item in recomputed
            ),
        }
    except DevelopmentArtifactVerificationError:
        raise
    except (KeyError, StopIteration, TypeError, ValueError, OverflowError) as error:
        raise DevelopmentArtifactVerificationError(
            "development artifact semantics are malformed"
        ) from error


__all__ = [
    "DevelopmentArtifactVerificationError",
    "FULL_ASSET_RECEIPT_PATH",
    "verify_artifact_semantics",
]
