"""Canonical UD English PUD r2.18 development-control corpus handling.

This module accepts one exact upstream CoNLL-U artifact.  It uses only the
Python standard library, preserves the upstream ``test`` split identity, and
does not make a legal, ownership, or chain-of-title determination.  Its rights
status means only that the exact archived upstream README and LICENSE make a
consistent CC BY-SA 3.0 declaration.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import struct
from typing import Any, Sequence


DATASET_ID = "UniversalDependencies/UD_English-PUD:r2.18:test"
REPOSITORY = "UniversalDependencies/UD_English-PUD"
RELEASE_TAG = "r2.18"
REVISION = "e173a1be1b442faf34e7d5a502189ad5d9d1e197"
TREE = "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde"
SPLIT = "test"
FILE = "en_pud-ud-test.conllu"
FORMAT = "CoNLL-U"
SOURCE_URL = (
    "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/"
    f"{REVISION}/{FILE}"
)
SOURCE_GIT_BLOB = "f0288b7292bdfebe3eab1bcd012666f5fd83adf0"
SOURCE_BYTES = 1_386_858
SOURCE_SHA256 = "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa"
SOURCE_TERMINATOR = b"\n\n"
SENTENCE_COUNT = 1_000
PARTITIONS = 32
JOIN_SEPARATOR = "\n\n"
JOINED_TEXT_BYTES = 112_419
JOINED_TEXT_SHA256 = (
    "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea"
)

README_COMPONENT = "UD English PUD development corpus README"
README_FILE = "README.md"
README_ARCHIVED_PATH = "upstream/ud-english-pud-r2.18-README.md"
README_URL = (
    "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/"
    f"{REVISION}/{README_FILE}"
)
README_GIT_BLOB = "15ab0c810de4c223663e25f956c9225e34d376fc"
README_BYTES = 6_986
README_SHA256 = "9558eb70a6565a40e2ecf06d0f38c9f6117de0f0f8bc5021805bdce51ee0d67f"

LICENSE_COMPONENT = "UD English PUD development corpus license"
LICENSE_FILE = "LICENSE.txt"
LICENSE_ARCHIVED_PATH = "upstream/ud-english-pud-r2.18-LICENSE.txt"
LICENSE_URL = (
    "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/"
    f"{REVISION}/{LICENSE_FILE}"
)
LICENSE_GIT_BLOB = "a0bd8baeb667daae1407869f3152489fab3001de"
LICENSE_BYTES = 19_556
LICENSE_SHA256 = "b278eb53fe50b8bb7fa0d90fb8536c35fdcaa80f9d63812cb51db539555d2a89"
LICENSE_ID = "CC-BY-SA-3.0"
LICENSE_CANONICAL_URL = "https://creativecommons.org/licenses/by-sa/3.0/"

ATTRIBUTION_ARCHIVED_PATH = "UD_ENGLISH_PUD_ATTRIBUTION.md"
ATTRIBUTION_BYTES = 2_056
ATTRIBUTION_SHA256 = (
    "296ebce07660b5f37cf99729f0a2be86d5e183021149a9993e9db0f59ddcb9da"
)
SOURCE_EVIDENCE_SCHEMA = (
    "corelm-crossmodel-livewiki-v2-license-source-evidence-v1"
)
SOURCE_EVIDENCE_STATUS = "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED"
RIGHTS_STATUS = "CONSISTENT_UPSTREAM_LICENSE_DECLARATION"
RIGHTS_SCOPE = "UPSTREAM_DECLARATION_ONLY_NO_OWNERSHIP_OR_CHAIN_OF_TITLE_CLAIM"

MAGIC = b"CORELM-UD-ENGLISH-PUD-R2.18-DEVELOPMENT-RECORD\0"
_TOKEN_ID = re.compile(r"[1-9][0-9]*(?:-[1-9][0-9]*|\.[1-9][0-9]*)?\Z")


class DevelopmentCorpusError(ValueError):
    """Raised when corpus, provenance, or record bytes are non-canonical."""


@dataclass(frozen=True)
class CorpusSentence:
    """One source-order sentence extracted without text normalization."""

    index: int
    sent_id: str
    text: str
    block_sha256: str


def expected_source_evidence_entries() -> tuple[dict[str, Any], ...]:
    """Return fresh copies of the two exact upstream rights-evidence entries."""

    common = {
        "repository": REPOSITORY,
        "revision": REVISION,
        "archivedEncoding": "identity",
        "declaredLicense": LICENSE_ID,
    }
    return (
        {
            "component": README_COMPONENT,
            **common,
            "relativePath": README_FILE,
            "archivedPath": README_ARCHIVED_PATH,
            "url": README_URL,
            "bytes": README_BYTES,
            "sha256": README_SHA256,
        },
        {
            "component": LICENSE_COMPONENT,
            **common,
            "relativePath": LICENSE_FILE,
            "archivedPath": LICENSE_ARCHIVED_PATH,
            "url": LICENSE_URL,
            "bytes": LICENSE_BYTES,
            "sha256": LICENSE_SHA256,
        },
    )


def _verify_exact_blob(
    raw: bytes, *, expected_bytes: int, expected_sha256: str, label: str
) -> str:
    if type(raw) is not bytes:
        raise DevelopmentCorpusError(f"{label} is not bytes")
    if len(raw) != expected_bytes:
        raise DevelopmentCorpusError(f"{label} byte length differs")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise DevelopmentCorpusError(f"{label} SHA-256 differs")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentCorpusError(f"{label} is not strict UTF-8") from error
    if text.encode("utf-8", errors="strict") != raw:
        raise DevelopmentCorpusError(f"{label} UTF-8 is non-canonical")
    return text


def verify_rights_evidence(
    source_evidence: Any,
    readme_raw: bytes,
    license_raw: bytes,
    attribution_raw: bytes,
) -> str:
    """Verify exact upstream declarations without asserting ownership.

    Other components may coexist in the repository-wide source-evidence file,
    but both PUD entries must occur exactly once and match byte for byte.
    """

    if (
        not isinstance(source_evidence, dict)
        or source_evidence.get("schemaVersion") != SOURCE_EVIDENCE_SCHEMA
        or source_evidence.get("status") != SOURCE_EVIDENCE_STATUS
        or not isinstance(source_evidence.get("sources"), list)
    ):
        raise DevelopmentCorpusError("PUD license source evidence differs")

    expected = {
        entry["component"]: entry for entry in expected_source_evidence_entries()
    }
    observed: dict[str, dict[str, Any]] = {}
    for value in source_evidence["sources"]:
        if not isinstance(value, dict):
            continue
        component = value.get("component")
        if component not in expected:
            continue
        if component in observed:
            raise DevelopmentCorpusError("PUD source evidence is duplicated")
        observed[component] = value
    if observed != expected:
        raise DevelopmentCorpusError("PUD source-evidence commitments differ")

    readme = _verify_exact_blob(
        readme_raw,
        expected_bytes=README_BYTES,
        expected_sha256=README_SHA256,
        label="PUD upstream README",
    )
    license_text = _verify_exact_blob(
        license_raw,
        expected_bytes=LICENSE_BYTES,
        expected_sha256=LICENSE_SHA256,
        label="PUD upstream license",
    )
    attribution = _verify_exact_blob(
        attribution_raw,
        expected_bytes=ATTRIBUTION_BYTES,
        expected_sha256=ATTRIBUTION_SHA256,
        label="PUD attribution",
    )
    if (
        readme.count("License: CC BY-SA 3.0") != 1
        or readme.count("Includes text: yes") != 1
        or readme.count(
            "GOOGLE MAKES THEM AVAILABLE TO YOU under CC-BY-SA 3.0"
        )
        != 1
        or LICENSE_CANONICAL_URL not in license_text
        or "Attribution-ShareAlike 3.0" not in license_text
        or RELEASE_TAG not in attribution
        or REVISION not in attribution
        or TREE not in attribution
        or SOURCE_SHA256 not in attribution
        or "No endorsement" not in attribution
    ):
        raise DevelopmentCorpusError("PUD rights or attribution declaration differs")
    return RIGHTS_STATUS


def _parse_blocks(raw: bytes, *, expected_blocks: int) -> tuple[CorpusSentence, ...]:
    if type(raw) is not bytes or not raw:
        raise DevelopmentCorpusError("PUD source is not non-empty bytes")
    if type(expected_blocks) is not int or expected_blocks <= 0:
        raise DevelopmentCorpusError("PUD expected block count is invalid")
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or b"\x00" in raw:
        raise DevelopmentCorpusError("PUD source encoding markers differ")
    if not raw.endswith(SOURCE_TERMINATOR) or raw.endswith(b"\n\n\n"):
        raise DevelopmentCorpusError("PUD source must end in exactly two LF bytes")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise DevelopmentCorpusError("PUD source is not strict UTF-8") from error

    blocks = raw[: -len(SOURCE_TERMINATOR)].split(SOURCE_TERMINATOR)
    if len(blocks) != expected_blocks or any(not block for block in blocks):
        raise DevelopmentCorpusError("PUD sentence block count differs")

    records: list[CorpusSentence] = []
    sent_ids: set[str] = set()
    for index, block in enumerate(blocks):
        try:
            block_text = block.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise DevelopmentCorpusError(
                f"PUD sentence block {index} is not UTF-8"
            ) from error
        lines = block_text.split("\n")
        if not lines or any(not line for line in lines):
            raise DevelopmentCorpusError(f"PUD sentence block {index} is malformed")

        sent_id_values: list[str] = []
        text_values: list[str] = []
        token_seen = False
        syntactic_tokens = 0
        for line in lines:
            if line.startswith("#"):
                if token_seen or not line.startswith("# "):
                    raise DevelopmentCorpusError(
                        f"PUD sentence block {index} has misplaced metadata"
                    )
                if line.startswith("# sent_id"):
                    if not line.startswith("# sent_id = "):
                        raise DevelopmentCorpusError(
                            f"PUD sentence block {index} has malformed sent_id"
                        )
                    sent_id_values.append(line.removeprefix("# sent_id = "))
                if line.startswith("# text"):
                    if not line.startswith("# text = "):
                        raise DevelopmentCorpusError(
                            f"PUD sentence block {index} has malformed text metadata"
                        )
                    text_values.append(line.removeprefix("# text = "))
                continue

            token_seen = True
            fields = line.split("\t")
            if len(fields) != 10 or _TOKEN_ID.fullmatch(fields[0]) is None:
                raise DevelopmentCorpusError(
                    f"PUD sentence block {index} has malformed CoNLL-U row"
                )
            if "-" not in fields[0] and "." not in fields[0]:
                syntactic_tokens += 1

        if (
            len(sent_id_values) != 1
            or len(text_values) != 1
            or not sent_id_values[0]
            or sent_id_values[0].strip() != sent_id_values[0]
            or not text_values[0]
            or syntactic_tokens == 0
        ):
            raise DevelopmentCorpusError(
                f"PUD sentence block {index} metadata differs"
            )
        sent_id = sent_id_values[0]
        if sent_id in sent_ids:
            raise DevelopmentCorpusError("PUD sent_id values are not unique")
        sent_ids.add(sent_id)
        records.append(
            CorpusSentence(
                index=index,
                sent_id=sent_id,
                text=text_values[0],
                block_sha256=hashlib.sha256(block).hexdigest(),
            )
        )
    return tuple(records)


def joined_text(records: Sequence[CorpusSentence]) -> bytes:
    """Join source-order sentence text with exactly two LF characters."""

    if not isinstance(records, Sequence) or not records:
        raise DevelopmentCorpusError("PUD sentence sequence is empty")
    values: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, CorpusSentence) or record.index != index:
            raise DevelopmentCorpusError("PUD sentence order differs")
        values.append(record.text)
    try:
        return JOIN_SEPARATOR.join(values).encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise DevelopmentCorpusError("PUD joined text is not strict UTF-8") from error


def parse_corpus(raw: bytes) -> tuple[CorpusSentence, ...]:
    """Parse only the exact pinned r2.18 upstream source artifact."""

    if type(raw) is not bytes:
        raise DevelopmentCorpusError("PUD source is not bytes")
    if len(raw) != SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise DevelopmentCorpusError("PUD source identity differs")
    records = _parse_blocks(raw, expected_blocks=SENTENCE_COUNT)
    joined = joined_text(records)
    if (
        len(joined) != JOINED_TEXT_BYTES
        or hashlib.sha256(joined).hexdigest() != JOINED_TEXT_SHA256
    ):
        raise DevelopmentCorpusError("PUD joined text commitment differs")
    return records


def partition_bounds(*, partitions: int = PARTITIONS) -> tuple[tuple[int, int], ...]:
    """Return the fixed contiguous equal-floor sentence boundaries."""

    if type(partitions) is not int or partitions <= 0 or partitions > SENTENCE_COUNT:
        raise DevelopmentCorpusError("PUD partition count is invalid")
    return tuple(
        (
            SENTENCE_COUNT * index // partitions,
            SENTENCE_COUNT * (index + 1) // partitions,
        )
        for index in range(partitions)
    )


def _field(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise DevelopmentCorpusError(f"{label} is not text")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise DevelopmentCorpusError(f"{label} is not strict UTF-8") from error
    return struct.pack(">Q", len(raw)) + raw


def serialize_record(
    *, sentence_start: int, sentence_end: int, content: str
) -> bytes:
    """Serialize one canonical provenance-bound development record."""

    if (
        type(sentence_start) is not int
        or type(sentence_end) is not int
        or sentence_start < 0
        or sentence_end <= sentence_start
        or sentence_end > SENTENCE_COUNT
    ):
        raise DevelopmentCorpusError("PUD sentence range is invalid")
    if not isinstance(content, str) or not content:
        raise DevelopmentCorpusError("PUD record content is empty")
    return b"".join(
        (
            MAGIC,
            _field(DATASET_ID, label="dataset ID"),
            _field(REPOSITORY, label="repository"),
            _field(RELEASE_TAG, label="release tag"),
            _field(REVISION, label="revision"),
            _field(TREE, label="tree"),
            _field(SPLIT, label="split"),
            _field(FILE, label="file"),
            _field(SOURCE_SHA256, label="source SHA-256"),
            _field(JOINED_TEXT_SHA256, label="joined-text SHA-256"),
            struct.pack(">Q", sentence_start),
            struct.pack(">Q", sentence_end),
            _field(content, label="content"),
        )
    )


def parse_record(raw: bytes) -> dict[str, Any]:
    """Parse and byte-for-byte reconstruct one canonical record."""

    if type(raw) is not bytes or not raw.startswith(MAGIC):
        raise DevelopmentCorpusError("PUD development record magic differs")
    offset = len(MAGIC)

    def take(size: int, label: str) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(raw):
            raise DevelopmentCorpusError(f"PUD record is truncated: {label}")
        value = raw[offset : offset + size]
        offset += size
        return value

    def take_u64(label: str) -> int:
        return int.from_bytes(take(8, label), "big")

    def take_text(label: str) -> str:
        size = take_u64(f"{label} length")
        encoded = take(size, label)
        try:
            value = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise DevelopmentCorpusError(
                f"PUD record field is not UTF-8: {label}"
            ) from error
        if value.encode("utf-8", errors="strict") != encoded:
            raise DevelopmentCorpusError(f"PUD record field is non-canonical: {label}")
        return value

    values = {
        "datasetId": take_text("dataset ID"),
        "repository": take_text("repository"),
        "releaseTag": take_text("release tag"),
        "revision": take_text("revision"),
        "tree": take_text("tree"),
        "split": take_text("split"),
        "file": take_text("file"),
        "sourceSHA256": take_text("source SHA-256"),
        "joinedTextSHA256": take_text("joined-text SHA-256"),
        "sentenceStart": take_u64("sentence start"),
        "sentenceEnd": take_u64("sentence end"),
        "content": take_text("content"),
    }
    if offset != len(raw):
        raise DevelopmentCorpusError("PUD record has trailing bytes")
    expected_identity = {
        "datasetId": DATASET_ID,
        "repository": REPOSITORY,
        "releaseTag": RELEASE_TAG,
        "revision": REVISION,
        "tree": TREE,
        "split": SPLIT,
        "file": FILE,
        "sourceSHA256": SOURCE_SHA256,
        "joinedTextSHA256": JOINED_TEXT_SHA256,
    }
    if any(values[key] != value for key, value in expected_identity.items()):
        raise DevelopmentCorpusError("PUD record dataset identity differs")
    if (
        type(values["sentenceStart"]) is not int
        or type(values["sentenceEnd"]) is not int
        or values["sentenceStart"] < 0
        or values["sentenceEnd"] <= values["sentenceStart"]
        or values["sentenceEnd"] > SENTENCE_COUNT
        or not values["content"]
    ):
        raise DevelopmentCorpusError("PUD record sentence range differs")
    rebuilt = serialize_record(
        sentence_start=values["sentenceStart"],
        sentence_end=values["sentenceEnd"],
        content=values["content"],
    )
    if rebuilt != raw:
        raise DevelopmentCorpusError("PUD record reconstruction differs")
    return values


__all__ = [
    "ATTRIBUTION_ARCHIVED_PATH",
    "ATTRIBUTION_BYTES",
    "ATTRIBUTION_SHA256",
    "CorpusSentence",
    "DATASET_ID",
    "DevelopmentCorpusError",
    "FILE",
    "FORMAT",
    "JOINED_TEXT_BYTES",
    "JOINED_TEXT_SHA256",
    "LICENSE_ARCHIVED_PATH",
    "LICENSE_BYTES",
    "LICENSE_COMPONENT",
    "LICENSE_ID",
    "LICENSE_SHA256",
    "PARTITIONS",
    "README_ARCHIVED_PATH",
    "README_BYTES",
    "README_COMPONENT",
    "README_SHA256",
    "RELEASE_TAG",
    "REPOSITORY",
    "REVISION",
    "RIGHTS_SCOPE",
    "RIGHTS_STATUS",
    "SENTENCE_COUNT",
    "SOURCE_BYTES",
    "SOURCE_SHA256",
    "SOURCE_URL",
    "SPLIT",
    "TREE",
    "expected_source_evidence_entries",
    "joined_text",
    "parse_corpus",
    "parse_record",
    "partition_bounds",
    "serialize_record",
    "verify_rights_evidence",
]
