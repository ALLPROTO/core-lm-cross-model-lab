#!/usr/bin/env python3
"""Build and verify a public, non-scientific record from a retrieved sweep export.

The tool deliberately does not load models or the codec.  It verifies the local
transfer, archive grammar, retained evidence bindings, all 28 result rows, and
the seven same-Pod replay receipts.  The Pod's structural receipt remains the
only semantic/container verification claim; this tool never relabels it as an
independent replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn


os.umask(0o077)

CLASSIFICATION = "EXPLORATORY_PUBLIC_REGRESSION_ONLY"
PUBLICATION_INPUT_SCHEMA = "corelm-runpod-adapter-publication-input-v1"
ARCHIVE_RECEIPT_SCHEMA = "corelm-runpod-adapter-archive-receipt-v1"
RECORDED_RUN_SCHEMA = "corelm-runpod-adapter-recorded-run-v1"
INDEX_SCHEMA = "corelm-runpod-adapter-recorded-run-index-v1"
ARCHIVE_NAME = "corelm-runpod-adapter-sweep-v1.tar.gz"
CHECKSUM_NAME = "SHA256SUMS"
HORIZON = 32
MAX_ARCHIVE_BYTES = 64 * 1024**3
MAX_UNCOMPRESSED_BYTES = 64 * 1024**3
MAX_MEMBERS = 4096
MAX_JSON_BYTES = 16 * 1024**2
MAX_LOG_BYTES = 64 * 1024**2
MAX_CONTAINER_BYTES = 256 * 1024**2
TRUSTED_COMMAND_TIMEOUT_SECONDS = 30.0
TRUSTED_GIT_PATH = Path("/usr/bin/git")
TRUSTED_SSH_KEYGEN_PATH = Path("/usr/bin/ssh-keygen")
LIFECYCLE_ATTESTATION_BASIS = "OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED"
LIFECYCLE_VALIDATION_SCOPE = "SCHEMA_GRAMMAR_AND_INTERNAL_CONSISTENCY_ONLY"
TOKENIZATION_ASSERTION_SCOPE = "SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED"
WORKLOAD_SOURCE_SCOPE = "LOCALLY_RECONSTRUCTED_FROM_SIGNED_SWEEP_COMMIT"
ASSET_CONTENT_SCOPE = "SAME_POD_RECEIPT_ASSETS_NOT_RETRIEVED"
EXPECTED_CODEC_COMMIT = "e7e0504b15769c925206ad1783d45a9ca0b62207"
EXPECTED_CODEC_TREE = "924d3195122e3a486e2d26e4fbdfe574654ae6c8"
EXPECTED_CODEC_FILES = {
    ".github/locks/pip-bootstrap.txt": "587c4946469d33bb2e83b0d34cbe54d0c4c4799896e5af672331e108743f1fca",
    ".github/locks/real-llm-linux-cpu-py312.txt": "0d677129d864d7fef9c1a1cc63e61db7f6dcc14f3793a21866f47dcfb5a036d8",
    "RealLLM/__init__.py": "eb31053a3bfc960633f422bf9c8a4e143acf149ba291dc3777fe9cc0659e2fdd",
    "RealLLM/benchmark_real_llm.py": "b5e7b301222501e148d54cda3f0d04997e6a061051cedc6393d1a87b638522d0",
    "RealLLM/requirements.lock": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
    "RealLLM/voidtoken_v5.py": "80ed51aa2a201dbdaae36434709a50a8a679fa84d29b08ad7b083c14cec33758",
    "platforms/linux/scripts/runtime_safety.py": "9e08377f7232b56fd83a154670b018d2668f6a1b425dd148a3ade2fbe6750af3",
    "security/verify_locked_environment.py": "5b75b13efa93abddcaa8a69310905a61dbf8f12a713c1c7a57e96f1a982e8ba9",
}
KNOWN_ATTEMPT_FAILURES = {
    ("EXECUTABLE_CACHE_SMOKE", "TRITON_NOEXEC_CACHE"),
    (
        "SWEEP_ORCHESTRATE",
        "DISTILGPT2_LEGACY_CAUSAL_MASK_INCOMPATIBILITY",
    ),
    ("PRELAUNCH_CHECK", "OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR"),
}
TRUSTED_GIT_ENVIRONMENT = {
    "GIT_CONFIG": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
RUN_DIRECTORY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}-attempt-[0-9]{2}\Z")
PRIVATE_VALUE = re.compile(
    r"(?:hf_[A-Za-z0-9]{20,}|RUNPOD_API_KEY|HF_TOKEN|SSH_(?:AUTH_SOCK|CONNECTION)|"
    r"(?:podId|pod_id|RUNPOD_POD_ID)|"
    r"(?:[A-Za-z0-9-]+[.])+(?:proxy[.])?runpod[.]net|"
    r"(?:https?|ssh|wss?)://[^\s]+|[A-Za-z0-9.-]+:[0-9]{2,5}(?:\Z|[^0-9])|"
    r"(?:^|[^0-9])(?:[0-9]{1,3}[.]){3}[0-9]{1,3}(?:[^0-9]|$)|"
    r"/(?:Users|home|private|root|tmp|workspace)(?:/|\Z))",
    re.IGNORECASE,
)

MODEL_REPLAYS = {
    "qwen2.5-0.5b": "tracked-legal-protocol-v1",
    "smollm2-135m": "tracked-source-code-v1",
    "mistral-7b-v0.1": "tracked-structured-json-v1",
    "pythia-14m": "tracked-technical-prose-v1",
    "distilgpt2": "tracked-legal-protocol-v1",
    "opt-125m": "tracked-source-code-v1",
    "gemma-2b": "tracked-structured-json-v1",
}


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    observed = set(value)
    require(
        observed == keys,
        f"{label} keys differ: missing={sorted(keys - observed)}, "
        f"extra={sorted(observed - keys)}",
    )
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def strict_json(raw: bytes, label: str, *, canonical: bool = True) -> Any:
    require(len(raw) <= MAX_JSON_BYTES, f"{label} exceeds the JSON bound")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")
    if canonical:
        require(raw == canonical_json_bytes(value) + b"\n", f"{label} is not canonical JSON plus LF")
    return value


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path, maximum: int | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            count += len(chunk)
            if maximum is not None:
                require(count <= maximum, f"file exceeds its bound: {path.name}")
            digest.update(chunk)
    return digest.hexdigest(), count


def require_digest(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{label} is invalid")
    return value


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{label} is invalid")
    return value


def require_number(value: Any, label: str, minimum: float | None = None) -> float:
    require(type(value) in {int, float} and math.isfinite(float(value)), f"{label} is not finite")
    result = float(value)
    if minimum is not None:
        require(result >= minimum, f"{label} is below its minimum")
    return result


def timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value) is not None, f"{label} is invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def safe_regular(path: Path, label: str, maximum: int) -> os.stat_result:
    status = path.lstat()
    require(stat.S_ISREG(status.st_mode), f"{label} is not regular")
    require(status.st_nlink == 1, f"{label} has unexpected hard links")
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is not private")
    require(0 < status.st_size <= maximum, f"{label} size is invalid")
    return status


def safe_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    status = absolute.lstat()
    require(stat.S_ISDIR(status.st_mode), f"{label} is not a directory")
    require(not absolute.is_symlink() and absolute.resolve(strict=True) == absolute, f"{label} traverses a symlink")
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is not private")
    return absolute


def public_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    status = absolute.lstat()
    require(stat.S_ISDIR(status.st_mode), f"{label} is not a directory")
    require(not absolute.is_symlink() and absolute.resolve(strict=True) == absolute, f"{label} traverses a symlink")
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o022 == 0, f"{label} is group/world writable")
    return absolute


def public_regular(path: Path, label: str, maximum: int) -> os.stat_result:
    status = path.lstat()
    require(stat.S_ISREG(status.st_mode), f"{label} is not regular")
    require(status.st_nlink == 1, f"{label} has unexpected hard links")
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o022 == 0, f"{label} is group/world writable")
    require(0 < status.st_size <= maximum, f"{label} size is invalid")
    return status


def read_private_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    safe_regular(path, label, MAX_JSON_BYTES)
    raw = path.read_bytes()
    value = strict_json(raw, label)
    require(isinstance(value, dict), f"{label} must be an object")
    return value, raw


@dataclass(frozen=True)
class FrozenExport:
    archive_sha256: str
    archive_bytes: int
    checksum_sha256: str
    file_inventory: list[dict[str, Any]]
    directory_inventory: list[str]
    member_count: int
    total_regular_bytes: int
    documents: dict[str, bytes]


def _stream_member(handle: BinaryIO, *, capture: bool, maximum: int) -> tuple[str, int, bytes | None]:
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if capture else None
    total = 0
    while chunk := handle.read(1024 * 1024):
        total += len(chunk)
        require(total <= maximum, "archive member exceeds its bound while reading")
        digest.update(chunk)
        if chunks is not None:
            chunks.append(chunk)
    return digest.hexdigest(), total, b"".join(chunks) if chunks is not None else None


def _tar_octal(raw: bytes, label: str) -> int:
    require(
        len(raw) >= 2
        and raw[-1:] == b"\0"
        and re.fullmatch(rb"[0-7]+", raw[:-1]) is not None,
        f"tar {label} is not canonical octal",
    )
    return int(raw[:-1], 8)


class _CanonicalTarStream:
    """Validate the exact ustar byte grammar while gzip bytes are consumed."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.payload_remaining = 0
        self.padding_remaining = 0
        self.zero_blocks = 0
        self.after_eof = False
        self.members = 0

    def feed(self, raw: bytes) -> None:
        self.buffer.extend(raw)
        while True:
            if self.payload_remaining:
                consumed = min(self.payload_remaining, len(self.buffer))
                if consumed == 0:
                    return
                del self.buffer[:consumed]
                self.payload_remaining -= consumed
                continue
            if self.padding_remaining:
                consumed = min(self.padding_remaining, len(self.buffer))
                if consumed == 0:
                    return
                require(
                    not any(self.buffer[:consumed]),
                    "tar file-data padding is not zero",
                )
                del self.buffer[:consumed]
                self.padding_remaining -= consumed
                continue
            if len(self.buffer) < 512:
                return
            block = bytes(self.buffer[:512])
            del self.buffer[:512]
            if not any(block):
                self.after_eof = True
                self.zero_blocks += 1
                continue
            require(not self.after_eof, "tar has nonzero bytes after its EOF blocks")
            self._header(block)

    def _header(self, block: bytes) -> None:
        require(len(block) == 512, "tar header size differs")
        name_field = block[0:100]
        terminator = name_field.find(b"\0")
        require(terminator > 0, "tar member name is not NUL terminated")
        require(not any(name_field[terminator + 1 :]), "tar member name padding is not zero")
        try:
            name = name_field[:terminator].decode("utf-8", "strict")
        except UnicodeDecodeError:
            fail("tar member name is not strict UTF-8")
        type_flag = block[156:157]
        require(type_flag in {b"0", b"5"}, "tar member type differs")
        expected_mode = b"0000600\0" if type_flag == b"0" else b"0000700\0"
        require(block[100:108] == expected_mode, "tar member mode differs")
        require(block[108:116] == b"0000000\0", "tar member uid differs")
        require(block[116:124] == b"0000000\0", "tar member gid differs")
        size = _tar_octal(block[124:136], "member size")
        require(block[136:148] == b"00000000000\0", "tar member mtime differs")
        require(
            re.fullmatch(rb"[0-7]{6}\0 ", block[148:156]) is not None,
            "tar checksum field differs",
        )
        stored_checksum = int(block[148:154], 8)
        checksum_block = block[:148] + b" " * 8 + block[156:]
        require(sum(checksum_block) == stored_checksum, "tar header checksum differs")
        require(block[157:257] == b"\0" * 100, "tar link field is not empty")
        require(block[257:263] == b"ustar\0" and block[263:265] == b"00", "tar ustar signature differs")
        require(block[265:329] == b"\0" * 64, "tar owner names are not empty")
        require(block[329:345] == b"\0" * 16, "tar device fields are not empty")
        require(block[345:500] == b"\0" * 155, "tar prefix field is not empty")
        require(block[500:512] == b"\0" * 12, "tar header padding is not zero")
        require((type_flag == b"5") is name.endswith("/"), "tar directory-name grammar differs")
        require(type_flag != b"5" or size == 0, "tar directory has payload bytes")
        self.members += 1
        require(self.members <= MAX_MEMBERS, "tar has too many members")
        self.payload_remaining = size
        self.padding_remaining = (-size) % 512

    def finish(self) -> None:
        if self.after_eof and any(self.buffer):
            fail("tar has nonzero bytes after its EOF blocks")
        require(not self.buffer, "tar stream is not aligned to 512-byte blocks")
        require(self.payload_remaining == 0, "tar member payload is truncated")
        require(self.padding_remaining == 0, "tar member padding is truncated")
        require(self.zero_blocks >= 2, "tar is missing its two EOF zero blocks")


def _validate_single_gzip_member(path: Path) -> int:
    """Validate canonical gzip/ustar bytes and reject every hidden suffix.

    ``tarfile`` streaming mode stops at the tar EOF and can leave bytes in the
    compressed or uncompressed stream unread.  This pass consumes the gzip
    member through CRC/ISIZE while independently checking the canonical ustar
    headers, payload padding, EOF blocks, and all remaining blocking padding.
    """

    with path.open("rb") as header_handle:
        header = header_handle.read(10)
        require(
            len(header) == 10
            and header[:8] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00"
            and header[8] in {0, 2}
            and header[9] in {3, 255},
            "gzip header is not canonical no-name, zero-mtime output",
        )
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    tar_stream = _CanonicalTarStream()
    uncompressed_bytes = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                require(not decompressor.eof, "gzip archive has trailing compressed bytes")
                pending = chunk
                while pending:
                    output = decompressor.decompress(pending, 1024 * 1024)
                    uncompressed_bytes += len(output)
                    require(
                        uncompressed_bytes <= MAX_UNCOMPRESSED_BYTES,
                        "gzip uncompressed bytes exceed the bound",
                    )
                    tar_stream.feed(output)
                    require(
                        not decompressor.unused_data,
                        "gzip archive has a second member or trailing bytes",
                    )
                    if decompressor.eof:
                        pending = b""
                    elif decompressor.unconsumed_tail:
                        pending = decompressor.unconsumed_tail
                    else:
                        pending = b""
    except zlib.error as error:
        fail(f"gzip archive is corrupt or has an invalid trailer: {error}")
    require(decompressor.eof, "gzip archive is truncated before its trailer")
    require(not decompressor.unused_data, "gzip archive has trailing bytes")
    flushed = decompressor.flush()
    uncompressed_bytes += len(flushed)
    require(uncompressed_bytes <= MAX_UNCOMPRESSED_BYTES, "gzip uncompressed bytes exceed the bound")
    tar_stream.feed(flushed)
    tar_stream.finish()
    return uncompressed_bytes


def read_export(export_dir: Path) -> FrozenExport:
    root = safe_directory(export_dir, "retrieved export directory")
    require({entry.name for entry in root.iterdir()} == {ARCHIVE_NAME, CHECKSUM_NAME}, "retrieved export inventory differs")
    archive_path = root / ARCHIVE_NAME
    checksum_path = root / CHECKSUM_NAME
    archive_status = safe_regular(archive_path, "retrieved archive", MAX_ARCHIVE_BYTES)
    safe_regular(checksum_path, "retrieved checksum", 1024)
    checksum_raw = checksum_path.read_bytes()
    match = re.fullmatch(
        rb"([0-9a-f]{64})  corelm-runpod-adapter-sweep-v1[.]tar[.]gz\n",
        checksum_raw,
    )
    require(match is not None, "SHA256SUMS grammar differs")
    expected_archive_sha = match.group(1).decode("ascii")
    observed_archive_sha, observed_archive_bytes = sha256_file(archive_path, MAX_ARCHIVE_BYTES)
    require(observed_archive_bytes == archive_status.st_size, "archive size changed during hashing")
    require(observed_archive_sha == expected_archive_sha, "retrieved archive checksum differs")
    _validate_single_gzip_member(archive_path)

    documents: dict[str, bytes] = {}
    inventory: list[dict[str, Any]] = []
    paths: set[str] = set()
    directories: list[str] = []
    member_count = 0
    total_regular = 0
    with archive_path.open("rb") as archive_handle:
        with tarfile.open(fileobj=archive_handle, mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                require(member_count <= MAX_MEMBERS, "archive has too many members")
                raw_name = member.name
                normalized = raw_name[:-1] if raw_name.endswith("/") else raw_name
                pure = PurePosixPath(normalized)
                require(
                    normalized == pure.as_posix()
                    and not pure.is_absolute()
                    and pure.parts
                    and pure.parts[0] == "evidence"
                    and ".." not in pure.parts,
                    f"unsafe archive member: {raw_name!r}",
                )
                require(normalized not in paths, f"duplicate archive member: {normalized}")
                paths.add(normalized)
                require(member.uid == 0 and member.gid == 0 and member.mtime == 0, f"archive metadata differs: {normalized}")
                require(not getattr(member, "sparse", None), f"sparse archive member is forbidden: {normalized}")
                if member.isdir():
                    require(member.mode & 0o777 == 0o700, f"archive directory mode differs: {normalized}")
                    directories.append(normalized)
                    continue
                require(member.isfile(), f"unsafe archive member type: {normalized}")
                require(member.mode & 0o777 == 0o600, f"archive file mode differs: {normalized}")
                if normalized.endswith(".json"):
                    maximum = MAX_JSON_BYTES
                    capture = True
                elif normalized.endswith(".sha256"):
                    maximum = 1024
                    capture = True
                elif normalized == "evidence/source-identity.txt":
                    maximum = 64 * 1024
                    capture = True
                elif normalized.endswith(".log"):
                    maximum = MAX_LOG_BYTES
                    minimum = 0
                    capture = False
                elif normalized.endswith(".vtl5"):
                    maximum = MAX_CONTAINER_BYTES
                    capture = False
                else:
                    fail(f"unregistered archive file suffix: {normalized}")
                if not normalized.endswith(".log"):
                    minimum = 1
                require(minimum <= member.size <= maximum, f"archive member size differs: {normalized}")
                extracted = archive.extractfile(member)
                require(extracted is not None, f"archive member cannot be read: {normalized}")
                observed_sha, observed_size, captured = _stream_member(extracted, capture=capture, maximum=maximum)
                require(observed_size == member.size, f"archive member size changed: {normalized}")
                total_regular += member.size
                require(total_regular <= MAX_UNCOMPRESSED_BYTES, "archive uncompressed bytes exceed the bound")
                inventory.append({"path": normalized, "bytes": member.size, "sha256": observed_sha})
                if captured is not None:
                    require(len(captured) == member.size, f"captured archive member size changed: {normalized}")
                    documents[normalized] = captured
    require(member_count > 0 and inventory, "archive is empty")
    inventory.sort(key=lambda entry: entry["path"].encode("utf-8"))
    return FrozenExport(
        archive_sha256=observed_archive_sha,
        archive_bytes=observed_archive_bytes,
        checksum_sha256=sha256_bytes(checksum_raw),
        file_inventory=inventory,
        directory_inventory=sorted(directories, key=lambda value: value.encode("utf-8")),
        member_count=member_count,
        total_regular_bytes=total_regular,
        documents=documents,
    )


def _document(export: FrozenExport, relative: str) -> bytes:
    path = f"evidence/{relative}"
    require(path in export.documents, f"archive document is absent: {path}")
    return export.documents[path]


def _json_document(export: FrozenExport, relative: str) -> dict[str, Any]:
    raw = _document(export, relative)
    value = strict_json(raw, f"evidence/{relative}")
    require(isinstance(value, dict), f"evidence/{relative} must be an object")
    return value


def _inventory_map(export: FrozenExport) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in export.file_inventory}


def _verify_sidecar(export: FrozenExport, relative: str) -> str:
    raw = _document(export, relative)
    sidecar = _document(export, relative + ".sha256")
    digest = sha256_bytes(raw)
    expected = f"{digest}  {Path(relative).name}\n".encode("ascii")
    require(sidecar == expected, f"digest sidecar differs: evidence/{relative}")
    return digest


def parse_source_identity(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"source identity is not UTF-8: {error}")
    require(text.endswith("\n") and "\r" not in text and "\x00" not in text, "source identity grammar differs")
    result: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        require(line.count("=") == 1, "source identity line grammar differs")
        key, value = line.split("=", 1)
        require(key and value and key not in result, "source identity key/value differs")
        require(PRIVATE_VALUE.search(value) is None, f"source identity contains a private value: {key}")
        result[key] = value
    exact_object(
        result,
        {
            "schemaVersion",
            "sweepCommit",
            "sweepTree",
            "commitSignatureTrustRootSHA256",
            "sweepCommitSignatureVerified",
            "codecCommit",
            "codecTree",
            "codecCommitSignatureVerified",
            "classification",
            "scientificEvidence",
            "countsTowardScientificVerdict",
            "containerImageDigest",
            "containerImageDigestAuthority",
            "gpuName",
            "gpuMemoryMiB",
            "gpuDriverVersion",
            "cgroupVersion",
            "cgroupCpuQuota",
            "cgroupCpuPeriod",
            "cgroupMemoryMax",
            "codecRequirementsSHA256",
            "pipBootstrapLockSHA256",
            "portableRuntimeLockSHA256",
            "cudaTorchLockSHA256",
        },
        "source identity",
    )
    require(result["schemaVersion"] == "corelm-runpod-adapter-sweep-source-v1", "source identity schema differs")
    require_digest(result["sweepCommit"], "sweep commit", HEX40)
    require_digest(result["sweepTree"], "sweep tree", HEX40)
    require_digest(result["codecCommit"], "codec commit", HEX40)
    require_digest(result["codecTree"], "codec tree", HEX40)
    for name in (
        "commitSignatureTrustRootSHA256",
        "codecRequirementsSHA256",
        "pipBootstrapLockSHA256",
        "portableRuntimeLockSHA256",
        "cudaTorchLockSHA256",
    ):
        require_digest(result[name], name)
    require_digest(result["containerImageDigest"], "container image digest", IMAGE_DIGEST)
    require(result["sweepCommitSignatureVerified"] == "true", "sweep signature was not verified")
    require(result["codecCommitSignatureVerified"] == "true", "codec signature was not verified")
    require(result["classification"] == CLASSIFICATION, "source classification differs")
    require(result["scientificEvidence"] == "false", "source identity makes a scientific claim")
    require(result["countsTowardScientificVerdict"] == "false", "source identity counts toward a scientific verdict")
    require(result["containerImageDigestAuthority"] == "operator-supplied-control-plane-value", "image digest authority differs")
    require(result["cgroupVersion"] in {"v1", "v2"}, "cgroup version differs")
    for name in ("gpuMemoryMiB", "cgroupCpuPeriod"):
        require(re.fullmatch(r"[0-9]+", result[name]) is not None, f"source identity {name} differs")
    for name in ("cgroupCpuQuota", "cgroupMemoryMax"):
        require(result[name] == "max" or re.fullmatch(r"[0-9]+", result[name]) is not None, f"source identity {name} differs")
    require(re.fullmatch(r"[0-9]+(?:[.][0-9]+){1,3}", result["gpuDriverVersion"]) is not None, "GPU driver differs")
    return result


def load_repository_inputs(repository: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes]]:
    root = Path(os.path.abspath(repository))
    suite = root / "runpod-adapter-sweep-v1"
    documents: dict[str, bytes] = {}
    values: dict[str, dict[str, Any]] = {}
    for name in ("profiles.json", "workloads.json"):
        raw = (suite / name).read_bytes()
        value = strict_json(raw, name, canonical=name != "workloads.json")
        require(isinstance(value, dict), f"{name} must be an object")
        documents[name] = raw
        values[name] = value
    documents["PROTOCOL.md"] = (suite / "PROTOCOL.md").read_bytes()
    documents["torch-linux-cu130-py312.txt"] = (
        suite / "torch-linux-cu130-py312.txt"
    ).read_bytes()
    return values["profiles.json"], values["workloads.json"], documents


def _trusted_executable(path: Path, label: str) -> None:
    status = path.lstat()
    require(stat.S_ISREG(status.st_mode), f"trusted {label} path is not a regular file")
    require(status.st_uid == 0, f"trusted {label} is not owned by root")
    require(status.st_mode & 0o022 == 0, f"trusted {label} is group/world writable")
    require(status.st_mode & 0o111 != 0, f"trusted {label} is not executable")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        fail("trusted Git process group survived SIGKILL")


def _trusted_git(
    repository: Path,
    arguments: list[str],
    *,
    label: str,
    maximum_output_bytes: int | None,
) -> bytes:
    require(arguments and all(isinstance(item, str) and "\0" not in item for item in arguments), f"{label} argv is invalid")
    require(maximum_output_bytes is None or maximum_output_bytes >= 0, f"{label} output bound is invalid")
    command = [
        str(TRUSTED_GIT_PATH),
        "--no-pager",
        "--no-replace-objects",
        "-C",
        str(repository),
        *arguments,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if maximum_output_bytes is not None else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=dict(TRUSTED_GIT_ENVIRONMENT),
        close_fds=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + TRUSTED_COMMAND_TIMEOUT_SECONDS
    output = bytearray()
    selector: selectors.BaseSelector | None = None
    pipe_open = maximum_output_bytes is not None
    try:
        if pipe_open:
            require(process.stdout is not None, f"{label} stdout pipe is absent")
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
        while process.poll() is None or pipe_open:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                fail(f"{label} timed out")
            if not pipe_open:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    _kill_process_group(process)
                    fail(f"{label} timed out")
                continue
            assert selector is not None and process.stdout is not None
            events = selector.select(timeout=min(remaining, 0.25))
            for key, _ in events:
                assert maximum_output_bytes is not None
                capacity = maximum_output_bytes + 1 - len(output)
                if capacity <= 0:
                    _kill_process_group(process)
                    fail(f"{label} exceeded its output bound")
                chunk = os.read(key.fd, min(64 * 1024, capacity))
                if chunk:
                    output.extend(chunk)
                    if len(output) > maximum_output_bytes:
                        _kill_process_group(process)
                        fail(f"{label} exceeded its output bound")
                else:
                    selector.unregister(process.stdout)
                    process.stdout.close()
                    pipe_open = False
        return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException:
        if process.poll() is None:
            _kill_process_group(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
    require(return_code == 0, f"{label} failed")
    return bytes(output)


def _trusted_git_blob(
    repository: Path,
    commit: str,
    relative: str,
    *,
    expected_bytes: int,
    label: str,
) -> bytes:
    require(
        relative == PurePosixPath(relative).as_posix()
        and not PurePosixPath(relative).is_absolute()
        and ".." not in PurePosixPath(relative).parts,
        f"{label} path is unsafe",
    )
    object_specification = f"{commit}:{relative}"
    object_type = _trusted_git(
        repository,
        ["cat-file", "-t", object_specification],
        label=f"{label} object-type query",
        maximum_output_bytes=16,
    )
    require(object_type == b"blob\n", f"{label} is not a Git blob")
    size_raw = _trusted_git(
        repository,
        ["cat-file", "-s", object_specification],
        label=f"{label} byte-count query",
        maximum_output_bytes=32,
    )
    require(re.fullmatch(rb"[0-9]+\n", size_raw) is not None, f"{label} byte count is invalid")
    require(int(size_raw) == expected_bytes, f"{label} byte count differs")
    return _trusted_git(
        repository,
        ["cat-file", "blob", object_specification],
        label=f"{label} blob read",
        maximum_output_bytes=expected_bytes,
    )


def _trusted_workload_blob(
    repository: Path,
    commit: str,
    relative: str,
) -> tuple[bytes, dict[str, Any]]:
    pure = PurePosixPath(relative)
    require(
        isinstance(relative, str)
        and relative == pure.as_posix()
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "\0" not in relative
        and "\n" not in relative
        and "\r" not in relative,
        "registered workload path is unsafe",
    )
    tree_entry = _trusted_git(
        repository,
        ["ls-tree", "-z", commit, "--", relative],
        label=f"workload tree entry {relative}",
        maximum_output_bytes=len(relative.encode("utf-8")) + 128,
    )
    require(
        tree_entry.endswith(b"\0") and tree_entry.count(b"\0") == 1,
        f"workload source does not resolve to one Git tree entry: {relative}",
    )
    try:
        header, recorded_path = tree_entry[:-1].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        tree_path = recorded_path.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"workload Git tree entry is invalid for {relative}: {error}")
    require(
        mode in {"100644", "100755"}
        and object_type == "blob"
        and HEX40.fullmatch(object_id) is not None
        and tree_path == relative,
        f"workload source is not one exact regular Git blob: {relative}",
    )
    size_raw = _trusted_git(
        repository,
        ["cat-file", "-s", object_id],
        label=f"workload byte count {relative}",
        maximum_output_bytes=32,
    )
    require(re.fullmatch(rb"[0-9]+\n", size_raw) is not None, f"workload byte count is invalid: {relative}")
    byte_count = int(size_raw)
    require(0 < byte_count <= MAX_JSON_BYTES, f"workload blob size is invalid: {relative}")
    raw = _trusted_git(
        repository,
        ["show", "--no-textconv", f"{commit}:{relative}"],
        label=f"workload blob {relative}",
        maximum_output_bytes=byte_count,
    )
    require(len(raw) == byte_count, f"workload blob byte count changed: {relative}")
    git_object = b"blob " + str(byte_count).encode("ascii") + b"\0" + raw
    try:
        computed_object_id = hashlib.sha1(git_object, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - older Python without the keyword
        computed_object_id = hashlib.sha1(git_object).hexdigest()
    require(computed_object_id == object_id, f"workload Git blob digest differs: {relative}")
    require(b"\0" not in raw, f"workload source contains NUL: {relative}")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"workload source is not strict UTF-8: {relative}: {error}")
    return raw, {
        "path": relative,
        "gitMode": mode,
        "gitBlobSHA1": object_id,
        "bytes": byte_count,
        "sha256": sha256_bytes(raw),
    }


def _reconstruct_workload_binding(
    repository: Path,
    commit: str,
    workloads_document: dict[str, Any],
    workload: dict[str, Any],
) -> dict[str, Any]:
    contract = exact_object(
        workloads_document.get("concatenation"),
        {
            "algorithm",
            "beginFrame",
            "contentBytes",
            "contentEncoding",
            "endFrame",
            "instructionBeginFrame",
            "instructionEndFrame",
            "normalization",
            "pathEncoding",
            "pathOrder",
        },
        "workload concatenation contract",
    )
    require(
        contract
        == {
            "algorithm": "corelm-tracked-utf8-file-frames-v1",
            "beginFrame": "===== BEGIN CORELM TRACKED FILE: {path} =====\n",
            "contentBytes": "exact-git-head-blob",
            "contentEncoding": "utf-8-strict",
            "endFrame": "\n===== END CORELM TRACKED FILE: {path} =====\n",
            "instructionBeginFrame": "===== BEGIN OPERATOR REQUEST =====\n",
            "instructionEndFrame": "\n===== END OPERATOR REQUEST =====\n",
            "normalization": "none",
            "pathEncoding": "utf-8",
            "pathOrder": "ascending-posix-bytewise",
        },
        "workload concatenation contract differs",
    )
    paths = workload.get("paths")
    require(
        isinstance(paths, list)
        and paths
        and len(paths) == len(set(paths))
        and paths == sorted(paths, key=lambda value: value.encode("utf-8")),
        f"workload {workload.get('workloadId')} path order differs",
    )
    instruction = workload.get("instruction")
    require(isinstance(instruction, str) and instruction.strip(), "workload instruction is empty")
    chunks = [
        contract["instructionBeginFrame"],
        instruction,
        contract["instructionEndFrame"],
    ]
    inventory: list[dict[str, Any]] = []
    tracked_bytes = 0
    for relative in paths:
        raw, item = _trusted_workload_blob(repository, commit, relative)
        chunks.extend(
            (
                contract["beginFrame"].format(path=relative),
                raw.decode("utf-8", errors="strict"),
                contract["endFrame"].format(path=relative),
            )
        )
        inventory.append(item)
        tracked_bytes += item["bytes"]
    require(
        tracked_bytes >= require_int(
            workload.get("minimumTrackedUtf8Bytes"),
            f"workload {workload.get('workloadId')} byte floor",
            1,
        ),
        f"workload {workload.get('workloadId')} is shorter than its registered byte floor",
    )
    framed = "".join(chunks).encode("utf-8")
    return {
        "category": workload["contentClass"],
        "promptUTF8SHA256": sha256_bytes(framed),
        "framedUTF8Bytes": len(framed),
        "sourceFiles": inventory,
    }


def verify_git_source(
    repository: Path,
    source: dict[str, Any],
    run: dict[str, Any],
    local_documents: dict[str, bytes],
) -> None:
    repository = public_directory(repository, "Git source repository")
    require("\n" not in str(repository) and "\r" not in str(repository), "Git source path contains a control character")
    _trusted_executable(TRUSTED_GIT_PATH, "Git")
    _trusted_executable(TRUSTED_SSH_KEYGEN_PATH, "ssh-keygen")
    commit = source["sweepCommit"]
    tree_raw = _trusted_git(
        repository,
        ["rev-parse", "--verify", f"{commit}^{{tree}}"],
        label="sweep tree resolution",
        maximum_output_bytes=65,
    )
    require(re.fullmatch(rb"[0-9a-f]{40}\n", tree_raw) is not None, "resolved sweep tree is invalid")
    tree = tree_raw[:-1].decode("ascii")
    require(tree == source["sweepTree"] == run["source"]["tree"], "local Git tree binding differs")
    require(run["source"] == {"commit": commit, "tree": tree, "branch": "HEAD"}, "run source identity differs")
    for filename, raw in local_documents.items():
        relative = f"runpod-adapter-sweep-v1/{filename}"
        observed = _trusted_git_blob(
            repository,
            commit,
            relative,
            expected_bytes=len(raw),
            label=f"registered source {relative}",
        )
        require(observed == raw, f"registered source bytes differ from signed commit: {relative}")
    allowed = repository / "v4/signing/allowed_signers"
    public_regular(allowed, "local allowed signers", 64 * 1024)
    allowed_raw = allowed.read_bytes()
    allowed_sha = sha256_bytes(allowed_raw)
    require(allowed_sha == source["commitSignatureTrustRootSHA256"], "local signature trust root differs")
    committed_allowed = _trusted_git_blob(
        repository,
        commit,
        "v4/signing/allowed_signers",
        expected_bytes=len(allowed_raw),
        label="committed allowed signers",
    )
    require(committed_allowed == allowed_raw, "local allowed signers differ from the signed commit")
    require(sha256_bytes(committed_allowed) == source["commitSignatureTrustRootSHA256"], "committed signature trust root differs")
    _trusted_git(
        repository,
        [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed}",
            "-c",
            f"gpg.ssh.program={TRUSTED_SSH_KEYGEN_PATH}",
            "verify-commit",
            commit,
        ],
        label="local sweep commit signature verification",
        maximum_output_bytes=None,
    )


def verify_publication_input(value: dict[str, Any], source: dict[str, str], archive_sha256: str) -> dict[str, Any]:
    exact_object(
        value,
        {
            "schemaVersion",
            "recordedAt",
            "successfulAttemptNumber",
            "attempts",
            "lifecycle",
            "operatorVerification",
        },
        "publication input",
    )
    require(value["schemaVersion"] == PUBLICATION_INPUT_SCHEMA, "publication input schema differs")
    recorded_at = timestamp(value["recordedAt"], "recordedAt")
    successful = require_int(value["successfulAttemptNumber"], "successful attempt", 1)
    attempts = value["attempts"]
    require(isinstance(attempts, list) and attempts, "attempt history is empty")
    require([entry.get("attemptNumber") for entry in attempts] == list(range(1, successful + 1)), "attempt history is not contiguous")
    for entry in attempts:
        exact_object(
            entry,
            {
                "attemptNumber",
                "status",
                "sourceCommit",
                "sourceTree",
                "failureStage",
                "failureCode",
                "forensics",
                "generatedRunRootDisposition",
            },
            "attempt history entry",
        )
        require_int(entry["attemptNumber"], "attempt number", 1)
        require_digest(entry["sourceCommit"], "attempt source commit", HEX40)
        require_digest(entry["sourceTree"], "attempt source tree", HEX40)
        require(
            entry["generatedRunRootDisposition"]
            in {
                "REMOVED_AFTER_BOUNDED_FORENSICS",
                "NO_RUN_ROOT_CREATED_BOUNDED_FORENSICS_RETAINED",
                "ARCHIVE_RETRIEVED_AND_VERIFIED",
            },
            "attempt run-root disposition differs",
        )
        if entry["attemptNumber"] < successful:
            require(entry["status"] == "INCOMPLETE", "a prior attempt is not marked incomplete")
            require(
                isinstance(entry["failureStage"], str)
                and re.fullmatch(r"[A-Z0-9_]+", entry["failureStage"]) is not None,
                "prior attempt failure stage differs",
            )
            require(isinstance(entry["failureCode"], str) and re.fullmatch(r"[A-Z0-9_]+", entry["failureCode"]), "prior attempt failure code differs")
            failure_pair = (entry["failureStage"], entry["failureCode"])
            require(
                PRIVATE_VALUE.search(entry["failureStage"]) is None
                and PRIVATE_VALUE.search(entry["failureCode"]) is None,
                "prior attempt failure identifiers contain a private value",
            )
            require(failure_pair in KNOWN_ATTEMPT_FAILURES, "prior attempt failure pair is not registered")
            forensic = exact_object(entry["forensics"], {"bytes", "manifestSHA256"}, "attempt forensics")
            require_int(forensic["bytes"], "forensics bytes", 1)
            require_digest(forensic["manifestSHA256"], "forensics manifest digest")
            expected_disposition = (
                "NO_RUN_ROOT_CREATED_BOUNDED_FORENSICS_RETAINED"
                if failure_pair
                == ("PRELAUNCH_CHECK", "OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR")
                else "REMOVED_AFTER_BOUNDED_FORENSICS"
            )
            require(
                entry["generatedRunRootDisposition"] == expected_disposition,
                "prior attempt disposition differs for its failure pair",
            )
        else:
            require(entry["status"] == "COMPLETE", "successful attempt is not complete")
            require(entry["failureStage"] is None and entry["failureCode"] is None and entry["forensics"] is None, "successful attempt contains failure data")
            require(entry["sourceCommit"] == source["sweepCommit"], "successful attempt commit differs")
            require(entry["sourceTree"] == source["sweepTree"], "successful attempt tree differs")
            require(entry["generatedRunRootDisposition"] == "ARCHIVE_RETRIEVED_AND_VERIFIED", "successful attempt disposition differs")

    lifecycle = exact_object(
        value["lifecycle"],
        {
            "attestationBasis",
            "builderValidationScope",
            "providerVerified",
            "platform",
            "isolationBoundary",
            "createdAt",
            "terminatedAt",
            "providerObservedCostUSD",
            "providerObservedTimeBilledMs",
            "providerObservedEffectiveHourlyRateUSD",
            "costObservationBasis",
            "currency",
            "admissionProjectedCombinedHourlyRateUSD",
            "costCeilingUSD",
            "providerTerminationFuseHours",
            "containerImageDigest",
            "podTerminated",
            "podVolumeDeleted",
            "networkVolumeUsed",
            "runpodSecretDeleted",
            "huggingFaceTokenRevoked",
            "lifecycleApiKeyRevoked",
            "sshCredentialRetired",
        },
        "lifecycle",
    )
    require(
        lifecycle["attestationBasis"] == LIFECYCLE_ATTESTATION_BASIS,
        "lifecycle attestation basis differs",
    )
    require(
        lifecycle["builderValidationScope"] == LIFECYCLE_VALIDATION_SCOPE,
        "lifecycle builder-validation scope differs",
    )
    require(lifecycle["providerVerified"] is False, "lifecycle data falsely claims provider verification")
    require(lifecycle["platform"] == "RunPod Pod", "platform differs")
    require(lifecycle["isolationBoundary"] == "PROVIDER_MANAGED_CONTAINER_NOT_INDEPENDENT_VM", "isolation boundary differs")
    created = timestamp(lifecycle["createdAt"], "Pod creation time")
    terminated = timestamp(lifecycle["terminatedAt"], "Pod termination time")
    require(created <= terminated <= recorded_at, "lifecycle timestamps differ")
    observed_cost = require_number(
        lifecycle["providerObservedCostUSD"], "provider-observed cost", 0
    )
    require(observed_cost > 0, "provider-observed cost must be positive")
    ceiling = require_number(lifecycle["costCeilingUSD"], "cost ceiling", 0)
    require(observed_cost <= ceiling == 35.0, "cost ceiling was exceeded or changed")
    billed_ms = require_int(
        lifecycle["providerObservedTimeBilledMs"], "provider-observed billed milliseconds", 1
    )
    wall_ms = int((terminated - created).total_seconds() * 1000)
    require(billed_ms <= wall_ms, "provider-observed billed duration exceeds Pod wall time")
    observed_rate = require_number(
        lifecycle["providerObservedEffectiveHourlyRateUSD"],
        "provider-observed effective hourly rate",
        0,
    )
    require(observed_rate > 0, "provider-observed effective hourly rate must be positive")
    require(
        math.isclose(
            observed_rate,
            observed_cost * 3_600_000 / billed_ms,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ),
        "provider-observed cost, duration, and effective rate differ",
    )
    projected_rate = require_number(
        lifecycle["admissionProjectedCombinedHourlyRateUSD"],
        "admission-projected combined hourly rate",
        0,
    )
    require(projected_rate > 0, "admission-projected combined hourly rate must be positive")
    require(projected_rate <= 1.75, "projected combined hourly rate exceeded the admission cap")
    require(observed_rate <= 1.75, "provider-observed effective hourly rate exceeded the admission cap")
    require(
        lifecycle["costObservationBasis"]
        == "RUNPOD_BILLING_API_FINAL_SO_FAR_AFTER_POD_ABSENCE_BEFORE_KEY_REVOCATION",
        "cost observation basis differs",
    )
    require(lifecycle["currency"] == "USD", "currency differs")
    require(lifecycle["providerTerminationFuseHours"] == 20, "provider fuse differs")
    require(lifecycle["containerImageDigest"] == source["containerImageDigest"], "lifecycle image digest differs")
    for name in (
        "podTerminated",
        "podVolumeDeleted",
        "runpodSecretDeleted",
        "huggingFaceTokenRevoked",
        "lifecycleApiKeyRevoked",
        "sshCredentialRetired",
    ):
        require(lifecycle[name] is True, f"operator lifecycle attestation does not state completion: {name}")
    require(lifecycle["networkVolumeUsed"] is False, "a network volume was used")

    verification = exact_object(
        value["operatorVerification"],
        {
            "kind",
            "independentHumanReview",
            "independentReplication",
            "localArchiveChecksumVerified",
            "localArchiveInventoryVerified",
            "podStructuralVerifier",
            "modelReplayReceipts",
            "archiveSHA256",
        },
        "operator verification",
    )
    require(verification["kind"] == "AUTHOR_SELF_VERIFICATION", "operator verification kind differs")
    require(verification["independentHumanReview"] is False, "independent human review is falsely claimed")
    require(verification["independentReplication"] is False, "independent replication is falsely claimed")
    require(verification["localArchiveChecksumVerified"] is True, "local archive checksum was not verified")
    require(verification["localArchiveInventoryVerified"] is True, "local archive inventory was not verified")
    require(verification["podStructuralVerifier"] == "SAME_POD_SAME_SOURCE_RUNTIME_CACHE", "Pod verifier boundary differs")
    require(verification["modelReplayReceipts"] == 7, "model replay receipt count differs")
    require(verification["archiveSHA256"] == archive_sha256, "operator archive digest differs")
    return value


def _validate_behavior(
    value: Any,
    label: str,
    *,
    vocabulary_size: int | None = None,
) -> dict[str, Any]:
    behavior = exact_object(
        value,
        {
            "predictionTokens",
            "controlledTop1AgreementCount",
            "controlledTop1Agreement",
            "meanKLDivergenceNat",
            "meanBaselineSelectedTokenSurprisalDeltaNat",
            "maxAbsLogitDifference",
            "perTokenKLDivergenceNat",
            "perTokenBaselineSelectedTokenSurprisalDeltaNat",
            "perTokenMaxAbsLogitDifference",
            "baselineTokenIds",
            "controlledCandidateTop1TokenIds",
            "candidateFreeRunTokenIds",
            "freeRunExact",
            "freeRunSamePositionCount",
            "freeRunLongestCommonPrefixTokens",
            "baselineContinuation",
            "candidateFreeRunContinuation",
        },
        label,
    )
    require(behavior["predictionTokens"] == HORIZON, f"{label} horizon differs")
    for name in ("baselineTokenIds", "controlledCandidateTop1TokenIds", "candidateFreeRunTokenIds"):
        values = behavior[name]
        require(isinstance(values, list) and len(values) == HORIZON, f"{label} {name} length differs")
        require(
            all(
                type(item) is int
                and item >= 0
                and (vocabulary_size is None or item < vocabulary_size)
                for item in values
            ),
            f"{label} {name} differs",
        )
    for name in (
        "perTokenKLDivergenceNat",
        "perTokenBaselineSelectedTokenSurprisalDeltaNat",
        "perTokenMaxAbsLogitDifference",
    ):
        values = behavior[name]
        require(isinstance(values, list) and len(values) == HORIZON, f"{label} {name} length differs")
        require(all(type(item) in {int, float} and math.isfinite(float(item)) for item in values), f"{label} {name} is non-finite")
    require(
        all(float(item) >= -1e-4 for item in behavior["perTokenKLDivergenceNat"]),
        f"{label} per-token KL is materially negative",
    )
    require(
        all(float(item) >= 0 for item in behavior["perTokenMaxAbsLogitDifference"]),
        f"{label} per-token logit difference is negative",
    )
    baseline = behavior["baselineTokenIds"]
    controlled = behavior["controlledCandidateTop1TokenIds"]
    free = behavior["candidateFreeRunTokenIds"]
    agreement = sum(left == right for left, right in zip(baseline, controlled))
    recorded_agreement = require_int(
        behavior["controlledTop1AgreementCount"],
        f"{label} top-1 count",
        0,
    )
    require(recorded_agreement <= HORIZON and recorded_agreement == agreement, f"{label} top-1 count differs")
    recorded_ratio = require_number(behavior["controlledTop1Agreement"], f"{label} top-1 ratio", 0)
    require(recorded_ratio <= 1 and math.isclose(recorded_ratio, agreement / HORIZON, rel_tol=0, abs_tol=1e-15), f"{label} top-1 ratio differs")
    mean_kl = sum(float(item) for item in behavior["perTokenKLDivergenceNat"]) / HORIZON
    mean_surprisal = sum(float(item) for item in behavior["perTokenBaselineSelectedTokenSurprisalDeltaNat"]) / HORIZON
    maximum = max(float(item) for item in behavior["perTokenMaxAbsLogitDifference"])
    recorded_mean_kl = require_number(behavior["meanKLDivergenceNat"], f"{label} mean KL")
    recorded_mean_surprisal = require_number(behavior["meanBaselineSelectedTokenSurprisalDeltaNat"], f"{label} mean surprisal")
    recorded_maximum = require_number(behavior["maxAbsLogitDifference"], f"{label} max logit difference", 0)
    require(math.isclose(recorded_mean_kl, mean_kl, rel_tol=2e-6, abs_tol=2e-5), f"{label} mean KL differs")
    require(recorded_mean_kl >= -1e-4, f"{label} mean KL is materially negative")
    require(math.isclose(recorded_mean_surprisal, mean_surprisal, rel_tol=2e-6, abs_tol=2e-5), f"{label} mean surprisal differs")
    require(math.isclose(recorded_maximum, maximum, rel_tol=2e-6, abs_tol=2e-5), f"{label} max logit difference differs")
    same = sum(left == right for left, right in zip(baseline, free))
    prefix = 0
    for left, right in zip(baseline, free):
        if left != right:
            break
        prefix += 1
    require(behavior["freeRunExact"] is (baseline == free), f"{label} free-run exactness differs")
    recorded_same = require_int(behavior["freeRunSamePositionCount"], f"{label} free-run same-position count", 0)
    recorded_prefix = require_int(behavior["freeRunLongestCommonPrefixTokens"], f"{label} free-run prefix", 0)
    require(recorded_same <= HORIZON and recorded_same == same, f"{label} free-run same-position count differs")
    require(recorded_prefix <= HORIZON and recorded_prefix == prefix, f"{label} free-run prefix differs")
    require(all(isinstance(behavior[name], str) for name in ("baselineContinuation", "candidateFreeRunContinuation")), f"{label} continuation differs")
    return behavior


def _validate_converted_weights(value: Any, label: str) -> dict[str, Any]:
    converted = exact_object(
        value,
        {
            "bytes",
            "conversion",
            "environment",
            "path",
            "sha256",
            "sourcePath",
            "sourceSha256",
            "sourceTensorEqualityVerified",
        },
        label,
    )
    require_int(converted["bytes"], f"{label} bytes", 1)
    require(converted["conversion"] == "torch-weights-only-to-safetensors-v1", f"{label} conversion differs")
    require(converted["path"] == "model.safetensors" and converted["sourcePath"] == "pytorch_model.bin", f"{label} paths differ")
    require_digest(converted["sha256"], f"{label} digest")
    require_digest(converted["sourceSha256"], f"{label} source digest")
    require(converted["sourceTensorEqualityVerified"] is True, f"{label} tensor equality was not verified")
    environment = exact_object(
        converted["environment"],
        {
            "boundary",
            "credentialNamesPresent",
            "hfHubOffline",
            "implicitTokenDisabled",
            "pythonFlags",
            "transformersOffline",
        },
        f"{label} environment",
    )
    require(
        environment
        == {
            "boundary": "application-offline-single-purpose-process",
            "credentialNamesPresent": [],
            "hfHubOffline": True,
            "implicitTokenDisabled": True,
            "pythonFlags": ["-E", "-s", "-B"],
            "transformersOffline": True,
        },
        f"{label} environment differs",
    )
    return converted


def _validate_asset_receipts(
    raw_assets: dict[str, Any],
    assets: dict[str, Any],
    conversion: dict[str, Any],
    profiles: list[dict[str, Any]],
    profiles_sha256: str,
) -> None:
    model_order = [profile["modelId"] for profile in profiles]
    receipt_files: dict[str, list[list[dict[str, Any]]]] = {}
    for receipt, expected_status, label in (
        (raw_assets, "RAW_ASSETS_VERIFIED", "raw asset receipt"),
        (assets, "ASSETS_VERIFIED", "asset receipt"),
    ):
        exact_object(
            receipt,
            {"schemaVersion", "status", "modelOrder", "profilesSHA256", "profiles"},
            label,
        )
        require(receipt["schemaVersion"] == "corelm-runpod-adapter-assets-v1", f"{label} schema differs")
        require(receipt["status"] == expected_status, f"{label} status differs")
        require(receipt["modelOrder"] == model_order, f"{label} model order differs")
        require(receipt["profilesSHA256"] == profiles_sha256, f"{label} profile digest differs")
        entries = receipt["profiles"]
        require(isinstance(entries, list) and len(entries) == len(profiles), f"{label} profile count differs")
        profile_files: list[list[dict[str, Any]]] = []
        for profile, entry in zip(profiles, entries):
            exact_object(entry, {"modelId", "repository", "revision", "files", "convertedWeights"}, f"{label} profile")
            require(
                (entry["modelId"], entry["repository"], entry["revision"])
                == (profile["modelId"], profile["repository"], profile["revision"]),
                f"{label} profile identity differs",
            )
            files = entry["files"]
            require(isinstance(files, list) and files, f"{label} asset inventory is empty")
            require([item.get("path") for item in files] == [item["path"] for item in profile["files"]], f"{label} asset order differs")
            for registered, item in zip(profile["files"], files):
                exact_object(item, {"path", "bytes", "sha256"}, f"{label} asset")
                require(
                    item["path"] == registered["path"]
                    and ".." not in PurePosixPath(item["path"]).parts,
                    f"{label} asset path differs",
                )
                require(
                    require_int(item["bytes"], f"{label} asset bytes", 1)
                    == require_int(registered["bytes"], f"registered {label} asset bytes", 1),
                    f"{label} registered asset byte count differs: {profile['modelId']}/{item['path']}",
                )
                require_digest(item["sha256"], f"{label} asset digest")
                registered_sha256 = registered.get("sha256")
                if registered_sha256 is not None:
                    require_digest(registered_sha256, f"registered {label} asset digest")
                    require(
                        item["sha256"] == registered_sha256,
                        f"{label} registered asset digest differs: {profile['modelId']}/{item['path']}",
                    )
            if expected_status == "RAW_ASSETS_VERIFIED" or profile["modelId"] != "opt-125m":
                require(entry["convertedWeights"] is None, f"{label} has an unexpected conversion")
            else:
                _validate_converted_weights(entry["convertedWeights"], f"{label} converted weights")
            profile_files.append(files)
        receipt_files[expected_status] = profile_files
    require(
        receipt_files["RAW_ASSETS_VERIFIED"] == receipt_files["ASSETS_VERIFIED"],
        "raw and verified asset file receipts differ",
    )
    exact_object(
        conversion,
        {"schemaVersion", "status", "profileId", "profilesSHA256", "convertedWeights"},
        "OPT conversion receipt",
    )
    opt = next(profile for profile in profiles if profile["modelId"] == "opt-125m")
    require(conversion["schemaVersion"] == "corelm-runpod-opt-conversion-v1", "OPT conversion schema differs")
    require(conversion["status"] == "OPT_CONVERSION_COMPLETE", "OPT conversion status differs")
    require(conversion["profileId"] == opt["profileId"], "OPT conversion profile differs")
    require(conversion["profilesSHA256"] == profiles_sha256, "OPT conversion profile digest differs")
    converted = _validate_converted_weights(conversion["convertedWeights"], "OPT converted weights")
    require(converted["conversion"] == opt["weightConversion"], "OPT conversion contract differs")
    raw_opt = next(entry for entry in raw_assets["profiles"] if entry["modelId"] == "opt-125m")
    source_asset = next(
        (item for item in raw_opt["files"] if item["path"] == converted["sourcePath"]),
        None,
    )
    require(source_asset is not None, "OPT conversion source asset is absent")
    require(
        converted["sourceSha256"] == source_asset["sha256"],
        "OPT conversion source digest differs from the raw asset receipt",
    )
    verified_opt = next(entry for entry in assets["profiles"] if entry["modelId"] == "opt-125m")
    require(verified_opt["convertedWeights"] == converted, "OPT conversion receipts differ")


def _validate_codec_source(
    codec_source: Any,
    source: dict[str, str],
    cuda_torch_lock: bytes,
) -> dict[str, Any]:
    value = exact_object(codec_source, {"commit", "tree", "files"}, "codec source receipt")
    require_digest(value["commit"], "codec source commit", HEX40)
    require_digest(value["tree"], "codec source tree", HEX40)
    require(
        value["commit"] == source["codecCommit"] == EXPECTED_CODEC_COMMIT
        and value["tree"] == source["codecTree"] == EXPECTED_CODEC_TREE,
        "codec source commit/tree differs from the registered same-Pod receipt",
    )
    files = exact_object(value["files"], set(EXPECTED_CODEC_FILES), "codec source file manifest")
    for relative, expected_sha256 in EXPECTED_CODEC_FILES.items():
        item = exact_object(files[relative], {"bytes", "sha256"}, f"codec source file {relative}")
        require_int(item["bytes"], f"codec source file {relative} bytes", 1)
        require_digest(item["sha256"], f"codec source file {relative} digest")
        require(item["sha256"] == expected_sha256, f"codec source file digest differs: {relative}")
    require(
        source["codecRequirementsSHA256"]
        == files["RealLLM/requirements.lock"]["sha256"],
        "codec requirements lock binding differs",
    )
    require(
        source["pipBootstrapLockSHA256"]
        == files[".github/locks/pip-bootstrap.txt"]["sha256"],
        "codec pip-bootstrap lock binding differs",
    )
    require(
        source["portableRuntimeLockSHA256"]
        == files[".github/locks/real-llm-linux-cpu-py312.txt"]["sha256"],
        "codec portable-runtime lock binding differs",
    )
    require(
        source["cudaTorchLockSHA256"] == sha256_bytes(cuda_torch_lock),
        "sweep CUDA runtime lock binding differs",
    )
    return value


def codec_configuration(profile: dict[str, Any]) -> dict[str, Any]:
    layers = int(profile["geometry"]["layers"])
    high = {0, min(layers - 1, layers // 3)}
    return {
        "backend": "voidtoken-v5",
        "bitsByLayer": [9 if index in high else 8 for index in range(layers)],
        "codeCompression": "zlib-9",
        "groupSize": 128,
        "scaleCompression": "zlib-9",
        "schedule": "normalized-layer-0-and-one-third-9bit-rest-8bit-v1",
        "signMode": "none",
        "transformBlockSize": 128,
    }


def _validate_codec_configuration(
    encoding: dict[str, Any],
    profile: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    configuration = codec_configuration(profile)
    require(encoding["configuration"] == configuration, f"{label} differs")
    require_digest(encoding["configurationSHA256"], f"{label} digest")
    require(
        encoding["configurationSHA256"]
        == sha256_bytes(canonical_json_bytes(configuration)),
        f"{label} digest differs",
    )
    return configuration


def _validate_cache_observation(
    observation: dict[str, Any],
    profile: dict[str, Any],
    label: str,
) -> None:
    geometry = profile["geometry"]
    expected_layer_suffix = (
        ".DynamicSlidingWindowLayer"
        if profile["modelId"] == "mistral-7b-v0.1"
        else ".DynamicLayer"
    )
    require(
        isinstance(observation["cacheClass"], str)
        and observation["cacheClass"].endswith(".DynamicCache"),
        f"{label} cache class differs",
    )
    require(
        isinstance(observation["layerClass"], str)
        and observation["layerClass"].endswith(expected_layer_suffix),
        f"{label} layer class differs",
    )
    expected = {
        "tensorLayout": "batch,kv_head,token,head_dimension",
        "batchSize": 1,
        "layers": int(geometry["layers"]),
        "kvHeads": int(geometry["kvHeads"]),
        "headDimension": int(geometry["headDimension"]),
        "dtype": "bfloat16",
        "targetContextTokens": int(profile["gpuAdmission"]["maxInputTokens"]),
        "prefillTokens": int(profile["maxPrefillTokens"]),
        "finalPromptTokens": 1,
        "continuationTokens": HORIZON,
        "effectiveCacheTokens": int(profile["maxPrefillTokens"]),
        "evictedTokens": 0,
    }
    for name, value in expected.items():
        require(observation[name] == value, f"{label} {name} differs")


def _validate_runtime(
    runtime: Any,
    profile: dict[str, Any],
    dense_bytes: int,
    source: dict[str, str],
    label: str,
) -> dict[str, Any]:
    value = exact_object(
        runtime,
        {
            "startedAt",
            "completedAt",
            "python",
            "torch",
            "cuda",
            "gpuName",
            "gpuDriverVersion",
            "gpuTotalBytes",
            "gpuFreeBytesBeforeCell",
            "memoryEstimateBytes",
            "peakAllocatedBytes",
            "peakReservedBytes",
            "peakRssBytes",
            "diskFreeBytesBeforeCell",
            "diskRequiredBytes",
            "modelRequirementsLockSHA256",
            "pipBootstrapLockSHA256",
            "portableRuntimeLockSHA256",
            "cudaRuntimeLockSHA256",
            "packages",
            "cgroupMemoryCurrentBytesAtCompletion",
            "cgroupMemoryPeakBytesAtCompletion",
            "cgroupMemoryLimitBytes",
            "dtype",
            "attentionImplementation",
            "deterministicAlgorithms",
        },
        label,
    )
    started = timestamp(value["startedAt"], f"{label} start")
    completed = timestamp(value["completedAt"], f"{label} completion")
    require(completed >= started, f"{label} completion precedes start")
    for name in ("python", "torch", "cuda", "gpuName"):
        require(isinstance(value[name], str) and value[name] and PRIVATE_VALUE.search(value[name]) is None, f"{label} {name} differs")
    require(value["gpuName"] == source["gpuName"], f"{label} GPU name differs")
    require(value["gpuDriverVersion"] == source["gpuDriverVersion"], f"{label} GPU driver differs")
    total = require_int(value["gpuTotalBytes"], f"{label} GPU total bytes", 1)
    free = require_int(value["gpuFreeBytesBeforeCell"], f"{label} free GPU bytes", 0)
    allocated = require_int(value["peakAllocatedBytes"], f"{label} peak allocated bytes", 0)
    reserved = require_int(value["peakReservedBytes"], f"{label} peak reserved bytes", 0)
    require(free <= total and allocated <= total and reserved <= total, f"{label} GPU accounting exceeds total")
    require_int(value["peakRssBytes"], f"{label} peak RSS", 1)
    disk_free = require_int(value["diskFreeBytesBeforeCell"], f"{label} free disk", 1)
    disk_required = require_int(value["diskRequiredBytes"], f"{label} required disk", 1)
    require(disk_free >= disk_required, f"{label} disk admission differs")
    for field, source_field in (
        ("modelRequirementsLockSHA256", "codecRequirementsSHA256"),
        ("pipBootstrapLockSHA256", "pipBootstrapLockSHA256"),
        ("portableRuntimeLockSHA256", "portableRuntimeLockSHA256"),
        ("cudaRuntimeLockSHA256", "cudaTorchLockSHA256"),
    ):
        require_digest(value[field], f"{label} {field}")
        require(value[field] == source[source_field], f"{label} {field} differs")
    require(
        value["packages"]
        == {
            "huggingface-hub": "1.25.1",
            "numpy": "2.5.1",
            "safetensors": "0.8.0",
            "tokenizers": "0.22.2",
            "torch": "2.13.0+cu130",
            "transformers": "5.14.1",
        },
        f"{label} package identity differs",
    )
    cgroup_current = require_int(value["cgroupMemoryCurrentBytesAtCompletion"], f"{label} cgroup current", 0)
    cgroup_peak = require_int(value["cgroupMemoryPeakBytesAtCompletion"], f"{label} cgroup peak", cgroup_current)
    cgroup_limit = value["cgroupMemoryLimitBytes"]
    require(cgroup_limit is None or (type(cgroup_limit) is int and cgroup_limit >= cgroup_peak), f"{label} cgroup limit differs")
    weight_bytes = sum(
        int(asset["bytes"])
        for asset in profile["files"]
        if asset["path"].endswith((".safetensors", ".bin"))
    )
    expected_estimate = weight_bytes + 6 * dense_bytes + 4 * 1024**3
    require(value["memoryEstimateBytes"] == expected_estimate, f"{label} memory estimate differs")
    cap = int(profile["gpuAdmission"]["maxGpuMemoryBytes"])
    require(expected_estimate <= int(total * 0.80) and expected_estimate <= int(free * 0.80) and expected_estimate <= cap, f"{label} memory estimate exceeds admission")
    require(allocated <= cap and reserved <= cap, f"{label} peak memory exceeds profile cap")
    require(value["dtype"] == "bfloat16" and value["attentionImplementation"] == "eager" and value["deterministicAlgorithms"] is True, f"{label} deterministic runtime differs")
    return value


def _validate_preflight_cell(
    cell: Any,
    profile: dict[str, Any],
    workload: dict[str, Any],
    trusted_workload: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    value = exact_object(
        cell,
        {
            "modelId",
            "workloadId",
            "category",
            "promptUTF8SHA256",
            "framedUTF8Bytes",
            "availableTokens",
            "selectedTokens",
            "prefillTokens",
            "tokenIdsU32LESHA256",
            "sourceFiles",
        },
        label,
    )
    require(
        (value["modelId"], value["workloadId"])
        == (profile["modelId"], workload["workloadId"]),
        f"{label} identity differs",
    )
    require(
        value["category"] == workload["contentClass"] == trusted_workload["category"],
        f"{label} category differs",
    )
    require_digest(value["promptUTF8SHA256"], f"{label} prompt digest")
    require_int(value["framedUTF8Bytes"], f"{label} framed bytes", 1)
    prefill = int(profile["maxPrefillTokens"])
    selected = require_int(value["selectedTokens"], f"{label} selected tokens", 1)
    available = require_int(value["availableTokens"], f"{label} available tokens", selected)
    require(value["prefillTokens"] == prefill, f"{label} prefill differs")
    require(selected == prefill + 1 and available >= selected, f"{label} token selection differs")
    require_digest(value["tokenIdsU32LESHA256"], f"{label} token digest")
    inventory = value["sourceFiles"]
    registered_paths = workload["paths"]
    require(isinstance(inventory, list) and len(inventory) == len(registered_paths), f"{label} source inventory count differs")
    require([entry.get("path") for entry in inventory] == registered_paths, f"{label} source paths differ")
    tracked_bytes = 0
    for position, entry in enumerate(inventory):
        exact_object(
            entry,
            {"path", "gitMode", "gitBlobSHA1", "bytes", "sha256"},
            f"{label} source file {position}",
        )
        require(entry["gitMode"] in {"100644", "100755"}, f"{label} source mode differs")
        require_digest(entry["gitBlobSHA1"], f"{label} source Git blob", HEX40)
        tracked_bytes += require_int(entry["bytes"], f"{label} source bytes", 1)
        require_digest(entry["sha256"], f"{label} source digest")
    require(tracked_bytes >= int(workload["minimumTrackedUtf8Bytes"]), f"{label} tracked source bytes are below the registered floor")
    require(
        value["promptUTF8SHA256"] == trusted_workload["promptUTF8SHA256"]
        and value["framedUTF8Bytes"] == trusted_workload["framedUTF8Bytes"]
        and inventory == trusted_workload["sourceFiles"],
        f"{label} locally reconstructed workload binding differs",
    )
    return value


def _validate_archive_evidence(
    export: FrozenExport,
    repository: Path,
) -> tuple[
    dict[str, Any],
    dict[str, str],
    list[dict[str, Any]],
    dict[str, Any],
    list[dict[str, Any]],
]:
    profiles_doc, workloads_doc, local_documents = load_repository_inputs(repository)
    profiles = profiles_doc.get("profiles")
    workloads = workloads_doc.get("workloads")
    require(isinstance(profiles, list) and len(profiles) == 7, "profile registry differs")
    require(isinstance(workloads, list) and len(workloads) == 4, "workload registry differs")
    model_order = [entry.get("modelId") for entry in profiles]
    workload_order = [entry.get("workloadId") for entry in workloads]
    require(model_order == list(MODEL_REPLAYS), "model order differs")
    expected_pairs = [(model, workload) for model in model_order for workload in workload_order]
    profile_map = {entry["modelId"]: entry for entry in profiles}
    workload_map = {entry["workloadId"]: entry for entry in workloads}

    for relative in (
        "assets-download.json",
        "opt-conversion.json",
        "assets-verify.json",
        "preflight.json",
        "structural-verification.json",
    ):
        _verify_sidecar(export, relative)
    raw_assets = _json_document(export, "assets-download.json")
    assets = _json_document(export, "assets-verify.json")
    conversion = _json_document(export, "opt-conversion.json")
    _validate_asset_receipts(raw_assets, assets, conversion, profiles, sha256_bytes(local_documents["profiles.json"]))

    preflight = _json_document(export, "preflight.json")
    preflight_digest = _verify_sidecar(export, "preflight.json")
    exact_object(
        preflight,
        {
            "schemaVersion",
            "status",
            "countsTowardScientificVerdict",
            "source",
            "codecSource",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
            "modelOrder",
            "workloadOrder",
            "horizon",
            "cells",
        },
        "preflight",
    )
    require(preflight["schemaVersion"] == "corelm-runpod-adapter-preflight-v1", "preflight schema differs")
    require(preflight["status"] == "TOKENIZER_ONLY_NO_MODEL_INFERENCE", "preflight status differs")
    require(preflight["countsTowardScientificVerdict"] is False, "preflight makes a scientific claim")
    require(preflight["modelOrder"] == model_order and preflight["workloadOrder"] == workload_order, "preflight order differs")
    require(preflight["horizon"] == HORIZON, "preflight horizon differs")
    require(isinstance(preflight["cells"], list) and len(preflight["cells"]) == 28, "preflight cell count differs")

    run = _json_document(export, "run/run.json")
    run_digest = _verify_sidecar(export, "run/run.json")
    exact_object(
        run,
        {
            "schemaVersion",
            "runId",
            "status",
            "classification",
            "countsTowardScientificVerdict",
            "source",
            "preflightSHA256",
            "assetReceiptSHA256",
            "profilesSHA256",
            "workloadsSHA256",
            "protocolSHA256",
            "expectedCells",
            "completeCells",
            "cells",
        },
        "run manifest",
    )
    require(run["schemaVersion"] == "corelm-runpod-adapter-run-v1", "run schema differs")
    uuid.UUID(run["runId"])
    require(run["status"] == "COMPLETE" and run["expectedCells"] == run["completeCells"] == 28, "run is not a complete 28-cell matrix")
    require(run["classification"] == CLASSIFICATION and run["countsTowardScientificVerdict"] is False, "run claim boundary differs")
    require(run["preflightSHA256"] == preflight_digest, "run preflight digest differs")
    require(run["assetReceiptSHA256"] == _verify_sidecar(export, "assets-verify.json"), "run asset digest differs")
    require(
        preflight["assetReceiptSHA256"] == run["assetReceiptSHA256"],
        "preflight asset receipt digest differs",
    )
    for field, filename in (("profilesSHA256", "profiles.json"), ("workloadsSHA256", "workloads.json"), ("protocolSHA256", "PROTOCOL.md")):
        require(run[field] == sha256_bytes(local_documents[filename]), f"run {field} differs from the local registered bytes")
    require(preflight["profilesSHA256"] == run["profilesSHA256"] and preflight["workloadsSHA256"] == run["workloadsSHA256"] and preflight["protocolSHA256"] == run["protocolSHA256"], "preflight input digests differ")
    require(preflight["source"] == run["source"] and preflight["codecSource"] is not None, "preflight source binding differs")

    source = parse_source_identity(_document(export, "source-identity.txt"))
    require(source["sweepCommit"] == run["source"]["commit"] and source["sweepTree"] == run["source"]["tree"], "source receipt and run differ")
    verify_git_source(repository, source, run, local_documents)
    codec_source = _validate_codec_source(
        preflight["codecSource"],
        source,
        local_documents["torch-linux-cu130-py312.txt"],
    )
    require(preflight["codecSource"] == codec_source, "preflight codec source receipt differs")
    workload_bindings = {
        workload["workloadId"]: _reconstruct_workload_binding(
            repository,
            source["sweepCommit"],
            workloads_doc,
            workload,
        )
        for workload in workloads
    }

    preflight_map: dict[tuple[str, str], dict[str, Any]] = {}
    for position, (entry, pair) in enumerate(zip(preflight["cells"], expected_pairs)):
        validated = _validate_preflight_cell(
            entry,
            profile_map[pair[0]],
            workload_map[pair[1]],
            workload_bindings[pair[1]],
            f"preflight cell {position}",
        )
        preflight_map[pair] = validated

    records = run["cells"]
    require(isinstance(records, list) and len(records) == 28, "run rows differ")
    inventory = _inventory_map(export)
    public_rows: list[dict[str, Any]] = []
    expected_files = {
        "evidence/source-identity.txt",
        *{
            f"evidence/{relative}{suffix}"
            for relative in (
                "assets-download.json",
                "opt-conversion.json",
                "assets-verify.json",
                "preflight.json",
                "structural-verification.json",
            )
            for suffix in ("", ".sha256")
        },
        "evidence/run/run.json",
        "evidence/run/run.json.sha256",
    }
    expected_directories = {"evidence", "evidence/replays", "evidence/run", "evidence/run/cells", "evidence/run/logs"}
    result_digests: dict[tuple[str, str], str] = {}
    result_documents: dict[tuple[str, str], dict[str, Any]] = {}
    total_container_bytes = 0
    total_containers = 0
    for index, (record, pair) in enumerate(zip(records, expected_pairs)):
        model_id, workload_id = pair
        exact_object(
            record,
            {
                "modelId",
                "workloadId",
                "startedAt",
                "completedAt",
                "returnCode",
                "exitSignal",
                "timedOut",
                "timeoutLimitSeconds",
                "terminationReason",
                "status",
                "resultPath",
                "resultSHA256",
                "stdoutSHA256",
                "stderrSHA256",
            },
            f"run row {index}",
        )
        require((record["modelId"], record["workloadId"]) == pair, f"run row {index} order differs")
        require(record["status"] == "COMPLETE" and record["returnCode"] == 0 and record["timedOut"] is False and record["exitSignal"] is None and record["terminationReason"] == "completed", f"run row {index} is not complete")
        require(record["timeoutLimitSeconds"] == int(profile_map[model_id]["gpuAdmission"]["executionTimeoutSeconds"]), f"run row {index} timeout differs")
        process_started = timestamp(record["startedAt"], f"run row {index} start")
        process_completed = timestamp(record["completedAt"], f"run row {index} completion")
        require(process_completed >= process_started, f"run row {index} timestamps differ")
        require_digest(record["resultSHA256"], f"run row {index} result digest")
        require_digest(record["stdoutSHA256"], f"run row {index} stdout digest")
        require_digest(record["stderrSHA256"], f"run row {index} stderr digest")
        result_relative = f"run/cells/{model_id}/{workload_id}/result.json"
        require(record.get("resultPath") == f"cells/{model_id}/{workload_id}/result.json", f"run row {index} result path differs")
        result_digest = _verify_sidecar(export, result_relative)
        require(record.get("resultSHA256") == result_digest, f"run row {index} result digest differs")
        result_digests[pair] = result_digest
        result = _json_document(export, result_relative)
        result_documents[pair] = result
        attempt_relative = f"run/cells/{model_id}/{workload_id}/attempt.json"
        attempt = _json_document(export, attempt_relative)
        _verify_sidecar(export, attempt_relative)
        exact_object(
            attempt,
            {
                "schemaVersion",
                "status",
                "classification",
                "countsTowardScientificVerdict",
                "attemptId",
                "runId",
                "startedAt",
                "modelId",
                "adapterId",
                "workloadId",
                "timeoutLimitSeconds",
                "source",
                "codecSource",
                "preflightSHA256",
                "assetReceiptSHA256",
                "profilesSHA256",
                "workloadsSHA256",
                "protocolSHA256",
            },
            f"attempt {index}",
        )
        try:
            attempt_id = str(uuid.UUID(attempt["attemptId"]))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f"attempt {index} ID is invalid") from error
        attempt_started = timestamp(attempt["startedAt"], f"attempt {index} start")
        require(process_started <= attempt_started <= process_completed, f"attempt {index} time differs")
        require(
            attempt
            == {
                **attempt,
                "schemaVersion": "corelm-runpod-adapter-cell-attempt-v1",
                "status": "STARTED",
                "classification": CLASSIFICATION,
                "countsTowardScientificVerdict": False,
                "attemptId": attempt_id,
                "runId": run["runId"],
                "modelId": model_id,
                "adapterId": profile_map[model_id]["adapterId"],
                "workloadId": workload_id,
                "timeoutLimitSeconds": record["timeoutLimitSeconds"],
                "source": run["source"],
                "codecSource": preflight["codecSource"],
                "preflightSHA256": preflight_digest,
                "assetReceiptSHA256": run["assetReceiptSHA256"],
                "profilesSHA256": run["profilesSHA256"],
                "workloadsSHA256": run["workloadsSHA256"],
                "protocolSHA256": run["protocolSHA256"],
            },
            f"attempt {index} binding differs",
        )
        exact_object(result, {"schemaVersion", "status", "classification", "countsTowardScientificVerdict", "model", "workload", "codecSource", "assetReceiptSHA256", "canonicalCacheBF16SHA256", "cacheObservation", "structuralReplay", "encoding", "behavior", "runtime"}, f"result {model_id}/{workload_id}")
        require(result["schemaVersion"] == "corelm-runpod-adapter-cell-v1" and result["status"] == "COMPLETE", f"result {index} schema/status differs")
        require(result["classification"] == CLASSIFICATION and result["countsTowardScientificVerdict"] is False, f"result {index} claim boundary differs")
        profile = profile_map[model_id]
        model = exact_object(result["model"], {"modelId", "adapterId", "repository", "revision", "geometry", "assetRootName"}, f"result {index} model")
        require(
            model
            == {
                "modelId": model_id,
                "adapterId": profile["adapterId"],
                "repository": profile["repository"],
                "revision": profile["revision"],
                "geometry": profile["geometry"],
                "assetRootName": model_id,
            },
            f"result {index} model binding differs",
        )
        require(result["codecSource"] == preflight["codecSource"], f"result {index} codec source differs")
        require(result["assetReceiptSHA256"] == run["assetReceiptSHA256"], f"result {index} asset receipt differs")
        require_digest(result["canonicalCacheBF16SHA256"], f"result {index} canonical cache digest")
        workload = result["workload"]
        require(workload == {key: value for key, value in preflight_map[pair].items() if key != "modelId"}, f"result {index} workload binding differs")
        observation = result["cacheObservation"]
        exact_object(observation, {"cacheClass", "layerClass", "tensorLayout", "batchSize", "layers", "kvHeads", "headDimension", "dtype", "targetContextTokens", "prefillTokens", "finalPromptTokens", "continuationTokens", "effectiveCacheTokens", "evictedTokens"}, f"cache observation {index}")
        _validate_cache_observation(observation, profile, f"result {index} cache observation")
        structural_replay = exact_object(result["structuralReplay"], {"maxAbsLogitDifference", "top1Identical"}, f"structural replay {index}")
        structural_difference = require_number(
            structural_replay["maxAbsLogitDifference"],
            f"result {index} native structural logit difference",
            0,
        )
        require(structural_difference == 0.0 and structural_replay["top1Identical"] is True, f"result {index} native structural replay differs")
        encoding = exact_object(result["encoding"], {"configuration", "configurationSHA256", "denseBF16Bytes", "containerBytes", "payloadBytes", "compressionRatio", "encodingNanoseconds", "containers"}, f"encoding {index}")
        configuration = _validate_codec_configuration(
            encoding,
            profile,
            f"result {index} codec configuration",
        )
        require_int(encoding["encodingNanoseconds"], f"result {index} encoding nanoseconds", 0)
        dense = require_int(encoding["denseBF16Bytes"], "dense bytes", 1)
        container_bytes = require_int(encoding["containerBytes"], "container bytes", 1)
        payload_bytes = require_int(encoding["payloadBytes"], "payload bytes", 1)
        expected_dense = observation["prefillTokens"] * 2 * observation["kvHeads"] * observation["headDimension"] * observation["layers"] * 2
        require(dense == expected_dense, f"result {index} dense byte accounting differs")
        compression_ratio = require_number(
            encoding["compressionRatio"],
            f"result {index} compression ratio",
            0,
        )
        require(math.isclose(compression_ratio, dense / container_bytes, rel_tol=0, abs_tol=1e-15), f"result {index} compression ratio differs")
        containers = encoding["containers"]
        require(isinstance(containers, list) and len(containers) == observation["layers"], f"result {index} container count differs")
        observed_container_total = 0
        observed_payload_total = 0
        for layer, container in enumerate(containers):
            exact_object(
                container,
                {
                    "layerIndex",
                    "bits",
                    "rows",
                    "columns",
                    "denseBF16Bytes",
                    "containerBytes",
                    "payloadBytes",
                    "containerSHA256",
                    "payloadSHA256",
                    "path",
                },
                f"result {index} container {layer}",
            )
            expected_columns = 2 * int(profile["geometry"]["kvHeads"]) * int(profile["geometry"]["headDimension"])
            expected_path = f"containers/layer-{layer:03d}.vtl5"
            require(
                container["layerIndex"] == layer
                and container["bits"] == configuration["bitsByLayer"][layer]
                and container["rows"] == int(profile["maxPrefillTokens"])
                and container["columns"] == expected_columns
                and container["denseBF16Bytes"] == int(profile["maxPrefillTokens"]) * expected_columns * 2
                and container["path"] == expected_path,
                f"result {index} container {layer} geometry/configuration differs",
            )
            require_int(container["containerBytes"], f"result {index} container {layer} bytes", 1)
            require_int(container["payloadBytes"], f"result {index} container {layer} payload bytes", 1)
            require(container["payloadBytes"] < container["containerBytes"], f"result {index} container {layer} payload is not strictly inside the container")
            require_digest(container["containerSHA256"], f"result {index} container {layer} digest")
            require_digest(container["payloadSHA256"], f"result {index} container {layer} payload digest")
            relative = f"evidence/run/cells/{model_id}/{workload_id}/{container.get('path')}"
            require(relative in inventory, f"result {index} container is absent")
            item = inventory[relative]
            require(item["bytes"] == container.get("containerBytes") and item["sha256"] == container.get("containerSHA256"), f"result {index} container binding differs")
            observed_container_total += item["bytes"]
            observed_payload_total += require_int(container.get("payloadBytes"), "payload bytes", 1)
            expected_files.add(relative)
        require(observed_container_total == container_bytes and observed_payload_total == payload_bytes, f"result {index} encoding totals differ")
        total_container_bytes += container_bytes
        total_containers += len(containers)
        behavior = _validate_behavior(
            result["behavior"],
            f"behavior {index}",
            vocabulary_size=int(profile["geometry"]["vocabularySize"]),
        )
        runtime = _validate_runtime(
            result["runtime"],
            profile,
            dense,
            source,
            f"result {index} runtime",
        )
        runtime_started = timestamp(runtime["startedAt"], f"result {index} runtime start")
        runtime_completed = timestamp(runtime["completedAt"], f"result {index} runtime completion")
        require(
            attempt_started <= runtime_started <= runtime_completed <= process_completed,
            f"result {index} runtime interval is outside its attempt/process interval",
        )
        for log_kind, digest_field in (("stdout", "stdoutSHA256"), ("stderr", "stderrSHA256")):
            log_path = f"evidence/run/logs/{model_id}--{workload_id}.{log_kind}.log"
            require(log_path in inventory and inventory[log_path]["sha256"] == record[digest_field], f"run row {index} {log_kind} digest differs")
            expected_files.add(log_path)
        for base in ("attempt.json", "result.json"):
            path = f"evidence/run/cells/{model_id}/{workload_id}/{base}"
            expected_files.update({path, path + ".sha256"})
            _verify_sidecar(export, path.removeprefix("evidence/"))
        expected_directories.update(
            {
                f"evidence/run/cells/{model_id}",
                f"evidence/run/cells/{model_id}/{workload_id}",
                f"evidence/run/cells/{model_id}/{workload_id}/containers",
            }
        )
        public_rows.append(
            {
                "row": index + 1,
                "modelId": model_id,
                "adapterId": profile["adapterId"],
                "workloadId": workload_id,
                "category": workload["category"],
                "promptUTF8SHA256": workload["promptUTF8SHA256"],
                "framedUTF8Bytes": workload["framedUTF8Bytes"],
                "sourceFilesSHA256": sha256_bytes(
                    canonical_json_bytes(workload["sourceFiles"])
                ),
                "workloadSourceVerificationScope": WORKLOAD_SOURCE_SCOPE,
                "availableTokens": workload["availableTokens"],
                "selectedTokens": workload["selectedTokens"],
                "tokenIdsU32LESHA256": workload["tokenIdsU32LESHA256"],
                "tokenizationAssertionScope": TOKENIZATION_ASSERTION_SCOPE,
                "prefillTokens": observation["prefillTokens"],
                "targetContextTokens": observation["targetContextTokens"],
                "finalPromptTokens": observation["finalPromptTokens"],
                "continuationTokens": observation["continuationTokens"],
                "effectiveCacheTokens": observation["effectiveCacheTokens"],
                "evictedTokens": observation["evictedTokens"],
                "layers": observation["layers"],
                "kvHeads": observation["kvHeads"],
                "headDimension": observation["headDimension"],
                "denseBF16Bytes": dense,
                "containerBytes": container_bytes,
                "payloadBytes": payload_bytes,
                "compressionRatio": compression_ratio,
                "spaceSavingFraction": 1.0 - container_bytes / dense,
                "containerBytesPerEffectiveCacheToken": container_bytes / observation["effectiveCacheTokens"],
                "encodingNanoseconds": encoding["encodingNanoseconds"],
                "structuralMaxAbsLogitDifference": structural_difference,
                "structuralTop1Identical": structural_replay["top1Identical"],
                "controlledTop1AgreementCount": behavior["controlledTop1AgreementCount"],
                "controlledTop1Agreement": behavior["controlledTop1Agreement"],
                "meanKLDivergenceNat": behavior["meanKLDivergenceNat"],
                "meanBaselineSelectedTokenSurprisalDeltaNat": behavior["meanBaselineSelectedTokenSurprisalDeltaNat"],
                "maxAbsLogitDifference": behavior["maxAbsLogitDifference"],
                "perTokenKLDivergenceNat": behavior["perTokenKLDivergenceNat"],
                "perTokenBaselineSelectedTokenSurprisalDeltaNat": behavior["perTokenBaselineSelectedTokenSurprisalDeltaNat"],
                "perTokenMaxAbsLogitDifference": behavior["perTokenMaxAbsLogitDifference"],
                "freeRunExact": behavior["freeRunExact"],
                "freeRunSamePositionCount": behavior["freeRunSamePositionCount"],
                "freeRunLongestCommonPrefixTokens": behavior["freeRunLongestCommonPrefixTokens"],
                "baselineTokenIds": behavior["baselineTokenIds"],
                "controlledCandidateTop1TokenIds": behavior["controlledCandidateTop1TokenIds"],
                "candidateFreeRunTokenIds": behavior["candidateFreeRunTokenIds"],
                "baselineContinuationSHA256": sha256_bytes(behavior["baselineContinuation"].encode("utf-8")),
                "candidateFreeRunContinuationSHA256": sha256_bytes(behavior["candidateFreeRunContinuation"].encode("utf-8")),
                "canonicalCacheBF16SHA256": result["canonicalCacheBF16SHA256"],
                "resultSHA256": result_digest,
                "peakAllocatedBytes": runtime["peakAllocatedBytes"],
                "peakReservedBytes": runtime["peakReservedBytes"],
                "peakRssBytes": runtime["peakRssBytes"],
            }
        )

    structural = _json_document(export, "structural-verification.json")
    structural_digest = _verify_sidecar(export, "structural-verification.json")
    exact_object(structural, {"schemaVersion", "status", "classification", "countsTowardScientificVerdict", "modelReplayPerformed", "runId", "runSHA256", "preflightSHA256", "assetReceiptSHA256", "cells", "containers", "containerBytes"}, "structural receipt")
    require(structural == {**structural, "schemaVersion": "corelm-runpod-adapter-structural-verification-v1", "status": "STRUCTURALLY_VERIFIED", "classification": CLASSIFICATION, "countsTowardScientificVerdict": False, "modelReplayPerformed": False, "runId": run["runId"], "runSHA256": run_digest, "preflightSHA256": preflight_digest, "assetReceiptSHA256": run["assetReceiptSHA256"], "cells": 28, "containers": total_containers, "containerBytes": total_container_bytes}, "structural receipt binding differs")

    replay_receipts: list[dict[str, Any]] = []
    for model_id, workload_id in MODEL_REPLAYS.items():
        relative = f"replays/{model_id}--{workload_id}.json"
        replay = _json_document(export, relative)
        replay_digest = _verify_sidecar(export, relative)
        exact_object(
            replay,
            {
                "schemaVersion",
                "status",
                "classification",
                "countsTowardScientificVerdict",
                "modelId",
                "workloadId",
                "resultSHA256",
                "preflightSHA256",
                "assetReceiptSHA256",
                "runSHA256",
                "structuralVerificationSHA256",
                "predictionTokens",
                "canonicalCacheBF16SHA256",
                "structuralReplayExact",
                "controlledTop1Agreement",
                "meanKLDivergenceNat",
                "meanBaselineSelectedTokenSurprisalDeltaNat",
                "baselineContinuationSHA256",
                "candidateContinuationSHA256",
                "device",
                "gpuName",
                "gpuDriverVersion",
                "peakAllocatedBytes",
            },
            f"replay receipt {model_id}",
        )
        require(replay["schemaVersion"] == "corelm-runpod-adapter-cell-replay-v1" and replay["status"] == "MODEL_REPLAY_VERIFIED", f"replay schema/status differs: {model_id}")
        require(replay["classification"] == CLASSIFICATION and replay["countsTowardScientificVerdict"] is False, f"replay claim boundary differs: {model_id}")
        require(replay["modelId"] == model_id and replay["workloadId"] == workload_id, f"replay identity differs: {model_id}")
        require(replay["resultSHA256"] == result_digests[(model_id, workload_id)], f"replay result digest differs: {model_id}")
        require(
            replay["runSHA256"] == run_digest
            and replay["preflightSHA256"] == preflight_digest
            and replay["assetReceiptSHA256"] == run["assetReceiptSHA256"]
            and replay["structuralVerificationSHA256"] == structural_digest,
            f"replay evidence binding differs: {model_id}",
        )
        result = result_documents[(model_id, workload_id)]
        behavior = result["behavior"]
        require(replay["predictionTokens"] == HORIZON and replay["structuralReplayExact"] is True, f"replay outcome differs: {model_id}")
        require_digest(replay["canonicalCacheBF16SHA256"], f"replay cache digest: {model_id}")
        require(replay["canonicalCacheBF16SHA256"] == result["canonicalCacheBF16SHA256"], f"replay cache binding differs: {model_id}")
        for replay_name, result_name in (
            ("controlledTop1Agreement", "controlledTop1Agreement"),
            ("meanKLDivergenceNat", "meanKLDivergenceNat"),
            (
                "meanBaselineSelectedTokenSurprisalDeltaNat",
                "meanBaselineSelectedTokenSurprisalDeltaNat",
            ),
        ):
            observed = require_number(replay[replay_name], f"replay {replay_name}: {model_id}")
            expected = require_number(behavior[result_name], f"result {result_name}: {model_id}")
            require(
                math.isclose(observed, expected, rel_tol=2e-6, abs_tol=2e-5),
                f"replay behavior binding differs: {model_id}/{replay_name}",
            )
        require_digest(replay["baselineContinuationSHA256"], f"replay baseline continuation: {model_id}")
        require_digest(replay["candidateContinuationSHA256"], f"replay candidate continuation: {model_id}")
        require(
            replay["baselineContinuationSHA256"]
            == sha256_bytes(behavior["baselineContinuation"].encode("utf-8")),
            f"replay baseline continuation binding differs: {model_id}",
        )
        require(
            replay["candidateContinuationSHA256"]
            == sha256_bytes(behavior["candidateFreeRunContinuation"].encode("utf-8")),
            f"replay candidate continuation binding differs: {model_id}",
        )
        runtime = result["runtime"]
        require(replay["device"] == "cuda:0", f"replay device differs: {model_id}")
        require(
            replay["gpuName"] == runtime["gpuName"] == source["gpuName"],
            f"replay GPU differs: {model_id}",
        )
        require(
            replay["gpuDriverVersion"]
            == runtime["gpuDriverVersion"]
            == source["gpuDriverVersion"],
            f"replay GPU driver differs: {model_id}",
        )
        replay_peak = require_int(replay["peakAllocatedBytes"], f"replay peak allocation: {model_id}", 0)
        gpu_total = require_int(runtime["gpuTotalBytes"], f"result GPU total: {model_id}", 1)
        require(
            replay_peak <= gpu_total
            and replay_peak <= int(profile_map[model_id]["gpuAdmission"]["maxGpuMemoryBytes"]),
            f"replay peak allocation exceeds its GPU/profile bound: {model_id}",
        )
        expected_files.update({f"evidence/{relative}", f"evidence/{relative}.sha256"})
        require_digest(replay_digest, "replay receipt digest")
        replay_receipts.append({**replay, "receiptSHA256": replay_digest})

    observed_files = set(inventory)
    require(observed_files == expected_files, f"archive evidence files differ: missing={sorted(expected_files-observed_files)}, extra={sorted(observed_files-expected_files)}")
    observed_directories = set(export.directory_inventory)
    require(observed_directories == expected_directories, f"archive evidence directories differ: missing={sorted(expected_directories-observed_directories)}, extra={sorted(observed_directories-expected_directories)}")
    return run, source, public_rows, structural, replay_receipts


def archive_receipt(export: FrozenExport) -> dict[str, Any]:
    inventory_bytes = canonical_json_bytes(export.file_inventory) + b"\n"
    return {
        "schemaVersion": ARCHIVE_RECEIPT_SCHEMA,
        "status": "LOCAL_TRANSFER_AND_INVENTORY_VERIFIED",
        "classification": CLASSIFICATION,
        "scientificEvidence": False,
        "countsTowardScientificVerdict": False,
        "archiveFilename": ARCHIVE_NAME,
        "archiveBytes": export.archive_bytes,
        "archiveSHA256": export.archive_sha256,
        "checksumFilename": CHECKSUM_NAME,
        "checksumFileSHA256": export.checksum_sha256,
        "archiveMemberCount": export.member_count,
        "directoryCount": len(export.directory_inventory),
        "regularFileCount": len(export.file_inventory),
        "totalRegularFileBytes": export.total_regular_bytes,
        "evidenceInventorySHA256": sha256_bytes(inventory_bytes),
        "verificationScope": "TRANSFER_CHECKSUM_SINGLE_GZIP_MEMBER_TAR_SAFETY_AND_RETAINED_EVIDENCE_BINDINGS_ONLY",
        "independentSemanticVerification": False,
        "independentModelReplay": False,
    }


def recorded_run(
    *,
    run: dict[str, Any],
    source: dict[str, str],
    rows: list[dict[str, Any]],
    structural: dict[str, Any],
    replay_receipts: list[dict[str, Any]],
    metadata: dict[str, Any],
    metadata_sha256: str,
    receipt: dict[str, Any],
    receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": RECORDED_RUN_SCHEMA,
        "status": "COMPLETE_RECORDED_EXPLORATORY_PUBLIC_REGRESSION",
        "classification": CLASSIFICATION,
        "scientificEvidence": False,
        "countsTowardScientificVerdict": False,
        "independentHumanReview": False,
        "independentReplication": False,
        "recordedAt": metadata["recordedAt"],
        "successfulAttemptNumber": metadata["successfulAttemptNumber"],
        "attempts": metadata["attempts"],
        "lifecycle": metadata["lifecycle"],
        "lifecycleClaimBoundary": {
            "attestationBasis": LIFECYCLE_ATTESTATION_BASIS,
            "builderValidationScope": LIFECYCLE_VALIDATION_SCOPE,
            "providerVerified": False,
        },
        "operatorVerification": metadata["operatorVerification"],
        "operatorMetadataSHA256": metadata_sha256,
        "archiveReceiptSHA256": receipt_sha256,
        "archive": receipt,
        "source": {
            "sweepCommit": source["sweepCommit"],
            "sweepTree": source["sweepTree"],
            "codecCommit": source["codecCommit"],
            "codecTree": source["codecTree"],
            "containerImageDigest": source["containerImageDigest"],
            "gpuName": source["gpuName"],
            "gpuMemoryMiB": int(source["gpuMemoryMiB"]),
            "gpuDriverVersion": source["gpuDriverVersion"],
            "cgroupVersion": source["cgroupVersion"],
            "runtimeLocks": {
                "codecRequirementsSHA256": source["codecRequirementsSHA256"],
                "pipBootstrapLockSHA256": source["pipBootstrapLockSHA256"],
                "portableRuntimeLockSHA256": source["portableRuntimeLockSHA256"],
                "cudaTorchLockSHA256": source["cudaTorchLockSHA256"],
            },
            "signatureVerificationScope": {
                "sweepCommit": "LOCALLY_REVERIFIED_WITH_COMMITTED_TRUST_ROOT",
                "codecCommit": "SAME_POD_RECEIPT_NOT_LOCALLY_REVERIFIED",
            },
        },
        "verification": {
            "runId": run["runId"],
            "runSHA256": structural["runSHA256"],
            "preflightSHA256": structural["preflightSHA256"],
            "assetReceiptSHA256": structural["assetReceiptSHA256"],
            "structuralStatus": structural["status"],
            "structurallyVerifiedCells": structural["cells"],
            "verifiedContainers": structural["containers"],
            "verifiedContainerBytes": structural["containerBytes"],
            "representativeModelReplayReceipts": 7,
            "modelReplayScope": "ONE_REGISTERED_CELL_PER_PROFILE_ON_THE_SAME_POD",
            "representativeModelReplays": replay_receipts,
            "workloadSourceVerificationScope": WORKLOAD_SOURCE_SCOPE,
            "tokenizationVerificationScope": TOKENIZATION_ASSERTION_SCOPE,
            "assetReceiptValidationScope": "SIGNED_PROFILE_PATH_BYTES_AND_AVAILABLE_SHA256_PLUS_RAW_VERIFIED_RECEIPT_EQUALITY",
            "assetContentVerificationScope": ASSET_CONTENT_SCOPE,
            "codecSourceValidationScope": "SAME_POD_RECEIPT_EXACT_REGISTERED_COMMIT_TREE_FILES_AND_LOCK_HASHES_CODEC_BYTES_NOT_RETRIEVED",
        },
        "matrix": {
            "plannedCells": 28,
            "completeCells": 28,
            "incompleteCells": 0,
            "rows": rows,
            "aggregationPolicy": "NO_CROSS_CELL_OR_CROSS_MODEL_AVERAGES",
        },
        "causalLimitations": {
            "determinismRole": "REPRODUCIBILITY_CONTROL_NOT_COMPRESSION_FACTOR",
            "lengthEffectEstablished": False,
            "reason": "Each model uses one fixed registered maximum prefill; cross-model lengths are confounded by model geometry, tokenizer, cache policy, and codec configuration.",
            "requiredFollowUp": "Within each unchanged model and workload, run a preregistered prefill-length ladder with all other inputs fixed and evaluate R(P)=denseBF16Bytes/containerBytes.",
        },
    }


def _format_number(value: Any) -> str:
    if type(value) is int:
        return str(value)
    return format(float(value), ".9g")


def render_results(record: dict[str, Any]) -> bytes:
    rows = record["matrix"]["rows"]
    lines = [
        "# Recorded RunPod adapter sweep",
        "",
        f"Status: `{record['status']}`. All 28 registered cells completed, the Pod structural verifier accepted all retained containers, and seven representative same-Pod model replay receipts were retained.",
        "",
        "This is an exploratory public regression, not scientific evidence or an independent replication. The producer, structural verifier, and replay verifier shared the same Pod, source, runtime, model cache, and operator-controlled attempt.",
        "",
        "Lifecycle timestamps, cost, termination, volume deletion, and credential-cleanup fields are `OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED`. The builder validates only their schema, grammar, and internal consistency; it does not contact RunPod or claim a provider attestation.",
        "",
        "The builder locally reconstructed every workload prompt from the exact signed-commit Git blobs and registered frames. Token IDs and available/selected token counts remain `SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED`, because this model-free builder does not retrieve tokenizer assets or rerun tokenization.",
        "",
        "## Attempt audit",
        "",
        "| Attempt | Status | Source commit | Failure code | Run-root disposition |",
        "|---:|---|---|---|---|",
    ]
    for attempt in record["attempts"]:
        lines.append(
            f"| {attempt['attemptNumber']} | {attempt['status']} | `{attempt['sourceCommit']}` | "
            f"{attempt['failureCode'] or '—'} | {attempt['generatedRunRootDisposition']} |"
        )
    lines.extend(
        [
            "",
            "The closed failure stage/code and forensic-manifest hashes are in `record.json`; free-text attempt summaries are forbidden. Incomplete attempts are preserved as negative operational history and are not counted as successful cells.",
            "",
            "## Exact 28-cell matrix",
            "",
            "There are no cross-cell, per-model, or global averages below. `mean KL` and `mean Δsurprisal` are protocol-defined summaries within one exact 32-token cell. The authoritative per-token arrays and token IDs are retained in `record.json`.",
            "",
            "| # | Model | Workload | Prefill | Dense bytes | Container bytes | R | Saving | Bytes/effective token | Top-1 | Mean KL (nat) | Mean Δsurprisal (nat) | Max |Δlogit| | Free exact | Same pos. | LCP |",
            "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|",
        ]
    )
    for row in rows:
        lines.append(
            "| {row} | `{model}` | `{workload}` | {prefill} | {dense} | {container} | {ratio} | {saving} | {per_token} | {top1}/32 | {kl} | {surprisal} | {logit} | {free} | {same} | {lcp} |".format(
                row=row["row"],
                model=row["modelId"],
                workload=row["workloadId"],
                prefill=row["prefillTokens"],
                dense=row["denseBF16Bytes"],
                container=row["containerBytes"],
                ratio=_format_number(row["compressionRatio"]),
                saving=_format_number(row["spaceSavingFraction"]),
                per_token=_format_number(row["containerBytesPerEffectiveCacheToken"]),
                top1=row["controlledTop1AgreementCount"],
                kl=_format_number(row["meanKLDivergenceNat"]),
                surprisal=_format_number(row["meanBaselineSelectedTokenSurprisalDeltaNat"]),
                logit=_format_number(row["maxAbsLogitDifference"]),
                free="yes" if row["freeRunExact"] else "no",
                same=row["freeRunSamePositionCount"],
                lcp=row["freeRunLongestCommonPrefixTokens"],
            )
        )
    lines.extend(
        [
            "",
            "`R = denseBF16Bytes / containerBytes`; for example, R=2 means the complete container occupies half the canonical dense BF16 bytes. It does not mean twice as many logical tokens were retained.",
            "",
            "## What this run cannot establish",
            "",
            "Deterministic execution controls repeatability; it is not itself a compression multiplier. This matrix uses one fixed maximum prefill per model and varies content only at that fixed length. Comparing models confounds sequence length with architecture geometry, tokenizer, cache policy, and codec configuration, so these rows cannot establish that compression grows with path length, linearly or multiplicatively.",
            "",
            "A causal length test requires a preregistered within-model, within-workload prefill ladder while every other input remains fixed, followed by direct inspection of `R(P)` for each cell. No result here is promoted into the frozen scientific verdict.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def render_reproduce(record: dict[str, Any], directory_name: str) -> bytes:
    source = record["source"]
    archive = record["archive"]
    lines = [
        "# Reproducing the recorded RunPod sweep",
        "",
        "This guide has two distinct goals: reproduce the published record bytes from the retrieved export, or rerun the exploratory matrix from its exact source. Neither operation is an independent scientific replication unless a separately controlled experiment is designed and executed.",
        "",
        "## Pinned identity",
        "",
        f"- Sweep commit: `{source['sweepCommit']}`",
        f"- Sweep tree: `{source['sweepTree']}`",
        f"- Codec commit: `{source['codecCommit']}`",
        f"- Codec tree: `{source['codecTree']}`",
        f"- Container image: `{source['containerImageDigest']}`",
        f"- Retrieved archive SHA-256: `{archive['archiveSHA256']}`",
        f"- GPU/driver observed: `{source['gpuName']}` / `{source['gpuDriverVersion']}`",
        "",
        "The complete runtime-lock digests, source receipt, 28 raw rows, attempt history, and cleanup attestations are in `record.json`. Lifecycle fields are explicitly `OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED`: this builder checks their schema, grammar, and internal consistency, but does not query RunPod or independently verify termination, billing, volume deletion, or credential revocation. Do not substitute a model revision, tokenizer asset, workload path, runtime wheel, codec commit, image tag, or context target.",
        "",
        "## Rebuild this publication record",
        "",
        "1. Obtain the two retrieved files `corelm-runpod-adapter-sweep-v1.tar.gz` and `SHA256SUMS` in one owner-private directory. The archive itself is intentionally not committed to Git.",
        "2. Check out this repository and make sure the recorded sweep commit is present. Its signature must verify against `v4/signing/allowed_signers`.",
        "3. From the repository root, run:",
        "",
        "```bash",
        "python3 runpod-adapter-sweep-v1/recorded-runs/build_recorded_run.py verify \\",
        f"  --publication-dir runpod-adapter-sweep-v1/recorded-runs/{directory_name} \\",
        "  --export-dir /private/path/to/retrieved-export \\",
        "  --repository .",
        "```",
        "",
        "This rechecks the archive checksum, exactly one complete gzip member with no trailing bytes, the safe inventory, every canonical JSON sidecar, all 28 result/container/log bindings, the structural receipt, the seven representative replay receipts, the sweep commit signature and committed trust root, the exact signed-commit workload blobs and registered frames, the operator metadata, and the deterministic Markdown rendering.",
        "",
        "The builder binds asset receipts to signed profile paths/byte counts and every profile SHA-256 available in the registry, and requires identical raw/verified file inventories. It does not retrieve gated asset bytes. It also requires the exact registered codec commit/tree, eight-file manifest, and lock hashes. The codec signature and codec bytes remain a same-Pod source-receipt assertion (`SAME_POD_RECEIPT_NOT_LOCALLY_REVERIFIED`) because the codec repository is not an input. Token IDs and available/selected token counts remain `SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED`; the model-free publication builder does not locally retokenize. It does not rerun the model or independently decode the containers.",
        "",
        "## Rerun the matrix",
        "",
        "1. Read `../../RUNPOD.md` in full. Use exactly one admitted NVIDIA GPU with at least 78,000 MiB visible VRAM, the immutable image digest above, the 20-hour provider fuse, and the USD 35 ceiling.",
        "2. Accept the gated Gemma terms and create only a dedicated fine-grained read token. Map it through RunPod Secrets; never put it in a command, file, notebook, log, or repository.",
        "3. Clone both repositories into separate sterile checkouts, detach the sweep at the exact commit/tree above, verify both signed commits, and build the exact CUDA runtime with `build_cuda_runtime.sh`.",
        "4. Launch only through `run_on_runpod.sh`. It performs the model-free tests, asset materialization, 28 fresh-process cells, structural verification, seven same-Pod replays, privacy scan, and deterministic packaging.",
        "5. Retrieve the archive and checksum over the host-key-pinned SSH channel. Verify them before terminating the Pod.",
        "6. Terminate rather than stop the Pod; confirm the Pod volume is gone; delete the RunPod Secret; revoke the Hugging Face and lifecycle API tokens; retire the ephemeral SSH credential.",
        "",
        "A rerun creates a new attempt and new evidence hashes. Do not overwrite this directory or treat a matching trend as a frozen scientific verdict.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def write_exclusive(path: Path, raw: bytes) -> str:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    return sha256_bytes(raw)


def write_with_sidecar(root: Path, name: str, raw: bytes) -> str:
    digest = write_exclusive(root / name, raw)
    write_exclusive(root / f"{name}.sha256", f"{digest}  {name}\n".encode("ascii"))
    return digest


def build(arguments: argparse.Namespace) -> int:
    repository = Path(os.path.abspath(arguments.repository))
    output = Path(os.path.abspath(arguments.output))
    require(not output.exists(), "publication output already exists")
    require(RUN_DIRECTORY.fullmatch(output.name) is not None, "publication directory name differs")
    metadata, metadata_raw = read_private_json(arguments.operator_metadata, "operator metadata")
    export = read_export(arguments.export_dir)
    run, source, rows, structural, replay_receipts = _validate_archive_evidence(export, repository)
    verify_publication_input(metadata, source, export.archive_sha256)
    require(output.name == f"{metadata['recordedAt'][:10]}-attempt-{metadata['successfulAttemptNumber']:02d}", "publication directory name does not bind metadata")
    receipt = archive_receipt(export)
    receipt_raw = canonical_json_bytes(receipt) + b"\n"
    receipt_sha = sha256_bytes(receipt_raw)
    metadata_sha = sha256_bytes(metadata_raw)
    record = recorded_run(
        run=run,
        source=source,
        rows=rows,
        structural=structural,
        replay_receipts=replay_receipts,
        metadata=metadata,
        metadata_sha256=metadata_sha,
        receipt=receipt,
        receipt_sha256=receipt_sha,
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        write_with_sidecar(staging, "operator-metadata.json", metadata_raw)
        write_with_sidecar(staging, "archive-receipt.json", receipt_raw)
        write_with_sidecar(staging, "record.json", canonical_json_bytes(record) + b"\n")
        write_with_sidecar(staging, "RESULTS.md", render_results(record))
        write_with_sidecar(staging, "REPRODUCE.md", render_reproduce(record, output.name))
        os.replace(staging, output)
    except BaseException:
        for child in staging.iterdir():
            child.unlink()
        staging.rmdir()
        raise
    print(f"RECORDED RUN BUILT {output}")
    return 0


def _verify_publication_files(publication_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = public_directory(publication_dir, "publication directory")
    expected_bases = {"operator-metadata.json", "archive-receipt.json", "record.json", "RESULTS.md", "REPRODUCE.md"}
    expected = expected_bases | {f"{name}.sha256" for name in expected_bases}
    require({entry.name for entry in root.iterdir()} == expected, "publication directory inventory differs")
    raw_files: dict[str, bytes] = {}
    for name in expected_bases:
        maximum = MAX_JSON_BYTES if name.endswith(".json") else 8 * 1024**2
        public_regular(root / name, name, maximum)
        public_regular(root / f"{name}.sha256", f"{name} sidecar", 1024)
        raw = (root / name).read_bytes()
        digest = sha256_bytes(raw)
        require((root / f"{name}.sha256").read_bytes() == f"{digest}  {name}\n".encode("ascii"), f"publication sidecar differs: {name}")
        raw_files[name] = raw
    metadata = strict_json(raw_files["operator-metadata.json"], "operator metadata")
    receipt = strict_json(raw_files["archive-receipt.json"], "archive receipt")
    record = strict_json(raw_files["record.json"], "record")
    require(isinstance(metadata, dict) and isinstance(receipt, dict) and isinstance(record, dict), "publication JSON root differs")
    require(record.get("schemaVersion") == RECORDED_RUN_SCHEMA and receipt.get("schemaVersion") == ARCHIVE_RECEIPT_SCHEMA, "publication schema differs")
    require(record.get("archive") == receipt, "record archive receipt copy differs")
    require(record.get("archiveReceiptSHA256") == sha256_bytes(raw_files["archive-receipt.json"]), "archive receipt digest differs")
    require(record.get("operatorMetadataSHA256") == sha256_bytes(raw_files["operator-metadata.json"]), "operator metadata digest differs")
    require(record.get("attempts") == metadata.get("attempts") and record.get("lifecycle") == metadata.get("lifecycle") and record.get("operatorVerification") == metadata.get("operatorVerification"), "operator metadata copy differs")
    require(raw_files["RESULTS.md"] == render_results(record), "RESULTS.md is not the deterministic rendering")
    require(raw_files["REPRODUCE.md"] == render_reproduce(record, root.name), "REPRODUCE.md is not the deterministic rendering")
    rows = record.get("matrix", {}).get("rows")
    require(isinstance(rows, list) and len(rows) == 28 and [row.get("row") for row in rows] == list(range(1, 29)), "record matrix differs")
    require(record["matrix"].get("aggregationPolicy") == "NO_CROSS_CELL_OR_CROSS_MODEL_AVERAGES", "aggregation policy differs")
    require(record.get("scientificEvidence") is False and record.get("countsTowardScientificVerdict") is False and record.get("independentReplication") is False, "record claim boundary differs")
    return metadata, record


def verify(arguments: argparse.Namespace) -> int:
    metadata, record = _verify_publication_files(arguments.publication_dir)
    export = read_export(arguments.export_dir)
    run, source, rows, structural, replay_receipts = _validate_archive_evidence(
        export,
        Path(os.path.abspath(arguments.repository)),
    )
    verify_publication_input(metadata, source, export.archive_sha256)
    receipt = archive_receipt(export)
    receipt_raw = canonical_json_bytes(receipt) + b"\n"
    expected = recorded_run(
        run=run,
        source=source,
        rows=rows,
        structural=structural,
        replay_receipts=replay_receipts,
        metadata=metadata,
        metadata_sha256=sha256_bytes(canonical_json_bytes(metadata) + b"\n"),
        receipt=receipt,
        receipt_sha256=sha256_bytes(receipt_raw),
    )
    require(record == expected, "record does not reproduce from the retrieved export")
    print("RECORDED RUN VERIFIED")
    return 0


def update_index(arguments: argparse.Namespace) -> int:
    root = public_directory(arguments.runs_root, "recorded-runs root")
    runs: list[dict[str, Any]] = []
    for child in sorted(root.iterdir(), key=lambda path: path.name):
        if not child.is_dir() or RUN_DIRECTORY.fullmatch(child.name) is None:
            continue
        _, record = _verify_publication_files(child)
        record_sha, _ = sha256_file(child / "record.json", MAX_JSON_BYTES)
        runs.append(
            {
                "directory": child.name,
                "recordedAt": record["recordedAt"],
                "successfulAttemptNumber": record["successfulAttemptNumber"],
                "runId": record["verification"]["runId"],
                "sourceCommit": record["source"]["sweepCommit"],
                "archiveSHA256": record["archive"]["archiveSHA256"],
                "recordSHA256": record_sha,
                "status": record["status"],
                "classification": CLASSIFICATION,
                "countsTowardScientificVerdict": False,
            }
        )
    require(runs, "no recorded runs were found")
    runs.sort(key=lambda item: (item["recordedAt"], item["directory"]))
    document = {"schemaVersion": INDEX_SCHEMA, "classification": CLASSIFICATION, "countsTowardScientificVerdict": False, "runs": runs}
    raw = canonical_json_bytes(document) + b"\n"
    digest = sha256_bytes(raw)
    for name, content in (("index.json", raw), ("index.json.sha256", f"{digest}  index.json\n".encode("ascii"))):
        target = root / name
        temporary = root / f".{name}.{uuid.uuid4().hex}.tmp"
        write_exclusive(temporary, content)
        os.replace(temporary, target)
    print("RECORDED RUN INDEX UPDATED")
    return 0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--export-dir", type=Path, required=True)
    build_parser.add_argument("--operator-metadata", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--publication-dir", type=Path, required=True)
    verify_parser.add_argument("--export-dir", type=Path, required=True)
    verify_parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    index_parser = commands.add_parser("update-index")
    index_parser.add_argument("--runs-root", type=Path, default=Path(__file__).resolve().parent)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.command == "build":
        return build(arguments)
    if arguments.command == "verify":
        return verify(arguments)
    return update_index(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"RECORDED RUN FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
