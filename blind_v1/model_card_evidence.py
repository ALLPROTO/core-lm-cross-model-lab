"""Offline verification for the six exact Blind V1 model-card declarations.

The confirmatory weights are not redistributed.  This module verifies only the
exact upstream README bytes used as immutable license-declaration provenance;
it does not make an ownership, chain-of-title, or legal-compliance conclusion.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "corelm-blind-crossmodel-v1-model-card-evidence-v1"
SUITE_ID = "corelm-blind-crossmodel-v1"
STATUS = "PINNED_EXACT_REVISION_MODEL_CARDS_ARCHIVED"
EVIDENCE_SCOPE = (
    "EXACT_UPSTREAM_MODEL_CARD_DECLARATION_ONLY_NO_OWNERSHIP_OR_"
    "CHAIN_OF_TITLE_CLAIM"
)
MANIFEST_RELATIVE_PATH = "LICENSES/blind-v1-model-card-evidence.json"
MANIFEST_ARCHIVE_PATH = "blind-v1-model-card-evidence.json"
CARD_COUNT = 6
MAXIMUM_MANIFEST_BYTES = 128 * 1024
MAXIMUM_CARD_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
LICENSE_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}\Z")
CARD_FIELDS = frozenset(
    {
        "archivedEncoding",
        "archivedPath",
        "bytes",
        "declaredLicense",
        "modelKey",
        "relativePath",
        "repository",
        "revision",
        "sha256",
        "sourceURL",
        "standaloneLicenseOrNoticeFiles",
    }
)
MANIFEST_FIELDS = frozenset(
    {
        "cards",
        "cardCount",
        "evidenceScope",
        "retrievedAt",
        "schemaVersion",
        "status",
        "suiteId",
        "weightsRedistributed",
    }
)
BINDING_FIELDS = frozenset(
    {
        "path",
        "bytes",
        "sha256",
        "schemaVersion",
        "cardCount",
        "weightsRedistributed",
    }
)


class ModelCardEvidenceError(ValueError):
    """The offline model-card evidence is absent, changed, or ambiguous."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelCardEvidenceError("model-card evidence has duplicate JSON keys")
        result[key] = value
    return result


def _load_canonical_manifest(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAXIMUM_MANIFEST_BYTES or not raw.endswith(b"\n"):
        raise ModelCardEvidenceError("model-card evidence manifest framing differs")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelCardEvidenceError("model-card evidence manifest is invalid JSON") from error
    if not isinstance(value, dict):
        raise ModelCardEvidenceError("model-card evidence manifest is not an object")
    expected = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )
    if raw != expected:
        raise ModelCardEvidenceError("model-card evidence manifest is not canonical JSON")
    return value


def _decode_card(stored: bytes, *, encoding: str) -> bytes:
    if encoding == "identity":
        return stored
    if encoding != "base64":
        raise ModelCardEvidenceError("model-card archived encoding is unsupported")
    if not stored.endswith(b"\n") or b"\n" in stored[:-1] or b"\r" in stored:
        raise ModelCardEvidenceError("model-card base64 framing differs")
    encoded = stored[:-1]
    try:
        payload = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ModelCardEvidenceError("model-card base64 is invalid") from error
    if base64.b64encode(payload) != encoded:
        raise ModelCardEvidenceError("model-card base64 is not canonical")
    return payload


def _front_matter_license(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ModelCardEvidenceError("model card is not strict UTF-8") from error
    if not text.startswith("---\n"):
        raise ModelCardEvidenceError("model card has no YAML front matter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ModelCardEvidenceError("model-card YAML front matter is unterminated")
    matches = re.findall(r"(?m)^license:[ \t]*([a-z0-9][a-z0-9.-]*)[ \t]*$", text[4:end])
    if len(matches) != 1 or LICENSE_ID.fullmatch(matches[0]) is None:
        raise ModelCardEvidenceError("model card has no unique license declaration")
    return matches[0]


def validate_model_card_evidence_bytes(
    manifest_raw: bytes,
    archived_files: Mapping[str, bytes],
    models: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Cross-bind exact archived cards to the ordered frozen design models."""

    manifest = _load_canonical_manifest(manifest_raw)
    if set(manifest) != MANIFEST_FIELDS:
        raise ModelCardEvidenceError("model-card evidence manifest fields differ")
    if (
        manifest["schemaVersion"] != SCHEMA_VERSION
        or manifest["suiteId"] != SUITE_ID
        or manifest["status"] != STATUS
        or manifest["evidenceScope"] != EVIDENCE_SCOPE
        or manifest["weightsRedistributed"] is not False
        or manifest["cardCount"] != CARD_COUNT
        or not isinstance(manifest["retrievedAt"], str)
        or UTC_SECOND.fullmatch(manifest["retrievedAt"]) is None
    ):
        raise ModelCardEvidenceError("model-card evidence identity differs")
    cards = manifest["cards"]
    if (
        not isinstance(cards, list)
        or len(cards) != CARD_COUNT
        or not isinstance(models, Sequence)
        or isinstance(models, (str, bytes))
        or len(models) != CARD_COUNT
    ):
        raise ModelCardEvidenceError("model-card/model-pool cardinality differs")

    seen_paths: set[str] = set()
    seen_urls: set[str] = set()
    total_bytes = 0
    card_summaries: list[dict[str, Any]] = []
    for index, (card, model) in enumerate(zip(cards, models, strict=True)):
        if not isinstance(card, dict) or set(card) != CARD_FIELDS:
            raise ModelCardEvidenceError(f"model-card evidence fields differ at index {index}")
        if not isinstance(model, Mapping):
            raise ModelCardEvidenceError(f"frozen model is invalid at index {index}")
        expected_identity = (
            model.get("key"),
            model.get("repository"),
            model.get("revision"),
            model.get("license"),
        )
        observed_identity = (
            card["modelKey"],
            card["repository"],
            card["revision"],
            card["declaredLicense"],
        )
        if observed_identity != expected_identity:
            raise ModelCardEvidenceError(
                f"model-card evidence differs from frozen model at index {index}"
            )
        if (
            not isinstance(card["revision"], str)
            or GIT_OID.fullmatch(card["revision"]) is None
            or card["relativePath"] != "README.md"
            or card["standaloneLicenseOrNoticeFiles"] != []
            or not isinstance(card["bytes"], int)
            or isinstance(card["bytes"], bool)
            or not 0 < card["bytes"] <= MAXIMUM_CARD_BYTES
            or not isinstance(card["sha256"], str)
            or SHA256.fullmatch(card["sha256"]) is None
        ):
            raise ModelCardEvidenceError(f"model-card commitment is invalid at index {index}")
        expected_url = (
            f"https://huggingface.co/{card['repository']}/resolve/"
            f"{card['revision']}/README.md"
        )
        if card["sourceURL"] != expected_url:
            raise ModelCardEvidenceError(f"model-card source URL differs at index {index}")
        path = card["archivedPath"]
        if not isinstance(path, str):
            raise ModelCardEvidenceError(f"model-card archive path is invalid at index {index}")
        pure = PurePosixPath(path)
        if (
            pure.as_posix() != path
            or pure.is_absolute()
            or ".." in pure.parts
            or not path.startswith("upstream/blind-v1-")
            or path in seen_paths
            or card["sourceURL"] in seen_urls
        ):
            raise ModelCardEvidenceError(f"model-card archive identity differs at index {index}")
        stored = archived_files.get(path)
        if not isinstance(stored, bytes):
            raise ModelCardEvidenceError(f"archived model card is absent: {path}")
        payload = _decode_card(stored, encoding=card["archivedEncoding"])
        if len(payload) != card["bytes"] or _sha256(payload) != card["sha256"]:
            raise ModelCardEvidenceError(f"archived model-card digest differs: {path}")
        if _front_matter_license(payload) != card["declaredLicense"]:
            raise ModelCardEvidenceError(f"model-card license declaration differs: {path}")
        seen_paths.add(path)
        seen_urls.add(card["sourceURL"])
        total_bytes += len(payload)
        card_summaries.append(
            {
                "modelKey": card["modelKey"],
                "repository": card["repository"],
                "revision": card["revision"],
                "declaredLicense": card["declaredLicense"],
                "bytes": card["bytes"],
                "sha256": card["sha256"],
            }
        )
    return {
        "status": "VERIFIED_EXACT_MODEL_CARD_EVIDENCE",
        "manifestBytes": len(manifest_raw),
        "manifestSHA256": _sha256(manifest_raw),
        "cardCount": len(card_summaries),
        "totalDecodedCardBytes": total_bytes,
        "weightsRedistributed": False,
        "cards": card_summaries,
    }


def verify_model_card_evidence_tree(
    project_root: Path,
    models: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Read the tracked LICENSES bundle without following links and verify it."""

    root = project_root.resolve(strict=True)
    manifest_path = root / MANIFEST_RELATIVE_PATH
    paths = [manifest_path]
    manifest_raw = _read_regular(manifest_path, maximum_bytes=MAXIMUM_MANIFEST_BYTES)
    manifest = _load_canonical_manifest(manifest_raw)
    archived: dict[str, bytes] = {}
    for card in manifest.get("cards", []):
        if not isinstance(card, dict) or not isinstance(card.get("archivedPath"), str):
            raise ModelCardEvidenceError("model-card evidence entry is malformed")
        path = root / "LICENSES" / PurePosixPath(card["archivedPath"])
        paths.append(path)
        archived[card["archivedPath"]] = _read_regular(
            path, maximum_bytes=MAXIMUM_CARD_BYTES * 2
        )
    if len({path.resolve(strict=True) for path in paths}) != len(paths):
        raise ModelCardEvidenceError("model-card evidence paths alias")
    return validate_model_card_evidence_bytes(manifest_raw, archived, models)


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise ModelCardEvidenceError(f"model-card evidence is unreadable: {path}") from error
    try:
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ModelCardEvidenceError(
                    f"model-card evidence is not a unique regular file: {path}"
                )
            if before.st_size <= 0 or before.st_size > maximum_bytes:
                raise ModelCardEvidenceError(f"model-card evidence size differs: {path}")

            raw = bytearray()
            while len(raw) <= maximum_bytes:
                try:
                    chunk = os.read(
                        descriptor,
                        min(1024 * 1024, maximum_bytes + 1 - len(raw)),
                    )
                except InterruptedError:
                    continue
                if not chunk:
                    break
                raw.extend(chunk)

            after = os.fstat(descriptor)
        except OSError as error:
            raise ModelCardEvidenceError(
                f"model-card evidence read failed: {path}"
            ) from error
    finally:
        os.close(descriptor)

    stable_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
    )
    stable_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
    )
    if (
        len(raw) != before.st_size
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or stable_after != stable_before
    ):
        raise ModelCardEvidenceError(f"model-card evidence changed while read: {path}")
    return bytes(raw)


def expected_design_binding(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact small binding embedded in design and freeze artifacts."""

    return {
        "path": MANIFEST_RELATIVE_PATH,
        "bytes": summary["manifestBytes"],
        "sha256": summary["manifestSHA256"],
        "schemaVersion": SCHEMA_VERSION,
        "cardCount": CARD_COUNT,
        "weightsRedistributed": False,
    }


def validate_design_binding(binding: Any, summary: Mapping[str, Any]) -> None:
    if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
        raise ModelCardEvidenceError("design model-card evidence binding fields differ")
    if binding != expected_design_binding(summary):
        raise ModelCardEvidenceError("design model-card evidence binding differs")


__all__ = [
    "CARD_COUNT",
    "MANIFEST_ARCHIVE_PATH",
    "MANIFEST_RELATIVE_PATH",
    "ModelCardEvidenceError",
    "SCHEMA_VERSION",
    "expected_design_binding",
    "validate_design_binding",
    "validate_model_card_evidence_bytes",
    "verify_model_card_evidence_tree",
]
