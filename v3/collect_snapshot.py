#!/usr/bin/env python3
"""Collect and independently replay the registered blind-v3 corpus snapshot.

This is the production command-line boundary around ``mediawiki_snapshot``.
It verifies every file committed by the model-asset manifest, loads only the
three committed ``tokenizer.json`` files into owned byte buffers, and then
performs the two registered MediaWiki crawls through an explicitly pinned CA
bundle.  It never imports model weights, runs inference, opens the codec, or
creates one-shot evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.fetch_assets import (  # noqa: E402
    DEFAULT_MANIFEST,
    AssetFetchError,
    AssetSpecification,
    load_manifest,
)
from v3.mediawiki_snapshot import (  # noqa: E402
    CRAWL_NOT_BEFORE,
    CRAWL_STAGE_SCHEMA,
    MODEL_KEYS,
    PROJECTS,
    PinnedHTTPSClient,
    SnapshotError,
    TokenizerLike,
    collect_crawl_stage,
    finalize_snapshot,
    verify_corpus_snapshot,
)
from v3.preflight import verify_file_beneath  # noqa: E402
from v3.protocol import sha256_bytes  # noqa: E402


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOKENIZER_FILENAME = "tokenizer.json"
WEIGHT_FILENAME = "model.safetensors"
READ_CHUNK_BYTES = 1024 * 1024


class CollectorCLIError(RuntimeError):
    """The production collector boundary was not satisfied."""


@dataclass(frozen=True)
class VerifiedAssets:
    manifest_sha256: str
    file_count: int
    total_bytes: int
    tokenizer_bytes: Mapping[str, bytes]


@dataclass(frozen=True)
class OwnedTokenizer:
    """Small adapter that exposes only the tokenizer operation the collector uses."""

    tokenizer: Any
    vocab_size: int

    def encode(self, text: str, *, add_special_tokens: bool) -> Sequence[int]:
        encoding = self.tokenizer.encode(
            text, add_special_tokens=add_special_tokens
        )
        token_ids = getattr(encoding, "ids", None)
        if not isinstance(token_ids, list):
            raise CollectorCLIError("tokenizer did not return an owned token ID list")
        return list(token_ids)


TokenizerFactory = Callable[[str, bytes], TokenizerLike]
HTTPSClientFactory = Callable[..., Any]
VerifySnapshot = Callable[..., dict[str, Any]]
CollectCrawlStage = Callable[..., dict[str, Any]]
FinalizeSnapshot = Callable[..., dict[str, Any]]


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_no_symlinks(path: Path) -> tuple[int, Path]:
    """Open an absolute directory one no-follow component at a time."""

    absolute = _absolute_without_resolving(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise CollectorCLIError(
                    f"directory component is not a directory: {absolute}"
                )
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        raise CollectorCLIError(
            f"directory path contains a symlink or invalid component: {absolute}"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute


def _assert_directory_chain(path: Path) -> Path:
    descriptor, absolute = _open_directory_no_symlinks(path)
    os.close(descriptor)
    return absolute


def _read_owned_verified_file(
    root: Path,
    relative: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> bytes:
    """Read one exact regular file through no-follow descriptors into owned bytes."""

    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise CollectorCLIError(f"unsafe relative file path: {relative}")
    descriptor, absolute_root = _open_directory_no_symlinks(root)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise CollectorCLIError(f"file parent is not a directory: {relative}")
            os.close(descriptor)
            descriptor = child
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(relative.parts[-1], file_flags, dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise CollectorCLIError(f"regular file required: {relative}")
            if before.st_size != expected_bytes:
                raise CollectorCLIError(f"file byte count mismatch: {relative}")
            chunks: list[bytes] = []
            observed = 0
            digest = hashlib.sha256()
            while True:
                chunk = os.read(file_descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                digest.update(chunk)
            after = os.fstat(file_descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if identity_after != identity_before or observed != expected_bytes:
                raise CollectorCLIError(f"file changed while reading: {relative}")
            if digest.hexdigest() != expected_sha256:
                raise CollectorCLIError(f"file SHA-256 mismatch: {relative}")
            return b"".join(chunks)
        finally:
            os.close(file_descriptor)
    except OSError as error:
        raise CollectorCLIError(
            f"file path contains a symlink, missing component, or invalid file: {relative}"
        ) from error
    finally:
        os.close(descriptor)


def _read_owned_path(path: Path) -> bytes:
    absolute = _absolute_without_resolving(path)
    parent_descriptor, parent = _open_directory_no_symlinks(absolute.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise CollectorCLIError(
                f"regular non-symlink file required: {absolute}"
            ) from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise CollectorCLIError(f"regular file required: {absolute}")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or observed != before.st_size
            ):
                raise CollectorCLIError(f"file changed while reading: {absolute}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CollectorCLIError(f"cannot read regular file: {absolute}") from error
    finally:
        os.close(parent_descriptor)


def verify_assets_and_load_tokenizer_bytes(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    asset_root: Path,
) -> VerifiedAssets:
    """Verify the complete manifest snapshot and retain exact tokenizer bytes."""

    if SHA256.fullmatch(expected_manifest_sha256) is None:
        raise CollectorCLIError("asset manifest SHA-256 must be 64 lowercase hex digits")
    manifest_bytes = _read_owned_path(manifest_path)
    manifest_sha256 = sha256_bytes(manifest_bytes)
    if manifest_sha256 != expected_manifest_sha256:
        raise CollectorCLIError("asset manifest SHA-256 differs from the explicit pin")
    try:
        specifications = load_manifest(manifest_path)
    except AssetFetchError as error:
        raise CollectorCLIError(str(error)) from error
    if _read_owned_path(manifest_path) != manifest_bytes:
        raise CollectorCLIError("asset manifest changed while it was being validated")

    grouped: dict[str, dict[str, AssetSpecification]] = {}
    for specification in specifications:
        grouped.setdefault(specification.model_key, {})[specification.filename] = specification
    if tuple(grouped) != MODEL_KEYS:
        raise CollectorCLIError("asset manifest model order/set differs from the design")
    for model_key in MODEL_KEYS:
        files = grouped[model_key]
        if TOKENIZER_FILENAME not in files or WEIGHT_FILENAME not in files:
            raise CollectorCLIError(
                f"asset manifest omits tokenizer or safetensors bytes for {model_key}"
            )

    total_bytes = 0
    for specification in specifications:
        try:
            verify_file_beneath(
                asset_root,
                Path(specification.model_key) / specification.filename,
                {
                    "bytes": specification.expected_bytes,
                    "sha256": specification.expected_sha256,
                },
            )
        except (OSError, ValueError) as error:
            raise CollectorCLIError(str(error)) from error
        total_bytes += specification.expected_bytes

    tokenizer_bytes: dict[str, bytes] = {}
    for model_key in MODEL_KEYS:
        specification = grouped[model_key][TOKENIZER_FILENAME]
        tokenizer_bytes[model_key] = _read_owned_verified_file(
            asset_root,
            Path(model_key) / TOKENIZER_FILENAME,
            expected_bytes=specification.expected_bytes,
            expected_sha256=specification.expected_sha256,
        )
    return VerifiedAssets(
        manifest_sha256=manifest_sha256,
        file_count=len(specifications),
        total_bytes=total_bytes,
        tokenizer_bytes=tokenizer_bytes,
    )


def default_tokenizer_factory(model_key: str, tokenizer_bytes: bytes) -> TokenizerLike:
    """Construct one tokenizer exclusively from already verified owned bytes."""

    try:
        tokenizer_json = tokenizer_bytes.decode("utf-8", errors="strict")
        from tokenizers import Tokenizer

        tokenizer = Tokenizer.from_str(tokenizer_json)
        vocab_size = tokenizer.get_vocab_size(with_added_tokens=True)
    except Exception as error:
        raise CollectorCLIError(
            f"cannot construct frozen tokenizer for {model_key}: {error}"
        ) from error
    if type(vocab_size) is not int or not 1 <= vocab_size <= 2**32:
        raise CollectorCLIError("tokenizer vocabulary size is outside uint32")
    return OwnedTokenizer(tokenizer=tokenizer, vocab_size=vocab_size)


def _assert_new_output_root(root: Path) -> Path:
    absolute = _absolute_without_resolving(root)
    parent_descriptor, _ = _open_directory_no_symlinks(absolute.parent)
    try:
        try:
            os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CollectorCLIError("snapshot output root must not already exist")
    finally:
        os.close(parent_descriptor)
    return absolute


def _create_new_output_root(root: Path) -> Path:
    """Create the already checked root exclusively and durably beneath its parent."""

    absolute = _absolute_without_resolving(root)
    parent_descriptor, _ = _open_directory_no_symlinks(absolute.parent)
    try:
        try:
            os.mkdir(absolute.name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise CollectorCLIError("snapshot output root appeared concurrently") from error
        os.fsync(parent_descriptor)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise CollectorCLIError("new snapshot root is not a directory")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CollectorCLIError(f"cannot create snapshot output root: {absolute}") from error
    finally:
        os.close(parent_descriptor)
    return absolute


def _assert_existing_output_root(root: Path) -> Path:
    absolute = _assert_directory_chain(root)
    if not absolute.is_dir() or absolute.is_symlink():
        raise CollectorCLIError("snapshot stage root must be a regular directory")
    return absolute


def _prepare_collection_dependencies(
    *,
    manifest_path: Path,
    manifest_sha256: str,
    asset_root: Path,
    ca_bundle: Path,
    ca_bundle_sha256: str,
    tokenizer_factory: TokenizerFactory,
    https_client_factory: HTTPSClientFactory,
) -> tuple[VerifiedAssets, Any, dict[str, TokenizerLike]]:
    if SHA256.fullmatch(ca_bundle_sha256) is None:
        raise CollectorCLIError("CA bundle SHA-256 must be 64 lowercase hex digits")
    ca_bytes = _read_owned_path(ca_bundle)
    if sha256_bytes(ca_bytes) != ca_bundle_sha256:
        raise CollectorCLIError("CA bundle SHA-256 differs from the explicit pin")
    assets = verify_assets_and_load_tokenizer_bytes(
        manifest_path=manifest_path,
        expected_manifest_sha256=manifest_sha256,
        asset_root=asset_root,
    )
    # PinnedHTTPSClient independently checks the CA bytes against this digest.
    transport = https_client_factory(
        ca_bundle=ca_bundle,
        ca_bundle_sha256=ca_bundle_sha256,
        allowed_hosts=PROJECTS,
    )
    tokenizers: dict[str, TokenizerLike] = {
        model_key: tokenizer_factory(model_key, assets.tokenizer_bytes[model_key])
        for model_key in MODEL_KEYS
    }
    return assets, transport, tokenizers


def _freeze_ready_report(
    *,
    root: Path,
    assets: VerifiedAssets,
    manifest: Any,
    verification: Any,
) -> dict[str, Any]:
    if (
        not isinstance(manifest, dict)
        or manifest.get("status") != "SNAPSHOT_READY_FOR_FREEZE"
        or manifest.get("countsTowardScientificVerdict") is not False
    ):
        raise CollectorCLIError("collected snapshot is not freeze-ready")
    if not isinstance(verification, dict):
        raise CollectorCLIError("snapshot verifier returned no structured report")
    if verification.get("status") != "VERIFIED_SNAPSHOT_BYTES":
        raise CollectorCLIError("snapshot verifier status differs")
    if verification.get("readyForFreeze") is not True:
        raise CollectorCLIError("snapshot verifier did not establish freeze readiness")
    if verification.get("tokenCommitmentsRecomputed") is not True:
        raise CollectorCLIError("snapshot verifier did not recompute token commitments")
    if verification.get("modelInferenceUsed") is not False:
        raise CollectorCLIError("snapshot verifier crossed the no-inference boundary")
    eligible_records = verification.get("eligibleRecords")
    manifest_digest = verification.get("manifestSHA256")
    if type(eligible_records) is not int or eligible_records < 3 * 64:
        raise CollectorCLIError("snapshot verifier eligible record count is insufficient")
    if not isinstance(manifest_digest, str) or SHA256.fullmatch(manifest_digest) is None:
        raise CollectorCLIError("snapshot verifier manifest digest is invalid")
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-collector-run-v1",
        "status": "SNAPSHOT_READY_FOR_FREEZE",
        "countsTowardScientificVerdict": False,
        "modelInferenceUsed": False,
        "outputRoot": str(root),
        "assetManifestSHA256": assets.manifest_sha256,
        "assetFilesVerified": assets.file_count,
        "assetBytesVerified": assets.total_bytes,
        "tokenizerFilesLoaded": len(assets.tokenizer_bytes),
        "eligibleRecords": eligible_records,
        "corpusManifestSHA256": manifest_digest,
        "tokenCommitmentsRecomputed": True,
    }


def run_collector_phase(
    *,
    phase: str,
    manifest_path: Path,
    manifest_sha256: str,
    asset_root: Path,
    ca_bundle: Path,
    ca_bundle_sha256: str,
    output_root: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    tokenizer_factory: TokenizerFactory = default_tokenizer_factory,
    https_client_factory: HTTPSClientFactory = PinnedHTTPSClient,
    collect_crawl_stage_fn: CollectCrawlStage = collect_crawl_stage,
    finalize_snapshot_fn: FinalizeSnapshot = finalize_snapshot,
    verify_snapshot_fn: VerifySnapshot = verify_corpus_snapshot,
) -> dict[str, Any]:
    """Run one durable crawl/finalize phase; partial failed stages are not resumed."""

    if phase not in {"crawl-1", "crawl-2", "finalize"}:
        raise CollectorCLIError("collector phase is not registered")
    root = (
        _assert_new_output_root(output_root)
        if phase == "crawl-1"
        else _assert_existing_output_root(output_root)
    )
    assets, transport, tokenizers = _prepare_collection_dependencies(
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        asset_root=asset_root,
        ca_bundle=ca_bundle,
        ca_bundle_sha256=ca_bundle_sha256,
        tokenizer_factory=tokenizer_factory,
        https_client_factory=https_client_factory,
    )
    if phase == "crawl-1":
        root = _create_new_output_root(root)
    if phase in {"crawl-1", "crawl-2"}:
        crawl_index = 0 if phase == "crawl-1" else 1
        stage = collect_crawl_stage_fn(
            root=root,
            crawl_index=crawl_index,
            transport=transport,
            clock=clock,
        )
        expected_not_before = CRAWL_NOT_BEFORE[crawl_index].strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if not isinstance(stage, dict) or set(stage) != {
            "schemaVersion",
            "countsTowardScientificVerdict",
            "crawlIndex",
            "notBefore",
            "projects",
        }:
            raise CollectorCLIError("crawl stage completion manifest differs")
        if (
            stage.get("schemaVersion") != CRAWL_STAGE_SCHEMA
            or stage.get("crawlIndex") != crawl_index + 1
            or stage.get("notBefore") != expected_not_before
            or stage.get("countsTowardScientificVerdict") is not False
            or not isinstance(stage.get("projects"), dict)
            or tuple(stage["projects"]) != PROJECTS
        ):
            raise CollectorCLIError("crawl stage completion manifest differs")
        return {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-collector-stage-run-v1",
            "status": f"CRAWL_{crawl_index + 1}_ARCHIVED",
            "freezeReady": False,
            "countsTowardScientificVerdict": False,
            "modelInferenceUsed": False,
            "outputRoot": str(root),
            "assetManifestSHA256": assets.manifest_sha256,
            "assetFilesVerified": assets.file_count,
            "assetBytesVerified": assets.total_bytes,
            "tokenizerFilesLoaded": len(assets.tokenizer_bytes),
        }

    manifest = finalize_snapshot_fn(
        root=root, transport=transport, tokenizers=tokenizers
    )
    verification = verify_snapshot_fn(root, tokenizers=tokenizers)
    return _freeze_ready_report(
        root=root, assets=assets, manifest=manifest, verification=verification
    )


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--phase",
        choices=("crawl-1", "crawl-2", "finalize"),
        required=True,
        help="required durable two-day collection phase",
    )
    parser.add_argument("--asset-manifest-sha256", required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--ca-bundle-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        common = {
            "manifest_path": arguments.asset_manifest,
            "manifest_sha256": arguments.asset_manifest_sha256,
            "asset_root": arguments.asset_root,
            "ca_bundle": arguments.ca_bundle,
            "ca_bundle_sha256": arguments.ca_bundle_sha256,
            "output_root": arguments.output_root,
        }
        report = run_collector_phase(phase=arguments.phase, **common)
    except (CollectorCLIError, SnapshotError, OSError, ValueError) as error:
        print(f"SNAPSHOT COLLECTION FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
