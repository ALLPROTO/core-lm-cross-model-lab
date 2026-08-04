#!/usr/bin/env python3
"""Read-only, no-inference preflight for the prospective blind v3 suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.protocol import (  # noqa: E402
    load_json_strict,
    sha256_bytes,
    validate_design_registration_lifecycle,
    validate_model_asset_manifest,
)
from v3.reproducibility import verify_content_digest  # noqa: E402


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_no_symlinks(path: Path) -> tuple[int, Path]:
    absolute = _absolute_without_resolving(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise ValueError(f"path component is not a directory: {absolute}")
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError(
            f"directory path contains a symlink or invalid component: {absolute}"
        ) from error
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute


def _verify_open_regular_file(
    parent_descriptor: int,
    filename: str,
    specification: dict[str, Any],
    *,
    display_path: Path,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(filename, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise ValueError(
            f"asset is not a no-follow regular file: {display_path}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(
                f"asset is not a no-follow regular file: {display_path}"
            )
        if before.st_size != specification["bytes"]:
            raise ValueError(f"asset byte count mismatch: {display_path}")
        observed_digest = _sha256_descriptor(descriptor)
        after = os.fstat(descriptor)
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
        if identity_after != identity_before:
            raise ValueError(f"asset changed while hashing: {display_path}")
        if observed_digest != specification["sha256"]:
            raise ValueError(f"asset digest mismatch: {display_path}")
    finally:
        os.close(descriptor)


def verify_file_beneath(
    root: Path, relative: Path, specification: dict[str, Any]
) -> None:
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"invalid relative asset path: {relative}")
    descriptor, absolute_root = _open_directory_no_symlinks(root)
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for component in relative.parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                raise ValueError(
                    f"asset parent is not a no-follow directory: {absolute_root / relative}"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        _verify_open_regular_file(
            descriptor,
            relative.parts[-1],
            specification,
            display_path=absolute_root / relative,
        )
    except OSError as error:
        raise ValueError(
            f"asset path contains a symlink or invalid component: {absolute_root / relative}"
        ) from error
    finally:
        os.close(descriptor)


def verify_regular_file(path: Path, specification: dict[str, Any]) -> None:
    verify_file_beneath(path.parent, Path(path.name), specification)


def command_output(arguments: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def verify_codec_source(codec_root: Path, registration: dict[str, Any]) -> dict[str, Any]:
    descriptor, root = _open_directory_no_symlinks(codec_root)
    os.close(descriptor)
    source = registration["codecSource"]
    commit = command_output(["/usr/bin/git", "rev-parse", "HEAD"], root)
    if commit != source["commit"]:
        raise ValueError(f"codec commit mismatch: {commit} != {source['commit']}")
    tree = command_output(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], root)
    if tree != source["tree"]:
        raise ValueError(f"codec tree mismatch: {tree} != {source['tree']}")
    files: dict[str, Any] = {}
    for relative, specification in source["requiredFiles"].items():
        verify_file_beneath(root, Path(relative), specification)
        files[relative] = specification
    return {"commit": commit, "tree": tree, "files": files}


def verify_local_assets(
    asset_root: Path | None, manifest: dict[str, Any]
) -> dict[str, Any]:
    if asset_root is None:
        return {"provided": False, "verified": False, "files": 0}
    descriptor, root = _open_directory_no_symlinks(asset_root)
    os.close(descriptor)
    files = 0
    for model_key, model in manifest["models"].items():
        for filename, specification in model["files"].items():
            verify_file_beneath(
                root, Path(model_key) / filename, specification
            )
            files += 1
    return {"provided": True, "verified": True, "files": files}


def verify_asset_receipt(
    receipt_path: Path | None,
    *,
    manifest_path: Path,
    manifest: dict[str, Any],
    local_assets: dict[str, Any],
) -> dict[str, Any]:
    if receipt_path is None:
        return {"provided": False, "verified": False}
    if local_assets.get("verified") is not True:
        raise ValueError("asset receipt requires a verified local asset snapshot")
    receipt = load_json_strict(receipt_path)
    if not isinstance(receipt, dict):
        raise ValueError("asset receipt must contain an object")
    verify_content_digest(receipt)
    if receipt.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-asset-receipt-v1":
        raise ValueError("unexpected asset receipt schema")
    if receipt.get("status") != "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED":
        raise ValueError("asset receipt status differs")
    for field in ("countsTowardScientificVerdict", "networkUsed", "modelInferenceUsed"):
        if receipt.get(field) is not False:
            raise ValueError(f"asset receipt boundary differs: {field}")
    if receipt.get("fullSafetensorsBytesLocallyVerified") is not True:
        raise ValueError("asset receipt does not prove full safetensors rehashing")
    manifest_bytes = manifest_path.read_bytes()
    if receipt.get("manifestFileSHA256") != sha256_bytes(manifest_bytes):
        raise ValueError("asset receipt binds a different model manifest")
    if receipt.get("manifestFileBytes") != len(manifest_bytes):
        raise ValueError("asset receipt manifest byte count differs")
    if receipt.get("fileCount") != local_assets.get("files"):
        raise ValueError("asset receipt file count differs")
    models = receipt.get("models")
    if not isinstance(models, dict) or set(models) != set(manifest["models"]):
        raise ValueError("asset receipt model set differs")
    expected_total = 0
    expected_weight_total = 0
    for model_key, model in manifest["models"].items():
        receipt_model = models.get(model_key)
        if not isinstance(receipt_model, dict):
            raise ValueError(f"asset receipt model entry differs: {model_key}")
        for field in ("repository", "revision", "license", "licenseURL"):
            if receipt_model.get(field) != model.get(field):
                raise ValueError(f"asset receipt model field differs: {model_key}/{field}")
        receipt_files = receipt_model.get("files")
        if not isinstance(receipt_files, dict) or set(receipt_files) != set(model["files"]):
            raise ValueError(f"asset receipt file set differs: {model_key}")
        for filename, specification in model["files"].items():
            expected = {
                "bytes": specification["bytes"],
                "sha256": specification["sha256"],
            }
            if receipt_files.get(filename) != expected:
                raise ValueError(f"asset receipt file differs: {model_key}/{filename}")
            expected_total += specification["bytes"]
            if filename == "model.safetensors":
                expected_weight_total += specification["bytes"]
    if receipt.get("totalBytes") != expected_total:
        raise ValueError("asset receipt total byte count differs")
    if receipt.get("fullSafetensorsBytes") != expected_weight_total:
        raise ValueError("asset receipt safetensors byte count differs")
    return {
        "provided": True,
        "verified": True,
        "contentSHA256": receipt["contentSHA256"],
        "fileSHA256": sha256_bytes(receipt_path.read_bytes()),
        "files": receipt["fileCount"],
        "bytes": receipt["totalBytes"],
    }


def platform_safety() -> dict[str, Any]:
    result: dict[str, Any] = {
        "system": platform.system(),
        "machine": platform.machine(),
        "acPower": None,
        "freeMemoryPercent": None,
    }
    if platform.system() == "Darwin":
        battery = command_output(["/usr/bin/pmset", "-g", "batt"])
        pressure = command_output(["/usr/bin/memory_pressure", "-Q"])
        match = re.search(r"free percentage:\s*(\d+)%", pressure)
        result.update(
            {
                "acPower": "AC Power" in battery,
                "freeMemoryPercent": int(match.group(1)) if match else None,
                "batteryReport": battery,
                "memoryPressureReport": pressure,
            }
        )
    return result


def result_boundary() -> dict[str, Any]:
    result_root = V3_ROOT / "results"
    entries = sorted(path.name for path in result_root.iterdir())
    if entries != ["README.md"]:
        raise ValueError("blind v3 result directory is not pristine")
    return {"pristine": True, "entries": entries}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codec-root", type=Path, required=True)
    parser.add_argument(
        "--asset-root",
        type=Path,
        help="optional no-symlink layout <root>/<model-key>/<runtime-file>",
    )
    parser.add_argument("--require-assets", action="store_true")
    parser.add_argument(
        "--asset-receipt",
        type=Path,
        help="deterministic receipt created after rehashing every local asset",
    )
    parser.add_argument("--require-execution-ready", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    registration = load_json_strict(V3_ROOT / "design-registration.draft.json")
    blockers = validate_design_registration_lifecycle(registration)
    manifest = load_json_strict(V3_ROOT / "model-assets.draft.json")
    manifest_summary = validate_model_asset_manifest(manifest, registration)
    codec = verify_codec_source(arguments.codec_root, registration)
    assets = verify_local_assets(arguments.asset_root, manifest)
    asset_receipt = verify_asset_receipt(
        arguments.asset_receipt,
        manifest_path=V3_ROOT / "model-assets.draft.json",
        manifest=manifest,
        local_assets=assets,
    )
    safety = platform_safety()
    boundary = result_boundary()
    readiness_failures: list[str] = []
    if blockers:
        readiness_failures.append(f"{len(blockers)} design freeze blockers remain")
    if registration["status"] != "PUBLIC_DESIGN_FROZEN":
        readiness_failures.append("design is not an immutable public frozen release")
    if asset_receipt["verified"] is not True:
        readiness_failures.append("full safetensors bytes are not locally rehashed")
    if not assets["verified"]:
        readiness_failures.append("full local asset snapshot was not provided")
    if sys.version_info[:3] != (3, 12, 10):
        readiness_failures.append("interpreter is not pinned Python 3.12.10")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        readiness_failures.append("primary one-shot requires macOS on arm64")
    else:
        if safety["acPower"] is not True:
            readiness_failures.append("Mac is not connected to AC power")
        free = safety["freeMemoryPercent"]
        if type(free) is not int or free < 50:
            readiness_failures.append("free memory is below the registered 50% floor")
    result = {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-preflight-v1",
        "status": "DEVELOPMENT_PREFLIGHT_ONLY",
        "countsTowardScientificVerdict": False,
        "networkUsed": False,
        "modelInferenceUsed": False,
        "corpusOpened": False,
        "attemptMarkerCreated": False,
        "primaryPlatformRequired": "Darwin-arm64",
        "designSHA256": sha256_bytes(
            (V3_ROOT / "design-registration.draft.json").read_bytes()
        ),
        "codec": codec,
        "assetManifest": manifest_summary,
        "localAssets": assets,
        "assetReceipt": asset_receipt,
        "platformSafety": safety,
        "resultBoundary": boundary,
        "executionReady": not readiness_failures,
        "readinessFailures": readiness_failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if arguments.require_assets and not assets["verified"]:
        return 2
    if arguments.require_execution_ready and readiness_failures:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
