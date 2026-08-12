#!/usr/bin/env python3
"""Download and verify the exact model assets for the adapter sweep."""

from __future__ import annotations

import argparse
import gc
import hashlib
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

os.umask(0o077)
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("DO_NOT_TRACK", "1")
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

from common import (  # noqa: E402
    MODEL_ORDER,
    PROFILES_PATH,
    canonical_json_bytes,
    git_blob_sha1,
    load_profiles,
    require,
    require_digest,
    require_exact_keys,
    require_regular,
    sha256_file,
    strict_json_file,
    verify_digest_sidecar,
    write_canonical_json,
)


CONVERSION_SCHEMA_VERSION = "corelm-runpod-opt-conversion-v1"


def safe_root(path: Path, label: str, *, create: bool) -> Path:
    unresolved = Path(os.path.abspath(path))
    if create:
        unresolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(unresolved, 0o700)
    require(unresolved.is_dir(), f"{label} is not a directory")
    require(unresolved == unresolved.resolve(), f"{label} traverses a symlink")
    status = unresolved.stat()
    require(status.st_uid == os.getuid(), f"{label} is not owner controlled")
    require(status.st_mode & 0o077 == 0, f"{label} is accessible to another user")
    return unresolved


def target_for(cache_root: Path, model_id: str) -> Path:
    path = cache_root / model_id
    require(path.parent == cache_root, "model cache path escaped its root")
    return path


def download_profile(profile: dict[str, Any], cache_root: Path) -> None:
    from huggingface_hub import hf_hub_download

    target = target_for(cache_root, profile["modelId"])
    target.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chmod(target, 0o700)
    token: str | bool = False
    if profile.get("gated") is True:
        value = os.environ.get("HF_TOKEN")
        require(isinstance(value, str) and value.strip(), "HF_TOKEN is required for the gated Gemma profile")
        token = value
    for asset in profile["files"]:
        relative = asset["path"]
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists():
            verify_asset(destination, asset, f"{profile['modelId']}/{relative}")
            continue
        resolved = Path(
            hf_hub_download(
                repo_id=profile["repository"],
                revision=profile["revision"],
                filename=relative,
                local_dir=target,
                token=token,
            )
        )
        require(resolved == destination, "Hugging Face returned an unexpected asset path")
        verify_asset(destination, asset, f"{profile['modelId']}/{relative}")
        os.chmod(destination, 0o600)
    metadata_root = target / ".cache"
    if metadata_root.exists():
        require(metadata_root.is_dir() and not metadata_root.is_symlink(), "unsafe Hugging Face local metadata path")
        shutil.rmtree(metadata_root)


def verify_asset(path: Path, asset: dict[str, Any], label: str) -> None:
    status = require_regular(path, label)
    require(status.st_uid == os.getuid(), f"asset is not owner controlled: {label}")
    require(status.st_size == int(asset["bytes"]), f"asset byte count differs: {label}")
    observed_sha256 = sha256_file(path)
    if asset.get("sha256") is None:
        raw = path.read_bytes()
        require(git_blob_sha1(raw) == asset["hfGitOidSha1"], f"gated Git blob OID differs: {label}")
    else:
        require(observed_sha256 == asset["sha256"], f"asset digest differs: {label}")


def conversion_environment_receipt() -> dict[str, Any]:
    forbidden = (
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "RUNPOD_API_KEY",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "SSH_AUTH_SOCK",
        "BASH_ENV",
        "ENV",
        "LD_PRELOAD",
    )
    require(not any(name in os.environ for name in forbidden), "OPT conversion inherited a credential or startup hook")
    require(os.environ.get("HF_HUB_OFFLINE") == "1", "OPT conversion is not in Hugging Face offline mode")
    require(os.environ.get("TRANSFORMERS_OFFLINE") == "1", "OPT conversion is not in Transformers offline mode")
    require(os.environ.get("HF_HUB_DISABLE_IMPLICIT_TOKEN") == "1", "OPT conversion permits implicit credentials")
    require(sys.flags.ignore_environment == 1, "OPT conversion Python did not use -E")
    require(sys.flags.no_user_site == 1, "OPT conversion Python did not use -s or isolated mode")
    require(sys.flags.dont_write_bytecode == 1, "OPT conversion Python did not use -B")
    return {
        "boundary": "application-offline-single-purpose-process",
        "credentialNamesPresent": [],
        "hfHubOffline": True,
        "implicitTokenDisabled": True,
        "pythonFlags": ["-E", "-s", "-B"],
        "transformersOffline": True,
    }


def convert_opt_weights(profile: dict[str, Any], cache_root: Path) -> dict[str, Any] | None:
    conversion = profile.get("weightConversion")
    if conversion is None:
        return None
    require(profile["modelId"] == "opt-125m", "only the pinned OPT profile may request conversion")
    require(conversion == "torch-weights-only-to-safetensors-v1", "unknown weight conversion")
    import torch
    from safetensors.torch import load_file, save_file

    target = target_for(cache_root, profile["modelId"])
    source = target / "pytorch_model.bin"
    output = target / "model.safetensors"
    require(not output.exists() and not output.is_symlink(), "converted OPT weights already exist")
    environment = conversion_environment_receipt()
    source_asset = next(asset for asset in profile["files"] if asset["path"] == source.name)
    require(source_asset["sha256"] == profile["weights"]["conversion"]["inputSha256"], "OPT source pins differ")
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "OPT source weights are not a regular file")
        require(before.st_nlink == 1, "OPT source weights have unexpected hard links")
        require(before.st_uid == os.getuid(), "OPT source weights are not owner controlled")
        require(before.st_size == int(source_asset["bytes"]), "OPT source byte count differs")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            digest = hashlib.sha256()
            while block := handle.read(1024 * 1024):
                digest.update(block)
            source_sha256 = digest.hexdigest()
            require(source_sha256 == source_asset["sha256"], "OPT source digest differs before parsing")
            handle.seek(0)
            state = torch.load(handle, map_location="cpu", weights_only=True)
        after = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "OPT source changed while it was parsed",
        )
    finally:
        os.close(descriptor)
    require(isinstance(state, dict) and state, "OPT weights are not a non-empty tensor mapping")
    tensors: dict[str, Any] = {}
    for key in sorted(state):
        value = state[key]
        require(isinstance(key, str) and key, "OPT state key is invalid")
        require(isinstance(value, torch.Tensor), f"OPT state value is not a tensor: {key}")
        require(value.layout == torch.strided, f"OPT state tensor is not strided: {key}")
        # Safetensors rejects shared storage. OPT intentionally ties its input
        # embeddings and language-model head, so materialize one independent,
        # contiguous CPU allocation per sorted state key before serialization.
        tensors[key] = value.detach().contiguous().clone()
    temporary = output.with_suffix(".safetensors.partial")
    require(not temporary.exists(), "stale OPT conversion temporary exists")
    save_file(
        tensors,
        temporary,
        metadata={
            "format": "pt",
            "source_sha256": source_sha256,
            "conversion": conversion,
        },
    )
    converted_state = load_file(temporary, device="cpu")
    require(set(converted_state) == set(tensors), "converted OPT key set differs")
    for key in sorted(tensors):
        require(
            converted_state[key].dtype == tensors[key].dtype
            and tuple(converted_state[key].shape) == tuple(tensors[key].shape)
            and bool(torch.equal(converted_state[key], tensors[key])),
            f"converted OPT tensor differs: {key}",
        )
    descriptor = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    del state, tensors, converted_state
    gc.collect()
    status = require_regular(output, "converted OPT weights")
    return {
        "bytes": status.st_size,
        "conversion": conversion,
        "environment": environment,
        "path": output.name,
        "sha256": sha256_file(output),
        "sourcePath": source.name,
        "sourceSha256": source_sha256,
        "sourceTensorEqualityVerified": True,
    }


def conversion_receipt(profile: dict[str, Any], cache_root: Path, path: Path) -> dict[str, Any]:
    value = strict_json_file(path, "OPT conversion receipt")
    require_exact_keys(
        value,
        {"schemaVersion", "status", "profileId", "profilesSHA256", "convertedWeights"},
        "OPT conversion receipt",
    )
    require(value["schemaVersion"] == CONVERSION_SCHEMA_VERSION, "OPT conversion receipt schema differs")
    require(value["status"] == "OPT_CONVERSION_COMPLETE", "OPT conversion receipt status differs")
    require(value["profileId"] == profile["profileId"], "OPT conversion receipt profile differs")
    require(value["profilesSHA256"] == sha256_file(PROFILES_PATH), "OPT conversion profile digest differs")
    converted = value["convertedWeights"]
    require_exact_keys(
        converted,
        {"bytes", "conversion", "environment", "path", "sha256", "sourcePath", "sourceSha256", "sourceTensorEqualityVerified"},
        "converted OPT weights",
    )
    require(converted["conversion"] == profile["weightConversion"], "OPT conversion contract differs")
    require(converted["path"] == "model.safetensors", "converted OPT path differs")
    require(converted["sourcePath"] == "pytorch_model.bin", "OPT conversion source path differs")
    require(converted["sourceTensorEqualityVerified"] is True, "OPT tensor equality was not verified")
    source = target_for(cache_root, profile["modelId"]) / converted["sourcePath"]
    output = target_for(cache_root, profile["modelId"]) / converted["path"]
    source_status = require_regular(source, "OPT conversion source")
    output_status = require_regular(output, "converted OPT weights")
    require(source_status.st_size > 0 and output_status.st_size == converted["bytes"], "OPT conversion byte count differs")
    require(converted["sourceSha256"] == sha256_file(source), "OPT conversion source digest differs")
    require(converted["sha256"] == sha256_file(output), "OPT conversion output digest differs")
    require_digest(converted["sourceSha256"], "OPT conversion source SHA-256")
    require_digest(converted["sha256"], "OPT conversion output SHA-256")
    require_exact_keys(
        converted["environment"],
        {"boundary", "credentialNamesPresent", "hfHubOffline", "implicitTokenDisabled", "pythonFlags", "transformersOffline"},
        "OPT conversion environment",
    )
    require(
        converted["environment"]
        == {
            "boundary": "application-offline-single-purpose-process",
            "credentialNamesPresent": [],
            "hfHubOffline": True,
            "implicitTokenDisabled": True,
            "pythonFlags": ["-E", "-s", "-B"],
            "transformersOffline": True,
        },
        "OPT conversion environment differs",
    )
    verify_digest_sidecar(path)
    return converted


def verify_all(
    cache_root: Path,
    receipt: Path | None,
    *,
    require_conversion: bool,
    conversion_receipt_path: Path | None = None,
) -> dict[str, Any]:
    manifest = load_profiles()
    profiles_result: list[dict[str, Any]] = []
    for profile in manifest["profiles"]:
        target = target_for(cache_root, profile["modelId"])
        require(target.is_dir() and target == target.resolve(), f"model directory is unsafe: {profile['modelId']}")
        files: list[dict[str, Any]] = []
        for asset in profile["files"]:
            path = target / asset["path"]
            verify_asset(path, asset, f"{profile['modelId']}/{asset['path']}")
            files.append({"path": asset["path"], "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        if profile.get("weightConversion") is None:
            converted = None
        elif require_conversion:
            require(conversion_receipt_path is not None, "OPT conversion receipt is required")
            converted = conversion_receipt(profile, cache_root, conversion_receipt_path)
        else:
            converted = None
        profiles_result.append(
            {
                "modelId": profile["modelId"],
                "repository": profile["repository"],
                "revision": profile["revision"],
                "files": files,
                "convertedWeights": converted,
            }
        )
    result = {
        "schemaVersion": "corelm-runpod-adapter-assets-v1",
        "status": "ASSETS_VERIFIED" if require_conversion else "RAW_ASSETS_VERIFIED",
        "modelOrder": list(MODEL_ORDER),
        "profilesSHA256": sha256_file(PROFILES_PATH),
        "profiles": profiles_result,
    }
    if receipt is not None:
        write_canonical_json(receipt, result)
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("download", "convert", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--receipt", type=Path)
        if name == "verify":
            command.add_argument("--conversion-receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    cache_root = safe_root(arguments.cache, "asset cache", create=arguments.command == "download")
    if arguments.command == "download":
        manifest = load_profiles()
        for profile in manifest["profiles"]:
            print(f"DOWNLOAD {profile['modelId']}", flush=True)
            download_profile(profile, cache_root)
        result = verify_all(cache_root, arguments.receipt, require_conversion=False)
    elif arguments.command == "convert":
        require(arguments.receipt is not None, "OPT conversion receipt path is required")
        manifest = load_profiles()
        profile = next(profile for profile in manifest["profiles"] if profile["modelId"] == "opt-125m")
        converted = convert_opt_weights(profile, cache_root)
        require(converted is not None, "OPT conversion did not produce a receipt")
        result = {
            "schemaVersion": CONVERSION_SCHEMA_VERSION,
            "status": "OPT_CONVERSION_COMPLETE",
            "profileId": profile["profileId"],
            "profilesSHA256": sha256_file(PROFILES_PATH),
            "convertedWeights": converted,
        }
        write_canonical_json(arguments.receipt, result)
    else:
        result = verify_all(
            cache_root,
            arguments.receipt,
            require_conversion=True,
            conversion_receipt_path=arguments.conversion_receipt,
        )
    print(canonical_json_bytes(result).decode("utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ASSET PREPARATION FAIL: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
