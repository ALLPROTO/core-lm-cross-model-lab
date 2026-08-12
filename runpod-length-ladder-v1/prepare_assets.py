#!/usr/bin/env python3
"""Materialize and verify only the pinned Qwen assets for the length ladder."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import re
from pathlib import Path
from typing import Any


os.umask(0o077)
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("DO_NOT_TRACK", "1")
sys.dont_write_bytecode = True

from common import (  # noqa: E402
    ASSET_SCHEMA_VERSION_LENGTH,
    LENGTH_MODEL_ID,
    PROFILES_PATH,
    canonical_json_bytes,
    profile_object_sha256,
    require,
    require_regular,
    selected_profile,
    sha256_file,
    verify_length_assets,
    write_canonical_json,
)


FORBIDDEN_CREDENTIALS = {
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "RUNPOD_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SSH_AUTH_SOCK",
}
FORBIDDEN_CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY|REFRESH_TOKEN|CLIENT_SECRET|CREDENTIALS?)(?:$|_)",
    re.IGNORECASE,
)
SAFE_NONCREDENTIAL_CONTROL_VALUES = {
    "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
}


def require_clean_credentials() -> None:
    present = sorted(
        name
        for name, value in os.environ.items()
        if (
            name in FORBIDDEN_CREDENTIALS
            or FORBIDDEN_CREDENTIAL_NAME.search(name) is not None
        )
        and SAFE_NONCREDENTIAL_CONTROL_VALUES.get(name) != value
    )
    require(not present, f"asset process inherited forbidden credentials: {present}")


def safe_cache(path: Path, *, create: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(absolute, 0o700)
    require(
        absolute.is_dir() and not absolute.is_symlink(), "asset cache is not a directory"
    )
    require(absolute == absolute.resolve(), "asset cache traverses a symlink")
    status = absolute.stat()
    require(
        status.st_uid == os.getuid() and status.st_mode & 0o077 == 0,
        "asset cache is not private and owner controlled",
    )
    return absolute


def _verify_one(path: Path, asset: dict[str, Any]) -> dict[str, Any]:
    status = require_regular(path, f"asset {asset['path']}")
    require(
        status.st_uid == os.getuid()
        and status.st_nlink == 1
        and status.st_mode & 0o022 == 0,
        f"asset is not private and owner controlled: {asset['path']}",
    )
    digest = sha256_file(path)
    require(
        status.st_size == int(asset["bytes"]) and digest == asset["sha256"],
        f"asset bytes differ: {asset['path']}",
    )
    return {"path": asset["path"], "bytes": status.st_size, "sha256": digest}


def download(cache: Path) -> None:
    from huggingface_hub import hf_hub_download

    profile = selected_profile()
    target = cache / LENGTH_MODEL_ID
    require(target.parent == cache, "asset target escaped cache")
    target.mkdir(mode=0o700, exist_ok=True)
    os.chmod(target, 0o700)
    for asset in profile["files"]:
        destination = target / asset["path"]
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists():
            _verify_one(destination, asset)
            continue
        resolved = Path(
            hf_hub_download(
                repo_id=profile["repository"],
                revision=profile["revision"],
                filename=asset["path"],
                local_dir=target,
                token=False,
            )
        )
        require(resolved == destination, "Hugging Face returned an unexpected path")
        os.chmod(destination, 0o600)
        _verify_one(destination, asset)
    metadata = target / ".cache"
    if metadata.exists():
        require(
            metadata.is_dir()
            and not metadata.is_symlink()
            and metadata.resolve().is_relative_to(target),
            "Hugging Face metadata path is unsafe",
        )
        shutil.rmtree(metadata)


def receipt_value(cache: Path) -> dict[str, Any]:
    profile = selected_profile()
    target = cache / LENGTH_MODEL_ID
    require(target.is_dir() and target == target.resolve(), "asset snapshot is unsafe")
    files = [_verify_one(target / asset["path"], asset) for asset in profile["files"]]
    expected = {asset["path"] for asset in profile["files"]}
    actual: set[str] = set()
    for candidate in target.rglob("*"):
        status = candidate.lstat()
        require(not stat.S_ISLNK(status.st_mode), "asset snapshot contains a symlink")
        if stat.S_ISREG(status.st_mode):
            actual.add(candidate.relative_to(target).as_posix())
        elif not stat.S_ISDIR(status.st_mode):
            raise RuntimeError("asset snapshot contains a special file")
    require(actual == expected, "asset snapshot has missing or extra files")
    require(
        {entry.name for entry in cache.iterdir()} == {LENGTH_MODEL_ID},
        "asset cache must contain only the selected Qwen snapshot",
    )
    return {
        "schemaVersion": ASSET_SCHEMA_VERSION_LENGTH,
        "status": "ASSETS_VERIFIED",
        "modelId": profile["modelId"],
        "repository": profile["repository"],
        "revision": profile["revision"],
        "sourceProfilesSHA256": sha256_file(PROFILES_PATH),
        "profileObjectSHA256": profile_object_sha256(profile),
        "files": files,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("download", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    require_clean_credentials()
    cache = safe_cache(arguments.cache, create=arguments.command == "download")
    if arguments.command == "download":
        download(cache)
        value = receipt_value(cache)
        write_canonical_json(arguments.receipt, value)
    else:
        value, _ = verify_length_assets(arguments.receipt, cache)
    print(canonical_json_bytes(value).decode("utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"LENGTH ASSET PREPARATION FAIL: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
