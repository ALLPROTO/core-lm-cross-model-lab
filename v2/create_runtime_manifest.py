#!/usr/bin/env python3
"""Create a complete byte inventory for the active blind-v2 Python runtime.

Run this script with the interpreter being inventoried.  The manifest includes
every regular file and symlink in both ``sys.prefix`` and ``sys.base_prefix``;
it does not treat mutable package names alone as runtime provenance.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any


V2_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V2_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v2.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    digest_regular_file,
    scan_tree,
    sha256_bytes,
    with_content_digest,
    write_new_bytes,
)


REGISTERED_PYTHON = (3, 12, 10)
ENVIRONMENT_KEYS = (
    "HF_HUB_DISABLE_TELEMETRY",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "PYTHONHASHSEED",
    "TOKENIZERS_PARALLELISM",
    "TRANSFORMERS_OFFLINE",
)


def command_output(arguments: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def git_identity(root: Path) -> dict[str, Any]:
    absolute = root.resolve(strict=True)
    commit = command_output(["git", "rev-parse", "HEAD"], absolute)
    tree = command_output(["git", "rev-parse", "HEAD^{tree}"], absolute)
    status = command_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], absolute
    )
    try:
        remote = command_output(["git", "remote", "get-url", "origin"], absolute)
    except subprocess.CalledProcessError:
        remote = None
    return {
        "commit": commit,
        "tree": tree,
        "origin": remote,
        "worktreeClean": status == "",
        "worktreeStatusSHA256": sha256_bytes(status.encode("utf-8")),
    }


def distribution_inventory() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        version = distribution.version
        if not name or not version:
            raise ValueError("installed distribution lacks Name or Version metadata")
        normalized = name.lower().replace("_", "-")
        if normalized in seen:
            raise ValueError(f"duplicate installed distribution: {normalized}")
        seen.add(normalized)
        metadata_text = distribution.read_text("METADATA")
        record_text = distribution.read_text("RECORD")
        license_expression = distribution.metadata.get("License-Expression")
        license_declared = distribution.metadata.get("License")
        requires_dist = sorted(distribution.metadata.get_all("Requires-Dist") or [])
        result.append(
            {
                "name": name,
                "normalizedName": normalized,
                "version": version,
                "metadataSHA256": (
                    sha256_bytes(metadata_text.encode("utf-8"))
                    if metadata_text is not None
                    else None
                ),
                "recordSHA256": (
                    sha256_bytes(record_text.encode("utf-8"))
                    if record_text is not None
                    else None
                ),
                "declaredFiles": len(distribution.files or ()),
                "licenseExpression": license_expression or None,
                "licenseDeclared": license_declared or None,
                "requiresDist": requires_dist,
            }
        )
    result.sort(key=lambda item: (item["normalizedName"], item["version"]))
    return result


def build_runtime_manifest(
    *,
    runtime_root: Path,
    requirements_locks: list[Path],
    lab_root: Path,
    codec_root: Path,
) -> dict[str, Any]:
    if sys.version_info[:3] != REGISTERED_PYTHON:
        raise ValueError(
            "runtime manifest requires registered Python 3.12.10, got "
            + platform.python_version()
        )
    expected_prefix = runtime_root.resolve(strict=True)
    active_prefix = Path(sys.prefix).resolve(strict=True)
    if active_prefix != expected_prefix:
        raise ValueError(
            f"active interpreter prefix differs: {active_prefix} != {expected_prefix}"
        )

    lock_inventory: list[dict[str, Any]] = []
    for path in requirements_locks:
        observed = digest_regular_file(path)
        lock_inventory.append(
            {
                "name": path.name,
                "bytes": observed["bytes"],
                "sha256": observed["sha256"],
            }
        )
    lock_inventory.sort(key=lambda item: item["name"])
    if len({item["name"] for item in lock_inventory}) != len(lock_inventory):
        raise ValueError("requirements lock basenames must be unique")

    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    base_tree = scan_tree(base_prefix)
    runtime_tree = (
        base_tree
        if base_prefix == expected_prefix
        else scan_tree(
            expected_prefix,
            external_roots={"base-python-root": base_prefix},
        )
    )
    packages = distribution_inventory()
    payload = {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-runtime-manifest-v1",
        "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
        "countsTowardScientificVerdict": False,
        "networkUsed": False,
        "modelInferenceUsed": False,
        "python": {
            "registeredVersion": "3.12.10",
            "version": platform.python_version(),
            "versionDetail": sys.version,
            "implementation": platform.python_implementation(),
            "cacheTag": sys.implementation.cache_tag,
            "byteorder": sys.byteorder,
            "executable": digest_regular_file(Path(sys.executable).resolve(strict=True)),
            "soabi": sysconfig.get_config_var("SOABI"),
            "multiarch": sysconfig.get_config_var("MULTIARCH"),
            "platformTag": sysconfig.get_platform(),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "macVersion": platform.mac_ver()[0] or None,
        },
        "environment": {key: os.environ.get(key) for key in ENVIRONMENT_KEYS},
        "requirementsLocks": lock_inventory,
        "installedDistributions": packages,
        "installedDistributionCount": len(packages),
        "runtimeTree": runtime_tree,
        "basePythonTree": base_tree,
        "basePythonDistinctFromRuntime": base_prefix != expected_prefix,
        "labSource": git_identity(lab_root),
        "codecSource": git_identity(codec_root),
    }
    return with_content_digest(payload)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument(
        "--requirements-lock",
        type=Path,
        action="append",
        dest="requirements_locks",
        required=True,
    )
    parser.add_argument("--lab-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--codec-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-clean-git",
        action="store_true",
        help="fail unless both lab and codec worktrees are pristine",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        manifest = build_runtime_manifest(
            runtime_root=arguments.runtime_root,
            requirements_locks=arguments.requirements_locks,
            lab_root=arguments.lab_root,
            codec_root=arguments.codec_root,
        )
        if arguments.require_clean_git:
            for source in ("labSource", "codecSource"):
                if manifest[source]["worktreeClean"] is not True:
                    raise ValueError(f"{source} worktree is not pristine")
        output_bytes = canonical_json_bytes(manifest) + b"\n"
        write_new_bytes(arguments.output, output_bytes)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"RUNTIME MANIFEST FAIL: {error}", file=sys.stderr)
        return 1
    summary = {
        "status": manifest["status"],
        "output": str(arguments.output),
        "fileBytes": len(output_bytes),
        "fileSHA256": sha256_bytes(output_bytes),
        "contentSHA256": manifest["contentSHA256"],
        "runtimeEntries": manifest["runtimeTree"]["entryCount"],
        "basePythonEntries": manifest["basePythonTree"]["entryCount"],
        "installedDistributions": manifest["installedDistributionCount"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
