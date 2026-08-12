#!/usr/bin/env python3
"""Shared fail-closed primitives for the RunPod adapter sweep.

This module intentionally depends only on the Python standard library.  Model
and codec imports happen only in the producer or replay process after all
manifests and source paths have been validated.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, NoReturn


SUITE_ROOT = Path(__file__).resolve().parent
LAB_ROOT = SUITE_ROOT.parent
PROFILES_PATH = SUITE_ROOT / "profiles.json"
WORKLOADS_PATH = SUITE_ROOT / "workloads.json"
PROTOCOL_PATH = SUITE_ROOT / "PROTOCOL.md"
TORCH_LOCK_PATH = SUITE_ROOT / "torch-linux-cu130-py312.txt"

SCHEMA_VERSION = "corelm-runpod-adapter-sweep-v1"
PROFILE_SCHEMA_VERSION = "corelm-runpod-adapter-profiles-v1"
WORKLOAD_SCHEMA_VERSION = "corelm-runpod-adapter-sweep-workloads-v1"
RESULT_SCHEMA_VERSION = "corelm-runpod-adapter-cell-v1"
RUN_SCHEMA_VERSION = "corelm-runpod-adapter-run-v1"
ATTEMPT_SCHEMA_VERSION = "corelm-runpod-adapter-cell-attempt-v1"
ASSET_SCHEMA_VERSION = "corelm-runpod-adapter-assets-v1"
CLASSIFICATION = "EXPLORATORY_PUBLIC_REGRESSION_ONLY"

MODEL_ORDER = (
    "qwen2.5-0.5b",
    "smollm2-135m",
    "mistral-7b-v0.1",
    "pythia-14m",
    "distilgpt2",
    "opt-125m",
    "gemma-2b",
)
ADAPTER_ORDER = (
    "qwen2-dynamic-cache-v1",
    "llama-dynamic-cache-v1",
    "mistral-dynamic-cache-v1",
    "gpt-neox-dynamic-cache-v1",
    "gpt2-dynamic-cache-v1",
    "opt-dynamic-cache-v1",
    "gemma-dynamic-cache-v1",
)

HORIZON = 32
MAX_MATRIX_ELEMENTS = 2 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")

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


class ContractError(RuntimeError):
    """A frozen input, result, or filesystem invariant failed."""


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw, usedforsecurity=False).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {value}")


def strict_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def require_regular(path: Path, label: str, *, links: int = 1) -> os.stat_result:
    try:
        status = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is absent: {path}")
    require(stat.S_ISREG(status.st_mode), f"{label} is not a regular file: {path}")
    require(not stat.S_ISLNK(status.st_mode), f"{label} is a symlink: {path}")
    require(status.st_nlink == links, f"{label} has unexpected hard links: {path}")
    return status


def strict_json_file(path: Path, label: str, *, canonical: bool = True) -> Any:
    require_regular(path, label)
    raw = path.read_bytes()
    value = strict_json_bytes(raw, label)
    if canonical:
        require(
            raw == canonical_json_bytes(value) + b"\n",
            f"{label} is not canonical JSON plus LF",
        )
    return value


def exclusive_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def write_canonical_json(path: Path, value: Any) -> str:
    raw = canonical_json_bytes(value) + b"\n"
    exclusive_write(path, raw)
    digest = sha256_bytes(raw)
    exclusive_write(
        path.with_suffix(path.suffix + ".sha256"),
        f"{digest}  {path.name}\n".encode("ascii"),
    )
    return digest


def verify_digest_sidecar(path: Path) -> str:
    digest = sha256_file(path)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    status = require_regular(sidecar, f"{path.name} digest sidecar")
    require(status.st_size < 1024, f"{path.name} digest sidecar is oversized")
    require(
        sidecar.read_bytes() == f"{digest}  {path.name}\n".encode("ascii"),
        f"{path.name} digest sidecar differs",
    )
    return digest


def require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    observed = set(value)
    require(
        observed == keys,
        f"{label} keys differ: missing={sorted(keys-observed)}, extra={sorted(observed-keys)}",
    )
    return value


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{label} is not an integer >= {minimum}")
    return value


def require_number(value: Any, label: str) -> float:
    require(type(value) in {int, float}, f"{label} is not numeric")
    result = float(value)
    require(math.isfinite(result), f"{label} is not finite")
    return result


def require_digest(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{label} is not a digest")
    return value


def command_output(arguments: list[str], cwd: Path) -> str:
    process = subprocess.run(
        arguments,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    require(process.returncode == 0, f"command failed: {' '.join(arguments)}: {process.stderr.strip()}")
    return process.stdout.strip()


def validate_codec_root(codec_root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(codec_root))
    require(root == root.resolve(), "codec root may not traverse a symlink")
    require(command_output(["git", "rev-parse", "HEAD"], root) == EXPECTED_CODEC_COMMIT, "codec commit differs")
    require(command_output(["git", "rev-parse", "HEAD^{tree}"], root) == EXPECTED_CODEC_TREE, "codec tree differs")
    require(
        command_output(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
            ],
            root,
        )
        == "",
        "codec checkout contains tracked, untracked, or ignored bytes",
    )
    require(command_output(["git", "rev-parse", "--is-shallow-repository"], root) == "false", "codec checkout is shallow")
    require(not (root / ".git/shallow").exists(), "codec checkout contains shallow metadata")
    require(not (root / ".git/info/grafts").exists(), "codec checkout contains grafts")
    replace = command_output(["git", "for-each-ref", "--format=%(refname)", "refs/replace"], root)
    require(replace == "", "codec checkout contains replace refs")
    files: dict[str, Any] = {}
    for relative, expected in EXPECTED_CODEC_FILES.items():
        path = root / relative
        status = require_regular(path, f"codec source {relative}")
        observed = sha256_file(path)
        require(observed == expected, f"codec source digest differs: {relative}")
        files[relative] = {"bytes": status.st_size, "sha256": observed}
    return {
        "commit": EXPECTED_CODEC_COMMIT,
        "tree": EXPECTED_CODEC_TREE,
        "files": files,
    }


def load_profiles() -> dict[str, Any]:
    value = strict_json_file(PROFILES_PATH, "model profiles")
    require_exact_keys(
        value,
        {
            "classification",
            "executionPolicy",
            "profiles",
            "schemaVersion",
            "scientificEvidence",
        },
        "model profiles",
    )
    require(value["schemaVersion"] == PROFILE_SCHEMA_VERSION, "model profile schema differs")
    require(value["classification"] == CLASSIFICATION, "model profile classification differs")
    require(value["scientificEvidence"] is False, "model profiles may not be scientific evidence")
    require(
        value["executionPolicy"]
        == {
            "acceptedAsBenchmarkEvidence": False,
            "allowNetworkDuringModelExecution": False,
            "assetVerificationRequired": True,
            "countsTowardScientificVerdict": False,
            "deviceClass": "single-NVIDIA-CUDA-GPU-min-78GB",
            "executionOrder": "sequential-one-profile-per-process",
            "inheritsQwenThresholds": False,
            "modelCode": "transformers-built-in-only",
            "registeredEvidence": False,
            "remoteCodeAllowed": False,
        },
        "model execution policy differs",
    )
    profiles = value.get("profiles")
    require(isinstance(profiles, list), "profiles must be an array")
    require([profile.get("modelId") for profile in profiles] == list(MODEL_ORDER), "model order differs")
    require([profile.get("adapterId") for profile in profiles] == list(ADAPTER_ORDER), "adapter order differs")
    for index, profile in enumerate(profiles):
        require(isinstance(profile, dict), f"profile[{index}] must be an object")
        expected_profile_keys = {
            "adapterId",
            "architecture",
            "cachePolicy",
            "files",
            "gated",
            "gating",
            "geometry",
            "license",
            "maxPrefillTokens",
            "modelId",
            "modelType",
            "profileId",
            "repository",
            "requiredAssets",
            "revision",
            "gpuAdmission",
            "status",
            "trustRemoteCode",
            "weights",
        }
        if profile.get("modelId") == "opt-125m":
            expected_profile_keys.add("weightConversion")
        require_exact_keys(profile, expected_profile_keys, f"profile[{index}]")
        require(profile["trustRemoteCode"] is False, "remote model code is forbidden")
        require(profile["requiredAssets"] == profile["files"], "required asset aliases differ")
        require_digest(profile.get("revision"), f"profile[{index}].revision", HEX40)
        require(isinstance(profile.get("repository"), str) and "/" in profile["repository"], "profile repository is invalid")
        geometry = profile.get("geometry")
        require(isinstance(geometry, dict), "profile geometry is absent")
        require(
            profile["architecture"] == geometry.get("architecture")
            and profile["modelType"] == geometry.get("modelType"),
            "profile architecture aliases differ",
        )
        layers = require_int(geometry.get("layers"), "layers", 1)
        heads = require_int(geometry.get("attentionHeads"), "attentionHeads", 1)
        kv_heads = require_int(geometry.get("kvHeads"), "kvHeads", 1)
        head_dimension = require_int(geometry.get("headDimension"), "headDimension", 1)
        hidden = require_int(geometry.get("hiddenSize"), "hiddenSize", 1)
        context = require_int(geometry.get("contextTokens"), "contextTokens", HORIZON + 2)
        require(hidden == heads * head_dimension, "profile hidden geometry is inconsistent")
        require(heads % kv_heads == 0, "profile grouped-query geometry is inconsistent")
        columns = 2 * kv_heads * head_dimension
        require(columns % 128 == 0, "profile cache width is not codec aligned")
        expected_limit = min(context - HORIZON - 1, MAX_MATRIX_ELEMENTS // columns)
        require(profile.get("maxPrefillTokens") == expected_limit, "profile max prefill does not bind codec/context limits")
        cache_policy = profile.get("cachePolicy")
        if profile["modelId"] == "mistral-7b-v0.1":
            require(
                cache_policy
                == {
                    "kind": "sliding-window-dynamic-cache",
                    "slidingWindowEnabled": True,
                    "slidingWindowTokens": 4096,
                    "workloadMustFitWithoutEviction": True,
                },
                "Mistral sliding-window policy differs",
            )
            require(expected_limit < 4096, "Mistral workload must remain below its sliding window")
        else:
            require(
                cache_policy
                == {
                    "kind": "full-context-dynamic-cache",
                    "slidingWindowEnabled": False,
                },
                "full-context cache policy differs",
            )
        if profile["modelId"] == "gemma-2b":
            require(profile["gated"] is True, "Gemma must remain gated")
            require(
                profile["gating"]
                == {
                    "credentialHandling": "environment-only-never-recorded",
                    "requiresAuthentication": True,
                    "requiresOperatorAcceptance": True,
                    "tokenValueStored": False,
                    "type": "manual-license-acceptance",
                },
                "Gemma gate policy differs",
            )
        else:
            require(profile["gated"] is False, "only Gemma may be gated")
            require(
                profile["gating"]
                == {"requiresAuthentication": False, "type": "none"},
                "public model gating policy differs",
            )
        budget = profile.get("gpuAdmission")
        require_exact_keys(
            budget,
            {
                "executionTimeoutSeconds",
                "maxGpuMemoryBytes",
                "maxInputTokens",
                "hardLimit",
            },
            "profile planning budget",
        )
        require(budget["hardLimit"] is True, "profile GPU budget must remain a hard admission limit")
        require_int(budget["executionTimeoutSeconds"], "profile timeout", 1)
        require_int(budget["maxGpuMemoryBytes"], "profile memory cap", 1)
        expected_input_cap = 4096 if profile["modelId"] == "mistral-7b-v0.1" else context
        require(budget["maxInputTokens"] == expected_input_cap, "profile input-token cap differs")
        require(profile["weights"].get("useSafetensors") is True, "unsafe model weight loading is forbidden")
        assets = profile.get("files")
        require(isinstance(assets, list) and assets, "profile assets are absent")
        paths: set[str] = set()
        for asset in assets:
            require(isinstance(asset, dict), "asset entry must be an object")
            relative = asset.get("path")
            require(isinstance(relative, str) and relative and not relative.startswith("/") and ".." not in Path(relative).parts, "unsafe asset path")
            require(relative not in paths, "duplicate asset path")
            paths.add(relative)
            require_int(asset.get("bytes"), "asset bytes", 1)
            asset_sha256 = asset.get("sha256")
            if asset_sha256 is None:
                require(profile.get("gated") is True, "only a gated profile may defer an asset SHA-256")
                require(asset.get("storage") == "git", "only a small Git blob may defer SHA-256")
                require_digest(asset.get("hfGitOidSha1"), "asset Git blob OID", HEX40)
                require(asset.get("sha256Availability") == "requires-authorized-materialization", "deferred SHA-256 reason differs")
            else:
                require_digest(asset_sha256, "asset sha256")
        require(any(path.endswith((".safetensors", ".bin")) for path in paths), "profile has no weights")
    return value


def profile_by_id(model_id: str) -> dict[str, Any]:
    profiles = load_profiles()["profiles"]
    matches = [profile for profile in profiles if profile["modelId"] == model_id]
    require(len(matches) == 1, f"unknown or duplicate model profile: {model_id}")
    return matches[0]


def verify_asset_receipt(path: Path, cache_root: Path) -> tuple[dict[str, Any], str]:
    """Bind every current asset byte, including derived OPT weights, to a receipt."""

    profiles = load_profiles()["profiles"]
    receipt = strict_json_file(path, "asset verification receipt")
    require_exact_keys(
        receipt,
        {"schemaVersion", "status", "modelOrder", "profilesSHA256", "profiles"},
        "asset verification receipt",
    )
    require(receipt["schemaVersion"] == ASSET_SCHEMA_VERSION, "asset receipt schema differs")
    require(receipt["status"] == "ASSETS_VERIFIED", "asset receipt status differs")
    require(receipt["modelOrder"] == list(MODEL_ORDER), "asset receipt model order differs")
    require(receipt["profilesSHA256"] == sha256_file(PROFILES_PATH), "asset receipt profile digest differs")
    entries = receipt["profiles"]
    require(isinstance(entries, list) and len(entries) == len(profiles), "asset receipt profile count differs")
    cache = Path(os.path.abspath(cache_root))
    require(cache.is_dir() and cache == cache.resolve(), "asset cache is unsafe")
    cache_status = cache.stat()
    require(cache_status.st_uid == os.getuid(), "asset cache is not owner controlled")
    require(cache_status.st_mode & 0o077 == 0, "asset cache is not private")
    for profile, entry in zip(profiles, entries):
        require_exact_keys(
            entry,
            {"modelId", "repository", "revision", "files", "convertedWeights"},
            f"asset receipt profile {profile['modelId']}",
        )
        require(
            (entry["modelId"], entry["repository"], entry["revision"])
            == (profile["modelId"], profile["repository"], profile["revision"]),
            f"asset receipt identity differs: {profile['modelId']}",
        )
        snapshot = cache / profile["modelId"]
        require(
            snapshot.parent == cache
            and snapshot.is_dir()
            and not snapshot.is_symlink()
            and snapshot == snapshot.resolve(),
            "asset snapshot is unsafe",
        )
        snapshot_status = snapshot.stat()
        require(snapshot_status.st_uid == os.getuid(), "asset snapshot is not owner controlled")
        require(snapshot_status.st_mode & 0o077 == 0, "asset snapshot is not private")
        file_entries = entry["files"]
        require(isinstance(file_entries, list) and len(file_entries) == len(profile["files"]), "asset receipt file count differs")
        expected_paths: set[str] = set()
        for asset, recorded in zip(profile["files"], file_entries):
            require_exact_keys(recorded, {"path", "bytes", "sha256"}, "asset receipt file")
            relative = asset["path"]
            expected_paths.add(relative)
            current = snapshot / relative
            status = require_regular(current, f"asset {profile['modelId']}/{relative}")
            require(
                recorded["path"] == relative
                and recorded["bytes"] == status.st_size == int(asset["bytes"])
                and recorded["sha256"] == sha256_file(current),
                f"asset receipt binding differs: {profile['modelId']}/{relative}",
            )
            require_digest(recorded["sha256"], "recorded asset SHA-256")
        converted = entry["convertedWeights"]
        if profile.get("weightConversion") is None:
            require(converted is None, "unexpected converted weights in asset receipt")
        else:
            require_exact_keys(
                converted,
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
                "converted weight receipt",
            )
            require(converted["conversion"] == profile["weightConversion"], "converted weight contract differs")
            require(converted["path"] == "model.safetensors", "converted weight path differs")
            require(converted["sourcePath"] == "pytorch_model.bin", "converted weight source path differs")
            require(converted["sourceTensorEqualityVerified"] is True, "converted tensor equality was not verified")
            converted_path = snapshot / "model.safetensors"
            source_path = snapshot / "pytorch_model.bin"
            converted_status = require_regular(converted_path, "converted OPT safetensors")
            require(
                converted["bytes"] == converted_status.st_size
                and converted["sha256"] == sha256_file(converted_path),
                "converted OPT safetensors receipt binding differs",
            )
            require(
                converted["sourceSha256"] == sha256_file(source_path),
                "converted OPT source receipt binding differs",
            )
            require_digest(converted["sha256"], "converted weight SHA-256")
            require_digest(converted["sourceSha256"], "converted weight source SHA-256")
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
                "converted OPT environment receipt differs",
            )
            expected_paths.add("model.safetensors")
        actual_paths: set[str] = set()
        for candidate in snapshot.rglob("*"):
            candidate_status = candidate.lstat()
            require(not stat.S_ISLNK(candidate_status.st_mode), "asset snapshot contains a symlink")
            require(candidate_status.st_uid == os.getuid(), "asset snapshot contains a foreign-owned path")
            if stat.S_ISDIR(candidate_status.st_mode):
                require(candidate_status.st_mode & 0o077 == 0, "asset directory is not private")
            elif stat.S_ISREG(candidate_status.st_mode):
                require(candidate_status.st_nlink == 1, "asset snapshot contains a hard-linked file")
                require(candidate_status.st_mode & 0o022 == 0, "asset file is group/world writable")
                actual_paths.add(candidate.relative_to(snapshot).as_posix())
            else:
                fail("asset snapshot contains a special file")
        require(actual_paths == expected_paths, f"asset snapshot contains missing or extra files: {profile['modelId']}")
    return receipt, verify_digest_sidecar(path)


def load_workloads() -> dict[str, Any]:
    value = strict_json_file(WORKLOADS_PATH, "workloads", canonical=False)
    require_exact_keys(
        value,
        {
            "adapterTargets",
            "classification",
            "concatenation",
            "horizonTokens",
            "schemaVersion",
            "scientificEvidence",
            "selection",
            "sourceBinding",
            "targetSemantics",
            "workloads",
        },
        "workloads",
    )
    require(value["schemaVersion"] == WORKLOAD_SCHEMA_VERSION, "workload schema differs")
    require(value["classification"] == CLASSIFICATION, "workload classification differs")
    require(value["scientificEvidence"] is False, "workloads may not be scientific evidence")
    require(value["horizonTokens"] == HORIZON, "workload horizon differs")
    require(
        value["targetSemantics"]
        == "maximum-codec-bounded-prefill-plus-greedy-horizon-v1",
        "workload target semantics differ",
    )
    require(
        value["selection"]
        == {
            "addSpecialTokens": False,
            "generationTokens": HORIZON,
            "prefillTokens": "maxCompressedPrefillTokens",
            "promptFinalInputTokens": 1,
            "selectedTokenRange": "first-maxCompressedPrefillTokens-plus-one",
            "truncation": False,
        },
        "workload token selection differs",
    )
    require(
        value["sourceBinding"]
        == {
            "allowWorkingTreeBytes": False,
            "requireCleanCheckout": True,
            "revision": "HEAD",
            "trackedBlobSource": "git-object-database",
            "tree": "HEAD^{tree}",
        },
        "workload source binding differs",
    )
    expected_targets = [
        {
            "adapterId": adapter_id,
            "cachePolicy": cache_policy,
            "contextTargetTokens": context_tokens,
            "maxCompressedPrefillTokens": prefill_tokens,
        }
        for adapter_id, context_tokens, prefill_tokens, cache_policy in (
            ("gemma-dynamic-cache-v1", 8192, 4096, "full-context"),
            ("gpt-neox-dynamic-cache-v1", 2048, 2015, "full-context"),
            ("gpt2-dynamic-cache-v1", 1024, 991, "full-context"),
            ("llama-dynamic-cache-v1", 8192, 5461, "full-context"),
            ("mistral-dynamic-cache-v1", 4096, 1024, "sliding-window-effective"),
            ("opt-dynamic-cache-v1", 2048, 1365, "full-context"),
            ("qwen2-dynamic-cache-v1", 32768, 8192, "full-context"),
        )
    ]
    require(value["adapterTargets"] == expected_targets, "workload adapter targets differ")
    workloads = value.get("workloads")
    require(isinstance(workloads, list) and len(workloads) == 4, "exactly four workloads are required")
    concatenation = value.get("concatenation")
    require(isinstance(concatenation, dict), "workload concatenation contract is absent")
    require(concatenation.get("algorithm") == "corelm-tracked-utf8-file-frames-v1", "workload concatenation algorithm differs")
    require(concatenation.get("contentBytes") == "exact-git-head-blob", "workload bytes are not Git-object bound")
    require(
        concatenation
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
    require(
        [entry.get("workloadId") for entry in workloads]
        == [
            "tracked-legal-protocol-v1",
            "tracked-source-code-v1",
            "tracked-structured-json-v1",
            "tracked-technical-prose-v1",
        ],
        "workload order differs",
    )
    identifiers: set[str] = set()
    for workload in workloads:
        require(isinstance(workload, dict), "workload must be an object")
        identifier = workload.get("workloadId")
        require(isinstance(identifier, str) and SAFE_ID.fullmatch(identifier) is not None, "unsafe workload ID")
        require(identifier not in identifiers, "duplicate workload ID")
        identifiers.add(identifier)
        require(isinstance(workload.get("contentClass"), str) and workload["contentClass"], "workload content class is empty")
        require(isinstance(workload.get("instruction"), str) and workload["instruction"].strip(), "workload instruction is empty")
        files = workload.get("paths")
        require(isinstance(files, list) and files, "workload sources are absent")
        require(len(files) == len(set(files)), "workload sources contain duplicates")
        require(files == sorted(files, key=lambda item: item.encode("utf-8")), "workload sources are not bytewise sorted")
        for relative in files:
            require(isinstance(relative, str) and relative and not relative.startswith("/"), "unsafe workload source")
            path = LAB_ROOT / relative
            require(path.resolve() == path.absolute(), "workload source traverses a symlink")
            require_regular(path, f"workload source {relative}")
    return value


def workload_text(workload: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    contract = load_workloads()["concatenation"]
    chunks: list[str] = [
        str(contract["instructionBeginFrame"]),
        workload["instruction"],
        str(contract["instructionEndFrame"]),
    ]
    inventory: list[dict[str, Any]] = []
    tracked_bytes = 0
    for relative in workload["paths"]:
        metadata_process = subprocess.run(
            ["git", "ls-tree", "-z", "HEAD", "--", relative],
            cwd=LAB_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        require(
            metadata_process.returncode == 0
            and metadata_process.stdout.endswith(b"\0")
            and metadata_process.stdout.count(b"\0") == 1,
            f"cannot resolve one tracked workload blob: {relative}",
        )
        try:
            header, recorded_path = metadata_process.stdout[:-1].split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            tree_path = recorded_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            fail(f"invalid tracked workload metadata for {relative}: {error}")
        require(
            mode in {"100644", "100755"}
            and object_type == "blob"
            and HEX40.fullmatch(object_id) is not None
            and tree_path == relative,
            f"workload source is not one exact regular Git blob: {relative}",
        )
        process = subprocess.run(
            ["git", "show", f"HEAD:{relative}"],
            cwd=LAB_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        require(process.returncode == 0, f"cannot read tracked workload blob: {relative}")
        raw = process.stdout
        require(b"\0" not in raw, f"workload source contains NUL: {relative}")
        text = raw.decode("utf-8", errors="strict")
        begin = str(contract["beginFrame"]).format(path=relative)
        end = str(contract["endFrame"]).format(path=relative)
        chunks.extend((begin, text, end))
        tracked_bytes += len(raw)
        inventory.append(
            {
                "path": relative,
                "gitMode": mode,
                "gitBlobSHA1": object_id,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            }
        )
    require(
        tracked_bytes >= int(workload["minimumTrackedUtf8Bytes"]),
        f"workload {workload['workloadId']} is shorter than its registered byte floor",
    )
    return "".join(chunks), inventory


def bits_schedule(layers: int) -> list[int]:
    """Project the frozen 24-layer schedule by normalized layer position.

    The original schedule uses 9 bits at normalized positions 0 and 1/3 and
    8 bits elsewhere.  This projection is fixed before inference and is not a
    claim that the Qwen verdict transfers to another architecture.
    """

    require(type(layers) is int and layers > 0, "layer count must be positive")
    high = {0, min(layers - 1, layers // 3)}
    return [9 if index in high else 8 for index in range(layers)]


def configuration_for_profile(profile: dict[str, Any]) -> dict[str, Any]:
    layers = int(profile["geometry"]["layers"])
    return {
        "backend": "voidtoken-v5",
        "bitsByLayer": bits_schedule(layers),
        "codeCompression": "zlib-9",
        "groupSize": 128,
        "scaleCompression": "zlib-9",
        "schedule": "normalized-layer-0-and-one-third-9bit-rest-8bit-v1",
        "signMode": "none",
        "transformBlockSize": 128,
    }


def configuration_sha256(profile: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(configuration_for_profile(profile)))
