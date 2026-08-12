#!/usr/bin/env python3
"""Model-free parser/publication tests for build_recorded_run.py."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("recorded_run_builder", HERE / "build_recorded_run.py")
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILDER
SPEC.loader.exec_module(BUILDER)
_WORKLOAD_BINDING_CACHE: dict[str, dict[str, dict[str, Any]]] = {}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPOSITORY), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


class ExportFixture:
    def __init__(self, root: Path, *, extra_directory: bool = False) -> None:
        self.root = root
        self.export_dir = root / "export"
        self.export_dir.mkdir(mode=0o700)
        self.metadata_path = root / "operator-metadata.json"
        self.output = root / "2026-08-12-attempt-02"
        profiles_raw = (REPOSITORY / "runpod-adapter-sweep-v1/profiles.json").read_bytes()
        workloads_raw = (REPOSITORY / "runpod-adapter-sweep-v1/workloads.json").read_bytes()
        protocol_raw = (REPOSITORY / "runpod-adapter-sweep-v1/PROTOCOL.md").read_bytes()
        profiles_doc = json.loads(profiles_raw)
        workloads_doc = json.loads(workloads_raw)
        profiles = profiles_doc["profiles"]
        workloads = workloads_doc["workloads"]
        model_order = [entry["modelId"] for entry in profiles]
        workload_order = [entry["workloadId"] for entry in workloads]
        commit = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        source = {"commit": commit, "tree": tree, "branch": "HEAD"}
        if commit not in _WORKLOAD_BINDING_CACHE:
            _WORKLOAD_BINDING_CACHE[commit] = {
                workload["workloadId"]: BUILDER._reconstruct_workload_binding(
                    REPOSITORY,
                    commit,
                    workloads_doc,
                    workload,
                )
                for workload in workloads
            }
        workload_bindings = _WORKLOAD_BINDING_CACHE[commit]
        codec = {
            "commit": BUILDER.EXPECTED_CODEC_COMMIT,
            "tree": BUILDER.EXPECTED_CODEC_TREE,
            "files": {
                relative: {"bytes": index + 1, "sha256": sha256}
                for index, (relative, sha256) in enumerate(
                    BUILDER.EXPECTED_CODEC_FILES.items()
                )
            },
        }
        codec_requirements_sha = BUILDER.EXPECTED_CODEC_FILES["RealLLM/requirements.lock"]
        pip_bootstrap_sha = BUILDER.EXPECTED_CODEC_FILES[".github/locks/pip-bootstrap.txt"]
        portable_runtime_sha = BUILDER.EXPECTED_CODEC_FILES[
            ".github/locks/real-llm-linux-cpu-py312.txt"
        ]
        cuda_runtime_sha = digest(
            (REPOSITORY / "runpod-adapter-sweep-v1/torch-linux-cu130-py312.txt").read_bytes()
        )
        files: dict[str, bytes] = {}

        def add_json(relative: str, value: Any) -> str:
            raw = canonical(value)
            path = f"evidence/{relative}"
            files[path] = raw
            observed = digest(raw)
            files[path + ".sha256"] = f"{observed}  {Path(relative).name}\n".encode("ascii")
            return observed

        opt_profile = next(profile for profile in profiles if profile["modelId"] == "opt-125m")
        opt_source_asset = next(
            asset for asset in opt_profile["files"] if asset["path"] == "pytorch_model.bin"
        )
        converted = {
            "bytes": 1,
            "conversion": "torch-weights-only-to-safetensors-v1",
            "environment": {
                "boundary": "application-offline-single-purpose-process",
                "credentialNamesPresent": [],
                "hfHubOffline": True,
                "implicitTokenDisabled": True,
                "pythonFlags": ["-E", "-s", "-B"],
                "transformersOffline": True,
            },
            "path": "model.safetensors",
            "sha256": "b" * 64,
            "sourcePath": "pytorch_model.bin",
            "sourceSha256": opt_source_asset["sha256"],
            "sourceTensorEqualityVerified": True,
        }
        raw_profile_receipts = [
            {
                "modelId": profile["modelId"],
                "repository": profile["repository"],
                "revision": profile["revision"],
                "files": [
                    {
                        "path": asset["path"],
                        "bytes": asset["bytes"],
                        "sha256": asset.get("sha256") or "d" * 64,
                    }
                    for asset in profile["files"]
                ],
                "convertedWeights": None,
            }
            for profile in profiles
        ]
        raw_assets = {
            "schemaVersion": "corelm-runpod-adapter-assets-v1",
            "status": "RAW_ASSETS_VERIFIED",
            "modelOrder": model_order,
            "profilesSHA256": digest(profiles_raw),
            "profiles": raw_profile_receipts,
        }
        add_json("assets-download.json", raw_assets)
        conversion = {
            "schemaVersion": "corelm-runpod-opt-conversion-v1",
            "status": "OPT_CONVERSION_COMPLETE",
            "profileId": next(profile for profile in profiles if profile["modelId"] == "opt-125m")["profileId"],
            "profilesSHA256": digest(profiles_raw),
            "convertedWeights": converted,
        }
        add_json("opt-conversion.json", conversion)
        verified_profile_receipts = json.loads(json.dumps(raw_profile_receipts))
        next(entry for entry in verified_profile_receipts if entry["modelId"] == "opt-125m")["convertedWeights"] = converted
        assets = {
            **raw_assets,
            "status": "ASSETS_VERIFIED",
            "profiles": verified_profile_receipts,
        }
        asset_digest = add_json("assets-verify.json", assets)
        preflight_cells: list[dict[str, Any]] = []
        for profile in profiles:
            for workload in workloads:
                binding = workload_bindings[workload["workloadId"]]
                preflight_cells.append(
                    {
                        "modelId": profile["modelId"],
                        "workloadId": workload["workloadId"],
                        "category": binding["category"],
                        "promptUTF8SHA256": binding["promptUTF8SHA256"],
                        "framedUTF8Bytes": binding["framedUTF8Bytes"],
                        "availableTokens": profile["maxPrefillTokens"] + 100,
                        "selectedTokens": profile["maxPrefillTokens"] + 1,
                        "prefillTokens": profile["maxPrefillTokens"],
                        "tokenIdsU32LESHA256": "2" * 64,
                        "sourceFiles": binding["sourceFiles"],
                    }
                )
        preflight = {
            "schemaVersion": "corelm-runpod-adapter-preflight-v1",
            "status": "TOKENIZER_ONLY_NO_MODEL_INFERENCE",
            "countsTowardScientificVerdict": False,
            "source": source,
            "codecSource": codec,
            "assetReceiptSHA256": asset_digest,
            "profilesSHA256": digest(profiles_raw),
            "workloadsSHA256": digest(workloads_raw),
            "protocolSHA256": digest(protocol_raw),
            "modelOrder": model_order,
            "workloadOrder": workload_order,
            "horizon": 32,
            "cells": preflight_cells,
        }
        preflight_digest = add_json("preflight.json", preflight)
        run_id = "00000000-0000-4000-8000-000000000001"
        rows: list[dict[str, Any]] = []
        result_digests: dict[tuple[str, str], str] = {}
        total_containers = 0
        total_container_bytes = 0
        for position, (profile, workload) in enumerate(
            (profile, workload) for profile in profiles for workload in workloads
        ):
            model_id = profile["modelId"]
            workload_id = workload["workloadId"]
            prefix = f"run/cells/{model_id}/{workload_id}"
            attempt = {
                "schemaVersion": "corelm-runpod-adapter-cell-attempt-v1",
                "status": "STARTED",
                "classification": BUILDER.CLASSIFICATION,
                "countsTowardScientificVerdict": False,
                "attemptId": f"00000000-0000-4000-8000-{position + 1:012d}",
                "runId": run_id,
                "startedAt": "2026-08-12T10:00:00Z",
                "modelId": model_id,
                "adapterId": profile["adapterId"],
                "workloadId": workload_id,
                "timeoutLimitSeconds": profile["gpuAdmission"]["executionTimeoutSeconds"],
                "source": source,
                "codecSource": codec,
                "preflightSHA256": preflight_digest,
                "assetReceiptSHA256": asset_digest,
                "profilesSHA256": digest(profiles_raw),
                "workloadsSHA256": digest(workloads_raw),
                "protocolSHA256": digest(protocol_raw),
            }
            add_json(f"{prefix}/attempt.json", attempt)
            layers = profile["geometry"]["layers"]
            prefill = profile["maxPrefillTokens"]
            kv_heads = profile["geometry"]["kvHeads"]
            head_dimension = profile["geometry"]["headDimension"]
            dense = prefill * 2 * kv_heads * head_dimension * layers * 2
            container_entries: list[dict[str, Any]] = []
            cell_container_bytes = 0
            for layer in range(layers):
                payload = f"fixture:{model_id}:{workload_id}:{layer}".encode("utf-8")
                raw = b"header00" + payload
                path = f"evidence/{prefix}/containers/layer-{layer:03d}.vtl5"
                files[path] = raw
                cell_container_bytes += len(raw)
                container_entries.append(
                    {
                        "layerIndex": layer,
                        "bits": BUILDER.codec_configuration(profile)["bitsByLayer"][layer],
                        "rows": prefill,
                        "columns": 2 * kv_heads * head_dimension,
                        "denseBF16Bytes": dense // layers,
                        "containerBytes": len(raw),
                        "payloadBytes": len(payload),
                        "containerSHA256": digest(raw),
                        "payloadSHA256": digest(payload),
                        "path": f"containers/layer-{layer:03d}.vtl5",
                    }
                )
            total_containers += layers
            total_container_bytes += cell_container_bytes
            tokens = [1] * 32
            zeros = [0.0] * 32
            behavior = {
                "predictionTokens": 32,
                "controlledTop1AgreementCount": 32,
                "controlledTop1Agreement": 1.0,
                "meanKLDivergenceNat": 0.0,
                "meanBaselineSelectedTokenSurprisalDeltaNat": 0.0,
                "maxAbsLogitDifference": 0.0,
                "perTokenKLDivergenceNat": zeros,
                "perTokenBaselineSelectedTokenSurprisalDeltaNat": zeros,
                "perTokenMaxAbsLogitDifference": zeros,
                "baselineTokenIds": tokens,
                "controlledCandidateTop1TokenIds": tokens,
                "candidateFreeRunTokenIds": tokens,
                "freeRunExact": True,
                "freeRunSamePositionCount": 32,
                "freeRunLongestCommonPrefixTokens": 32,
                "baselineContinuation": "fixture",
                "candidateFreeRunContinuation": "fixture",
            }
            preflight_cell = preflight_cells[position]
            result = {
                "schemaVersion": "corelm-runpod-adapter-cell-v1",
                "status": "COMPLETE",
                "classification": BUILDER.CLASSIFICATION,
                "countsTowardScientificVerdict": False,
                "model": {
                    "modelId": model_id,
                    "adapterId": profile["adapterId"],
                    "repository": profile["repository"],
                    "revision": profile["revision"],
                    "geometry": profile["geometry"],
                    "assetRootName": model_id,
                },
                "workload": {key: value for key, value in preflight_cell.items() if key != "modelId"},
                "codecSource": codec,
                "assetReceiptSHA256": asset_digest,
                "canonicalCacheBF16SHA256": "3" * 64,
                "cacheObservation": {
                    "cacheClass": "transformers.cache_utils.DynamicCache",
                    "layerClass": (
                        "transformers.cache_utils.DynamicSlidingWindowLayer"
                        if model_id == "mistral-7b-v0.1"
                        else "transformers.cache_utils.DynamicLayer"
                    ),
                    "tensorLayout": "batch,kv_head,token,head_dimension",
                    "batchSize": 1,
                    "layers": layers,
                    "kvHeads": kv_heads,
                    "headDimension": head_dimension,
                    "dtype": "bfloat16",
                    "targetContextTokens": profile["gpuAdmission"]["maxInputTokens"],
                    "prefillTokens": prefill,
                    "finalPromptTokens": 1,
                    "continuationTokens": 32,
                    "effectiveCacheTokens": prefill,
                    "evictedTokens": 0,
                },
                "structuralReplay": {"maxAbsLogitDifference": 0.0, "top1Identical": True},
                "encoding": {
                    "configuration": BUILDER.codec_configuration(profile),
                    "configurationSHA256": digest(
                        json.dumps(
                            BUILDER.codec_configuration(profile),
                            ensure_ascii=False,
                            allow_nan=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ),
                    "denseBF16Bytes": dense,
                    "containerBytes": cell_container_bytes,
                    "payloadBytes": sum(entry["payloadBytes"] for entry in container_entries),
                    "compressionRatio": dense / cell_container_bytes,
                    "encodingNanoseconds": 1,
                    "containers": container_entries,
                },
                "behavior": behavior,
                "runtime": {
                    "startedAt": "2026-08-12T10:00:00Z",
                    "completedAt": "2026-08-12T10:01:00Z",
                    "python": "3.12.13",
                    "torch": "2.13.0+cu130",
                    "cuda": "13.0",
                    "deterministicAlgorithms": True,
                    "attentionImplementation": "eager",
                    "dtype": "bfloat16",
                    "gpuName": "NVIDIA A100-SXM4-80GB",
                    "gpuDriverVersion": "580.65.06",
                    "gpuTotalBytes": 80 * 1024**3,
                    "gpuFreeBytesBeforeCell": 70 * 1024**3,
                    "memoryEstimateBytes": sum(
                        int(asset["bytes"])
                        for asset in profile["files"]
                        if asset["path"].endswith((".safetensors", ".bin"))
                    ) + 6 * dense + 4 * 1024**3,
                    "peakAllocatedBytes": 1,
                    "peakReservedBytes": 1,
                    "peakRssBytes": 1,
                    "diskFreeBytesBeforeCell": 16 * 1024**3,
                    "diskRequiredBytes": 8 * 1024**3,
                    "modelRequirementsLockSHA256": codec_requirements_sha,
                    "pipBootstrapLockSHA256": pip_bootstrap_sha,
                    "portableRuntimeLockSHA256": portable_runtime_sha,
                    "cudaRuntimeLockSHA256": cuda_runtime_sha,
                    "packages": {
                        "huggingface-hub": "1.25.1",
                        "numpy": "2.5.1",
                        "safetensors": "0.8.0",
                        "tokenizers": "0.22.2",
                        "torch": "2.13.0+cu130",
                        "transformers": "5.14.1",
                    },
                    "cgroupMemoryCurrentBytesAtCompletion": 1,
                    "cgroupMemoryPeakBytesAtCompletion": 1,
                    "cgroupMemoryLimitBytes": 250 * 1024**3,
                },
            }
            result_digest = add_json(f"{prefix}/result.json", result)
            result_digests[(model_id, workload_id)] = result_digest
            stdout = b"fixture complete\n"
            # A successful child may legitimately produce an empty stderr log.
            stderr = b""
            files[f"evidence/run/logs/{model_id}--{workload_id}.stdout.log"] = stdout
            files[f"evidence/run/logs/{model_id}--{workload_id}.stderr.log"] = stderr
            rows.append(
                {
                    "modelId": model_id,
                    "workloadId": workload_id,
                    "startedAt": "2026-08-12T10:00:00Z",
                    "completedAt": "2026-08-12T10:01:00Z",
                    "returnCode": 0,
                    "exitSignal": None,
                    "timedOut": False,
                    "timeoutLimitSeconds": profile["gpuAdmission"]["executionTimeoutSeconds"],
                    "terminationReason": "completed",
                    "status": "COMPLETE",
                    "resultPath": f"cells/{model_id}/{workload_id}/result.json",
                    "resultSHA256": result_digest,
                    "stdoutSHA256": digest(stdout),
                    "stderrSHA256": digest(stderr),
                }
            )
        run = {
            "schemaVersion": "corelm-runpod-adapter-run-v1",
            "runId": run_id,
            "status": "COMPLETE",
            "classification": BUILDER.CLASSIFICATION,
            "countsTowardScientificVerdict": False,
            "source": source,
            "preflightSHA256": preflight_digest,
            "assetReceiptSHA256": asset_digest,
            "profilesSHA256": digest(profiles_raw),
            "workloadsSHA256": digest(workloads_raw),
            "protocolSHA256": digest(protocol_raw),
            "expectedCells": 28,
            "completeCells": 28,
            "cells": rows,
        }
        run_digest = add_json("run/run.json", run)
        structural = {
            "schemaVersion": "corelm-runpod-adapter-structural-verification-v1",
            "status": "STRUCTURALLY_VERIFIED",
            "classification": BUILDER.CLASSIFICATION,
            "countsTowardScientificVerdict": False,
            "modelReplayPerformed": False,
            "runId": run_id,
            "runSHA256": run_digest,
            "preflightSHA256": preflight_digest,
            "assetReceiptSHA256": asset_digest,
            "cells": 28,
            "containers": total_containers,
            "containerBytes": total_container_bytes,
        }
        structural_digest = add_json("structural-verification.json", structural)
        for model_id, workload_id in BUILDER.MODEL_REPLAYS.items():
            result_path = f"evidence/run/cells/{model_id}/{workload_id}/result.json"
            selected_result = json.loads(files[result_path])
            selected_behavior = selected_result["behavior"]
            replay = {
                "schemaVersion": "corelm-runpod-adapter-cell-replay-v1",
                "status": "MODEL_REPLAY_VERIFIED",
                "classification": BUILDER.CLASSIFICATION,
                "countsTowardScientificVerdict": False,
                "modelId": model_id,
                "workloadId": workload_id,
                "resultSHA256": result_digests[(model_id, workload_id)],
                "preflightSHA256": preflight_digest,
                "assetReceiptSHA256": asset_digest,
                "runSHA256": run_digest,
                "structuralVerificationSHA256": structural_digest,
                "predictionTokens": 32,
                "canonicalCacheBF16SHA256": selected_result["canonicalCacheBF16SHA256"],
                "structuralReplayExact": True,
                "controlledTop1Agreement": selected_behavior["controlledTop1Agreement"],
                "meanKLDivergenceNat": selected_behavior["meanKLDivergenceNat"],
                "meanBaselineSelectedTokenSurprisalDeltaNat": selected_behavior[
                    "meanBaselineSelectedTokenSurprisalDeltaNat"
                ],
                "baselineContinuationSHA256": digest(
                    selected_behavior["baselineContinuation"].encode("utf-8")
                ),
                "candidateContinuationSHA256": digest(
                    selected_behavior["candidateFreeRunContinuation"].encode("utf-8")
                ),
                "device": "cuda:0",
                "gpuName": "NVIDIA A100-SXM4-80GB",
                "gpuDriverVersion": "580.65.06",
                "peakAllocatedBytes": 1,
            }
            add_json(f"replays/{model_id}--{workload_id}.json", replay)
        allowed_sha = digest((REPOSITORY / "v4/signing/allowed_signers").read_bytes())
        source_lines = {
            "schemaVersion": "corelm-runpod-adapter-sweep-source-v1",
            "sweepCommit": commit,
            "sweepTree": tree,
            "commitSignatureTrustRootSHA256": allowed_sha,
            "sweepCommitSignatureVerified": "true",
            "codecCommit": codec["commit"],
            "codecTree": codec["tree"],
            "codecCommitSignatureVerified": "true",
            "classification": BUILDER.CLASSIFICATION,
            "scientificEvidence": "false",
            "countsTowardScientificVerdict": "false",
            "containerImageDigest": "sha256:" + "5" * 64,
            "containerImageDigestAuthority": "operator-supplied-control-plane-value",
            "gpuName": "NVIDIA A100-SXM4-80GB",
            "gpuMemoryMiB": "81920",
            "gpuDriverVersion": "580.65.06",
            "cgroupVersion": "v1",
            "cgroupCpuQuota": "2720000",
            "cgroupCpuPeriod": "100000",
            "cgroupMemoryMax": "268435456000",
            "codecRequirementsSHA256": codec_requirements_sha,
            "pipBootstrapLockSHA256": pip_bootstrap_sha,
            "portableRuntimeLockSHA256": portable_runtime_sha,
            "cudaTorchLockSHA256": cuda_runtime_sha,
        }
        files["evidence/source-identity.txt"] = "".join(
            f"{key}={value}\n" for key, value in source_lines.items()
        ).encode("utf-8")
        self._write_archive(files, extra_directory=extra_directory)
        archive_raw = (self.export_dir / BUILDER.ARCHIVE_NAME).read_bytes()
        archive_sha = digest(archive_raw)
        checksum = f"{archive_sha}  {BUILDER.ARCHIVE_NAME}\n".encode("ascii")
        (self.export_dir / BUILDER.CHECKSUM_NAME).write_bytes(checksum)
        os.chmod(self.export_dir / BUILDER.ARCHIVE_NAME, 0o600)
        os.chmod(self.export_dir / BUILDER.CHECKSUM_NAME, 0o600)
        metadata = {
            "schemaVersion": BUILDER.PUBLICATION_INPUT_SCHEMA,
            "recordedAt": "2026-08-12T12:00:00Z",
            "successfulAttemptNumber": 2,
            "attempts": [
                {
                    "attemptNumber": 1,
                    "status": "INCOMPLETE",
                    "sourceCommit": commit,
                    "sourceTree": tree,
                    "failureStage": "EXECUTABLE_CACHE_SMOKE",
                    "failureCode": "TRITON_NOEXEC_CACHE",
                    "forensics": {"bytes": 1, "manifestSHA256": "a" * 64},
                    "generatedRunRootDisposition": "REMOVED_AFTER_BOUNDED_FORENSICS",
                },
                {
                    "attemptNumber": 2,
                    "status": "COMPLETE",
                    "sourceCommit": commit,
                    "sourceTree": tree,
                    "failureStage": None,
                    "failureCode": None,
                    "forensics": None,
                    "generatedRunRootDisposition": "ARCHIVE_RETRIEVED_AND_VERIFIED",
                },
            ],
            "lifecycle": {
                "attestationBasis": BUILDER.LIFECYCLE_ATTESTATION_BASIS,
                "builderValidationScope": BUILDER.LIFECYCLE_VALIDATION_SCOPE,
                "platform": "RunPod Pod",
                "isolationBoundary": "PROVIDER_MANAGED_CONTAINER_NOT_INDEPENDENT_VM",
                "createdAt": "2026-08-12T09:00:00Z",
                "terminatedAt": "2026-08-12T11:00:00Z",
                "providerObservedCostUSD": 2.0,
                "providerObservedTimeBilledMs": 7_200_000,
                "providerObservedEffectiveHourlyRateUSD": 1.0,
                "costObservationBasis": "RUNPOD_BILLING_API_FINAL_SO_FAR_AFTER_POD_ABSENCE_BEFORE_KEY_REVOCATION",
                "currency": "USD",
                "admissionProjectedCombinedHourlyRateUSD": 1.0,
                "costCeilingUSD": 35.0,
                "providerTerminationFuseHours": 20,
                "providerVerified": False,
                "containerImageDigest": source_lines["containerImageDigest"],
                "podTerminated": True,
                "podVolumeDeleted": True,
                "networkVolumeUsed": False,
                "runpodSecretDeleted": True,
                "huggingFaceTokenRevoked": True,
                "lifecycleApiKeyRevoked": True,
                "sshCredentialRetired": True,
            },
            "operatorVerification": {
                "kind": "AUTHOR_SELF_VERIFICATION",
                "independentHumanReview": False,
                "independentReplication": False,
                "localArchiveChecksumVerified": True,
                "localArchiveInventoryVerified": True,
                "podStructuralVerifier": "SAME_POD_SAME_SOURCE_RUNTIME_CACHE",
                "modelReplayReceipts": 7,
                "archiveSHA256": archive_sha,
            },
        }
        self.metadata = metadata
        self.metadata_path.write_bytes(canonical(metadata))
        os.chmod(self.metadata_path, 0o600)

    def _write_archive(self, files: dict[str, bytes], *, extra_directory: bool) -> None:
        directories = {"evidence"}
        for path in files:
            parts = Path(path).parts
            for index in range(1, len(parts)):
                directories.add("/".join(parts[:index]))
        if extra_directory:
            directories.add("evidence/unregistered-empty-directory")
        archive_path = self.export_dir / BUILDER.ARCHIVE_NAME
        with archive_path.open("wb") as raw_handle:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=0) as gzip_handle:
                with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for directory in sorted(directories):
                        info = tarfile.TarInfo(directory)
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o700
                        info.uid = info.gid = info.mtime = 0
                        archive.addfile(info)
                    for path, raw in sorted(files.items()):
                        info = tarfile.TarInfo(path)
                        info.size = len(raw)
                        info.mode = 0o600
                        info.uid = info.gid = info.mtime = 0
                        archive.addfile(info, io.BytesIO(raw))


class RecordedRunBuilderTests(unittest.TestCase):
    @staticmethod
    def rewrite_export_json(
        fixture: ExportFixture,
        relative: str,
        mutation: Any,
    ) -> None:
        archive_path = fixture.export_dir / BUILDER.ARCHIVE_NAME
        files: dict[str, bytes] = {}
        directories: set[str] = set()
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    directories.add(member.name)
                    continue
                handle = archive.extractfile(member)
                assert handle is not None
                files[member.name] = handle.read()
        archive_relative = f"evidence/{relative}"
        value = json.loads(files[archive_relative])
        mutation(value)
        raw = canonical(value)
        files[archive_relative] = raw
        files[archive_relative + ".sha256"] = (
            f"{digest(raw)}  {Path(relative).name}\n".encode("ascii")
        )
        with archive_path.open("wb") as raw_handle:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=0) as gzip_handle:
                with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for directory in sorted(directories):
                        info = tarfile.TarInfo(directory)
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o700
                        info.uid = info.gid = info.mtime = 0
                        archive.addfile(info)
                    for path, content in sorted(files.items()):
                        info = tarfile.TarInfo(path)
                        info.size = len(content)
                        info.mode = 0o600
                        info.uid = info.gid = info.mtime = 0
                        archive.addfile(info, io.BytesIO(content))
        archive_sha = digest(archive_path.read_bytes())
        (fixture.export_dir / BUILDER.CHECKSUM_NAME).write_bytes(
            f"{archive_sha}  {BUILDER.ARCHIVE_NAME}\n".encode("ascii")
        )
        os.chmod(archive_path, 0o600)
        os.chmod(fixture.export_dir / BUILDER.CHECKSUM_NAME, 0o600)

    def test_build_verify_and_index_are_model_free_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            build_arguments = argparse.Namespace(
                repository=REPOSITORY,
                output=fixture.output,
                operator_metadata=fixture.metadata_path,
                export_dir=fixture.export_dir,
            )
            self.assertEqual(BUILDER.build(build_arguments), 0)
            verify_arguments = argparse.Namespace(
                repository=REPOSITORY,
                publication_dir=fixture.output,
                export_dir=fixture.export_dir,
            )
            self.assertEqual(BUILDER.verify(verify_arguments), 0)
            record = json.loads((fixture.output / "record.json").read_text(encoding="utf-8"))
            self.assertEqual(len(record["matrix"]["rows"]), 28)
            self.assertEqual(record["matrix"]["aggregationPolicy"], "NO_CROSS_CELL_OR_CROSS_MODEL_AVERAGES")
            self.assertFalse(record["causalLimitations"]["lengthEffectEstablished"])
            self.assertEqual(
                record["lifecycleClaimBoundary"]["attestationBasis"],
                BUILDER.LIFECYCLE_ATTESTATION_BASIS,
            )
            self.assertFalse(record["lifecycleClaimBoundary"]["providerVerified"])
            self.assertEqual(record["source"]["cgroupVersion"], "v1")
            self.assertEqual(
                record["verification"]["tokenizationVerificationScope"],
                BUILDER.TOKENIZATION_ASSERTION_SCOPE,
            )
            self.assertEqual(
                len(record["verification"]["representativeModelReplays"]), 7
            )
            self.assertEqual(
                record["causalLimitations"]["determinismRole"],
                "REPRODUCIBILITY_CONTROL_NOT_COMPRESSION_FACTOR",
            )
            runs_root = root / "runs"
            runs_root.mkdir(mode=0o755)
            fixture.output.rename(runs_root / fixture.output.name)
            self.assertEqual(
                BUILDER.update_index(argparse.Namespace(runs_root=runs_root)), 0
            )
            index = json.loads((runs_root / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(len(index["runs"]), 1)
            self.assertFalse(index["countsTowardScientificVerdict"])

    def test_archive_checksum_tamper_is_rejected_before_tar_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            archive = fixture.export_dir / BUILDER.ARCHIVE_NAME
            original_archive = archive.read_bytes()
            with archive.open("ab") as handle:
                handle.write(b"PRIVATE-TRAILER")
            with self.assertRaisesRegex(ValueError, "checksum differs"):
                BUILDER.read_export(fixture.export_dir)
            archive_sha = digest(archive.read_bytes())
            (fixture.export_dir / BUILDER.CHECKSUM_NAME).write_bytes(
                f"{archive_sha}  {BUILDER.ARCHIVE_NAME}\n".encode("ascii")
            )
            os.chmod(fixture.export_dir / BUILDER.CHECKSUM_NAME, 0o600)
            with self.assertRaisesRegex(ValueError, "trailing|second member"):
                BUILDER.read_export(fixture.export_dir)
            uncompressed = gzip.decompress(original_archive)
            with archive.open("wb") as raw_handle:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw_handle, mtime=0
                ) as gzip_handle:
                    gzip_handle.write(
                        uncompressed + b"PRIVATE-IN-GZIP-AFTER-TAR-EOF"
                    )
            archive_sha = digest(archive.read_bytes())
            (fixture.export_dir / BUILDER.CHECKSUM_NAME).write_bytes(
                f"{archive_sha}  {BUILDER.ARCHIVE_NAME}\n".encode("ascii")
            )
            os.chmod(archive, 0o600)
            os.chmod(fixture.export_dir / BUILDER.CHECKSUM_NAME, 0o600)
            with self.assertRaisesRegex(ValueError, "nonzero bytes after.*EOF"):
                BUILDER.read_export(fixture.export_dir)

    def test_extra_archive_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root, extra_directory=True)
            frozen = BUILDER.read_export(fixture.export_dir)
            with self.assertRaisesRegex(ValueError, "directories differ"):
                BUILDER._validate_archive_evidence(frozen, REPOSITORY)

    def test_cleanup_false_and_duplicate_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            frozen = BUILDER.read_export(fixture.export_dir)
            _, source, _, _, _ = BUILDER._validate_archive_evidence(frozen, REPOSITORY)
            profiles_doc, workloads_doc, local_documents = BUILDER.load_repository_inputs(
                REPOSITORY
            )
            raw_assets = BUILDER._json_document(frozen, "assets-download.json")
            verified_assets = BUILDER._json_document(frozen, "assets-verify.json")
            conversion = BUILDER._json_document(frozen, "opt-conversion.json")
            tampered_raw = json.loads(json.dumps(raw_assets))
            tampered_verified = json.loads(json.dumps(verified_assets))
            tampered_raw["profiles"][0]["files"][0]["bytes"] += 1
            tampered_verified["profiles"][0]["files"][0]["bytes"] += 1
            with self.assertRaisesRegex(ValueError, "registered asset byte count differs"):
                BUILDER._validate_asset_receipts(
                    tampered_raw,
                    tampered_verified,
                    conversion,
                    profiles_doc["profiles"],
                    digest(local_documents["profiles.json"]),
                )
            preflight = BUILDER._json_document(frozen, "preflight.json")
            empty_codec_manifest = json.loads(json.dumps(preflight["codecSource"]))
            empty_codec_manifest["files"] = {}
            with self.assertRaisesRegex(ValueError, "codec source file manifest keys differ"):
                BUILDER._validate_codec_source(
                    empty_codec_manifest,
                    source,
                    local_documents["torch-linux-cu130-py312.txt"],
                )
            profile = profiles_doc["profiles"][0]
            workload = workloads_doc["workloads"][0]
            binding = BUILDER._reconstruct_workload_binding(
                REPOSITORY,
                source["sweepCommit"],
                workloads_doc,
                workload,
            )
            tampered_cell = json.loads(json.dumps(preflight["cells"][0]))
            tampered_cell["sourceFiles"][0]["sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "locally reconstructed workload binding differs"):
                BUILDER._validate_preflight_cell(
                    tampered_cell,
                    profile,
                    workload,
                    binding,
                    "tampered preflight cell",
                )
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["lifecycle"]["podTerminated"] = False
            with self.assertRaisesRegex(ValueError, "operator lifecycle attestation"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["lifecycle"]["providerVerified"] = True
            with self.assertRaisesRegex(ValueError, "falsely claims provider verification"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["lifecycle"]["attestationBasis"] = "PROVIDER_VERIFIED"
            with self.assertRaisesRegex(ValueError, "attestation basis differs"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            for field, message in (
                ("providerObservedCostUSD", "cost must be positive"),
                (
                    "providerObservedEffectiveHourlyRateUSD",
                    "effective hourly rate must be positive",
                ),
                (
                    "admissionProjectedCombinedHourlyRateUSD",
                    "combined hourly rate must be positive",
                ),
            ):
                metadata = json.loads(json.dumps(fixture.metadata))
                metadata["lifecycle"][field] = 0.0
                with self.assertRaisesRegex(ValueError, message):
                    BUILDER.verify_publication_input(
                        metadata, source, frozen.archive_sha256
                    )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            BUILDER.strict_json(b'{"a":1,"a":2}\n', "duplicate", canonical=False)
        with self.assertRaisesRegex(ValueError, "non-finite"):
            BUILDER.strict_json(b'{"a":NaN}\n', "non-finite", canonical=False)

    def test_replay_exact_schema_and_result_binding_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            relative = "replays/qwen2.5-0.5b--tracked-legal-protocol-v1.json"
            self.rewrite_export_json(
                fixture,
                relative,
                lambda value: value.__setitem__("controlledTop1Agreement", 0.0),
            )
            frozen = BUILDER.read_export(fixture.export_dir)
            with self.assertRaisesRegex(ValueError, "replay behavior binding differs"):
                BUILDER._validate_archive_evidence(frozen, REPOSITORY)

    def test_result_geometry_and_codec_configuration_tamper_fail_closed(self) -> None:
        profiles = json.loads(
            (REPOSITORY / "runpod-adapter-sweep-v1/profiles.json").read_text(
                encoding="utf-8"
            )
        )["profiles"]
        profile = profiles[0]
        observation = {
            "cacheClass": "transformers.cache_utils.DynamicCache",
            "layerClass": "transformers.cache_utils.DynamicLayer",
            "tensorLayout": "batch,kv_head,token,head_dimension",
            "batchSize": 1,
            "layers": profile["geometry"]["layers"],
            "kvHeads": profile["geometry"]["kvHeads"],
            "headDimension": profile["geometry"]["headDimension"],
            "dtype": "bfloat16",
            "targetContextTokens": profile["gpuAdmission"]["maxInputTokens"],
            "prefillTokens": profile["maxPrefillTokens"],
            "finalPromptTokens": 1,
            "continuationTokens": 32,
            "effectiveCacheTokens": profile["maxPrefillTokens"],
            "evictedTokens": 0,
        }
        BUILDER._validate_cache_observation(observation, profile, "fixture cache")
        tampered = json.loads(json.dumps(observation))
        tampered["kvHeads"] += 1
        with self.assertRaisesRegex(ValueError, "kvHeads differs"):
            BUILDER._validate_cache_observation(tampered, profile, "fixture cache")
        expected = BUILDER.codec_configuration(profile)
        encoding = {
            "configuration": expected,
            "configurationSHA256": digest(BUILDER.canonical_json_bytes(expected)),
        }
        BUILDER._validate_codec_configuration(encoding, profile, "fixture configuration")
        tampered_configuration = json.loads(json.dumps(expected))
        tampered_configuration["groupSize"] = 64
        tampered_encoding = {
            **encoding,
            "configuration": tampered_configuration,
        }
        with self.assertRaisesRegex(ValueError, "fixture configuration differs"):
            BUILDER._validate_codec_configuration(
                tampered_encoding,
                profile,
                "fixture configuration",
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            self.rewrite_export_json(
                fixture,
                "replays/qwen2.5-0.5b--tracked-legal-protocol-v1.json",
                lambda value: value.__setitem__("extra", False),
            )
            frozen = BUILDER.read_export(fixture.export_dir)
            with self.assertRaisesRegex(ValueError, "replay receipt .* keys differ"):
                BUILDER._validate_archive_evidence(frozen, REPOSITORY)

    def test_failure_stage_and_private_free_text_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fixture = ExportFixture(root)
            frozen = BUILDER.read_export(fixture.export_dir)
            _, source, _, _, _ = BUILDER._validate_archive_evidence(frozen, REPOSITORY)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["attempts"][0]["failureStage"] = "model-cell"
            with self.assertRaisesRegex(ValueError, "failure stage differs"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["attempts"][0]["failureStage"] = "UNKNOWN_STAGE"
            metadata["attempts"][0]["failureCode"] = "UNKNOWN_CODE"
            with self.assertRaisesRegex(ValueError, "failure pair is not registered"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["attempts"][0]["failureStage"] = "RUNPOD_API_KEY"
            with self.assertRaisesRegex(ValueError, "private value"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata = json.loads(json.dumps(fixture.metadata))
            metadata["attempts"][0]["failureStage"] = "PRELAUNCH_CHECK"
            metadata["attempts"][0]["failureCode"] = (
                "OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR"
            )
            metadata["attempts"][0]["generatedRunRootDisposition"] = (
                "NO_RUN_ROOT_CREATED_BOUNDED_FORENSICS_RETAINED"
            )
            BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            metadata["attempts"][0]["generatedRunRootDisposition"] = (
                "REMOVED_AFTER_BOUNDED_FORENSICS"
            )
            with self.assertRaisesRegex(ValueError, "disposition differs"):
                BUILDER.verify_publication_input(metadata, source, frozen.archive_sha256)
            self.assertEqual(
                BUILDER.KNOWN_ATTEMPT_FAILURES,
                {
                    ("EXECUTABLE_CACHE_SMOKE", "TRITON_NOEXEC_CACHE"),
                    (
                        "SWEEP_ORCHESTRATE",
                        "DISTILGPT2_LEGACY_CAUSAL_MASK_INCOMPATIBILITY",
                    ),
                    (
                        "PRELAUNCH_CHECK",
                        "OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR",
                    ),
                },
            )
            for sentinel in (
                "/Users/example/private-file",
                "/private/example/private-file",
                "https://example.invalid/private-endpoint",
                "example.invalid:12345",
            ):
                self.assertIsNotNone(BUILDER.PRIVATE_VALUE.search(sentinel), sentinel)

    def test_git_source_trust_uses_fixed_binaries_and_clean_environment(self) -> None:
        source = Path(BUILDER.__file__).read_text(encoding="utf-8")
        self.assertIn('TRUSTED_GIT_PATH = Path("/usr/bin/git")', source)
        self.assertIn('TRUSTED_SSH_KEYGEN_PATH = Path("/usr/bin/ssh-keygen")', source)
        self.assertIn('"gpg.format=ssh"', source)
        self.assertIn('env=dict(TRUSTED_GIT_ENVIRONMENT)', source)
        self.assertNotIn('gpg.ssh.program=ssh-keygen', source)
        self.assertNotIn('["git", "-C"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
