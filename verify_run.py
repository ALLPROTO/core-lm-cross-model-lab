#!/usr/bin/env python3
"""Verify a completed Core LM cross-model regression artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any


LAB_ROOT = Path(__file__).resolve().parent
MODEL_MATRIX_PATH = LAB_ROOT / "models.json"
EXPECTED_COMMIT = "61afcf1a44007dec54bd1c56e3403bc74182a400"
EXPECTED_CONFIGURATION_SHA256 = (
    "4c7be8c836aa725722b51f66dce78af7a5094e887432e622b5322f7ca2cf0af8"
)
EXPECTED_SOURCE_SHA256 = {
    "RealLLM/beacon_registration.json": (
        "7c0cb4cf544773041be84e75de4314c72769c71682e1b138b99ea85996cc5779"
    ),
    "RealLLM/benchmark_real_llm.py": (
        "b5e7b301222501e148d54cda3f0d04997e6a061051cedc6393d1a87b638522d0"
    ),
    "RealLLM/codecs.py": (
        "fe5763b7cb0b2e775436c7414a1af48704095518e0428fe4a7965b84f0ce7a05"
    ),
    "RealLLM/requirements.lock": (
        "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561"
    ),
    "RealLLM/voidtoken_v5.py": (
        "80ed51aa2a201dbdaae36434709a50a8a679fa84d29b08ad7b083c14cec33758"
    ),
}
BLOCK_TOKENS = 512
PREFILL_TOKENS = 383
PREDICTIONS = 128
LAYERS = 24


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def same_float(left: Any, right: Any, label: str) -> None:
    require(
        isinstance(left, (int, float)) and isinstance(right, (int, float)),
        f"{label} is not numeric",
    )
    require(math.isfinite(float(left)) and math.isfinite(float(right)), label)
    require(
        math.isclose(float(left), float(right), rel_tol=1e-12, abs_tol=1e-12),
        f"{label} differs: {left} != {right}",
    )


def validate_source(result: dict[str, Any], codec_root: Path) -> Any:
    source = result.get("source")
    require(isinstance(source, dict), "source manifest is missing")
    require(source.get("commit") == EXPECTED_COMMIT, "source commit mismatch")
    lab_files = source.get("labFiles")
    require(isinstance(lab_files, dict), "lab source manifest is missing")
    for filename in ("models.json", "run_cross_model.py", "verify_run.py"):
        path = LAB_ROOT / filename
        entry = lab_files.get(filename)
        require(isinstance(entry, dict), f"lab source entry missing: {filename}")
        require(entry.get("bytes") == path.stat().st_size, f"lab source size: {filename}")
        require(entry.get("sha256") == sha256_file(path), f"lab source digest: {filename}")
    files = source.get("files")
    require(isinstance(files, dict), "source file manifest is missing")
    for relative, expected in EXPECTED_SOURCE_SHA256.items():
        path = codec_root / relative
        require(path.is_file(), f"missing source file: {relative}")
        observed = sha256_file(path)
        require(observed == expected, f"local source digest mismatch: {relative}")
        entry = files.get(relative)
        require(isinstance(entry, dict), f"source entry missing: {relative}")
        require(entry.get("sha256") == expected, f"source result mismatch: {relative}")
        require(entry.get("bytes") == path.stat().st_size, f"source size mismatch: {relative}")
    sys.path.insert(0, str(codec_root))
    from RealLLM.voidtoken_v5 import VoidTokenV5Backend

    return VoidTokenV5Backend


def validate_result_digest(result_path: Path) -> None:
    digest_path = result_path.with_name("result.sha256")
    require(digest_path.is_file(), "result.sha256 is missing")
    fields = digest_path.read_text(encoding="ascii").strip().split()
    require(len(fields) == 2 and fields[1] == "result.json", "invalid result.sha256")
    require(fields[0] == sha256_file(result_path), "result.json digest mismatch")


def validate_model_and_assets(result: dict[str, Any]) -> dict[str, Any]:
    matrix = load_object(MODEL_MATRIX_PATH)
    models = matrix["models"]
    model_key = result.get("modelKey")
    require(model_key in models, "unknown modelKey")
    expected = models[model_key]
    model = result.get("model")
    require(isinstance(model, dict), "model object is missing")
    for field in ("repository", "revision", "license"):
        require(model.get(field) == expected[field], f"model {field} mismatch")
    require(model.get("geometry") is not None, "model geometry is missing")
    geometry = model["geometry"]
    for field in (
        "modelType",
        "layers",
        "hiddenSize",
        "attentionHeads",
        "kvHeads",
        "headDimension",
    ):
        require(
            geometry.get(field) == expected["architecture"][field],
            f"model geometry mismatch: {field}",
        )
    require(result.get("dataset") == matrix["dataset"], "dataset pin mismatch")
    require(result["dataset"].get("split") == "validation", "non-validation split")
    assets = result.get("assets", {}).get("files")
    require(isinstance(assets, dict), "asset manifest is missing")
    require("dataset/test" not in assets, "test asset must not be present")
    for filename, specification in expected["files"].items():
        entry = assets.get(f"model/{filename}")
        require(entry == specification, f"model asset mismatch: {filename}")
    dataset_entry = assets.get("dataset/validation")
    require(
        dataset_entry
        == {
            "bytes": matrix["dataset"]["bytes"],
            "sha256": matrix["dataset"]["sha256"],
        },
        "validation asset mismatch",
    )
    return expected


def validate_protocol(result: dict[str, Any]) -> dict[str, Any]:
    require(result.get("schemaVersion") == "corelm-cross-model-regression-v1", "schema")
    require(result.get("status") == "exploratory-cross-model-regression", "status")
    require(result.get("countsTowardScientificVerdict") is False, "scientific flag")
    require(result.get("blind") is False, "blind flag")
    protocol = result.get("protocol")
    require(isinstance(protocol, dict), "protocol is missing")
    require(protocol.get("blockTokens") == BLOCK_TOKENS, "blockTokens")
    require(protocol.get("prefillTokens") == PREFILL_TOKENS, "prefillTokens")
    require(protocol.get("predictionsPerBlock") == PREDICTIONS, "predictions")
    require(protocol.get("teacherForced") is True, "teacherForced")
    require(
        protocol.get("configurationSHA256") == EXPECTED_CONFIGURATION_SHA256,
        "configuration commitment mismatch",
    )
    configuration = protocol.get("configuration")
    require(isinstance(configuration, dict), "configuration is missing")
    require(
        sha256_bytes(canonical_json_bytes(configuration))
        == EXPECTED_CONFIGURATION_SHA256,
        "configuration bytes mismatch",
    )
    schedule = configuration.get("bitsByLayer")
    require(isinstance(schedule, list) and len(schedule) == LAYERS, "schedule length")
    require(protocol.get("thresholdsPreregisteredForThisModel") is False, "threshold flag")
    return configuration


def validate_token_file(
    result_path: Path, result: dict[str, Any], records: list[dict[str, Any]]
) -> None:
    inventory = result.get("tokenization")
    require(isinstance(inventory, dict), "token inventory missing")
    blocks = inventory.get("blocks")
    start = inventory.get("startBlock")
    require(type(blocks) is int and 1 <= blocks <= 8, "invalid block count")
    require(type(start) is int and start >= 64 and start + blocks <= 72, "invalid range")
    token_path = result_path.with_name("selected-token-ids.u32le")
    raw = token_path.read_bytes()
    require(len(raw) == blocks * BLOCK_TOKENS * 4, "token file length mismatch")
    require(
        sha256_bytes(raw) == inventory.get("selectedTokenIdsSHA256"),
        "selected token digest mismatch",
    )
    require(inventory.get("selectedTokenIds") == blocks * BLOCK_TOKENS, "token count")
    for offset, record in enumerate(records):
        block_raw = raw[offset * BLOCK_TOKENS * 4 : (offset + 1) * BLOCK_TOKENS * 4]
        require(record.get("blockIndex") == start + offset, "record block index")
        require(record.get("tokenIdsSHA256") == sha256_bytes(block_raw), "block token digest")


def validate_containers(
    result_path: Path,
    record: dict[str, Any],
    baseline: dict[str, Any],
    configuration: dict[str, Any],
    expected_model: dict[str, Any],
    backend: Any,
) -> None:
    block_index = record["blockIndex"]
    geometry = expected_model["architecture"]
    width = 2 * int(geometry["kvHeads"]) * int(geometry["headDimension"])
    expected_dense = PREFILL_TOKENS * width * LAYERS * 2
    require(record.get("denseBF16Bytes") == expected_dense, "dense BF16 bytes")
    require(baseline.get("denseBF16Bytes") == expected_dense, "baseline dense bytes")
    require(baseline.get("trajectoryShapePerLayer") == [PREFILL_TOKENS, width], "shape")
    require(baseline.get("layers") == LAYERS, "baseline layers")
    require(baseline.get("kvHeads") == geometry["kvHeads"], "baseline KV heads")
    require(
        baseline.get("headDimension") == geometry["headDimension"],
        "baseline head dimension",
    )
    require(baseline.get("layoutRebuildMaxAbsLogitDifference") == 0.0, "layout replay")
    require(baseline.get("layoutRebuildTop1Identical") is True, "layout top1")
    require(baseline.get("exactRebuildMaxAbsLogitDifference") == 0.0, "exact replay")
    require(baseline.get("exactRebuildTop1Identical") is True, "exact top1")
    manifest = record.get("containerManifest")
    require(isinstance(manifest, list) and len(manifest) == LAYERS, "container manifest")
    require(
        record.get("containerManifestSHA256")
        == sha256_bytes(canonical_json_bytes(manifest)),
        "container manifest digest",
    )
    total_payload = 0
    total_container = 0
    digest = hashlib.sha256()
    for layer_index, entry in enumerate(manifest):
        require(entry.get("layerIndex") == layer_index, "container layer order")
        path = (
            result_path.parent
            / "containers"
            / f"block-{block_index:06d}"
            / f"layer-{layer_index:02d}.vtl5"
        )
        raw = path.read_bytes()
        require(len(raw) == entry.get("containerBytes"), "container size")
        require(sha256_bytes(raw) == entry.get("containerSHA256"), "container digest")
        parsed = backend.from_bytes(raw)
        require(parsed.to_bytes() == raw, "non-canonical container")
        require(parsed.metadata == entry.get("metadata"), "container metadata")
        require(parsed.payload_bytes == entry.get("payloadBytes"), "payload bytes")
        metadata = parsed.metadata
        require(metadata.get("layerIndex") == layer_index, "metadata layer")
        require(metadata.get("shape") == [PREFILL_TOKENS, width], "metadata shape")
        require(metadata.get("bits") == configuration["bitsByLayer"][layer_index], "bits")
        for field in (
            "groupSize",
            "transformBlockSize",
            "scaleCompression",
            "codeCompression",
            "signMode",
        ):
            require(metadata.get(field) == configuration[field], f"metadata {field}")
        total_payload += len(parsed.payload)
        total_container += len(raw)
        digest.update(layer_index.to_bytes(4, "little"))
        digest.update(len(raw).to_bytes(8, "little"))
        digest.update(raw)
    require(total_payload == record.get("payloadBytes"), "payload total")
    require(total_container == record.get("encodedFileBytes"), "container total")
    require(digest.hexdigest() == record.get("payloadSHA256"), "container-set digest")
    require(record.get("predictionTokens") == PREDICTIONS, "prediction count")
    agreements = record.get("top1AgreementCount")
    require(type(agreements) is int and 0 <= agreements <= PREDICTIONS, "agreements")
    same_float(record.get("top1Agreement"), agreements / PREDICTIONS, "record top1")
    same_float(
        record.get("deltaNLLNatPerToken"),
        float(record["candidateNLLNatPerToken"])
        - float(record["baselineNLLNatPerToken"]),
        "record delta NLL",
    )


def recompute_aggregate(
    result: dict[str, Any], records: list[dict[str, Any]], configuration: dict[str, Any]
) -> dict[str, Any]:
    tokens = sum(int(record["predictionTokens"]) for record in records)
    dense = sum(int(record["denseBF16Bytes"]) for record in records)
    encoded = sum(int(record["encodedFileBytes"]) for record in records)
    agreements = sum(int(record["top1AgreementCount"]) for record in records)

    def weighted(field: str) -> float:
        return sum(
            float(record[field]) * int(record["predictionTokens"])
            for record in records
        ) / tokens

    baseline_nll = weighted("baselineNLLNatPerToken")
    candidate_nll = weighted("candidateNLLNatPerToken")
    delta = candidate_nll - baseline_nll
    thresholds = result["protocol"]["diagnosticThresholds"]
    gates = {
        "compression": dense / encoded >= thresholds["minimumCompressionRatioVsBF16"],
        "deltaNLL": delta <= thresholds["maximumDeltaNLLNatPerToken"],
        "top1Agreement": agreements / tokens >= thresholds["minimumTop1Agreement"],
    }
    return {
        "configuration": configuration,
        "configurationId": EXPECTED_CONFIGURATION_SHA256[:16],
        "blocks": len(records),
        "predictionTokens": tokens,
        "denseBF16Bytes": dense,
        "encodedFileBytes": encoded,
        "compressionRatioVsBF16": dense / encoded,
        "baselineNLLNatPerToken": baseline_nll,
        "candidateNLLNatPerToken": candidate_nll,
        "deltaNLLNatPerToken": delta,
        "perplexityRatio": math.exp(delta),
        "top1Agreement": agreements / tokens,
        "meanKLDivergenceNat": weighted("meanKLDivergenceNat"),
        "gates": gates,
        "pass": all(gates.values()),
    }


def verify(result_path: Path, codec_root: Path) -> dict[str, Any]:
    result_path = result_path.resolve()
    result = load_object(result_path)
    validate_result_digest(result_path)
    backend = validate_source(result, codec_root.resolve())
    expected_model = validate_model_and_assets(result)
    configuration = validate_protocol(result)
    records = result.get("records")
    baselines = result.get("baselines")
    require(isinstance(records, list) and records, "records are missing")
    require(isinstance(baselines, list), "baselines are missing")
    require(len(records) == len(baselines), "record/baseline count mismatch")
    validate_token_file(result_path, result, records)
    for record, baseline in zip(records, baselines):
        require(record.get("blockIndex") == baseline.get("blockIndex"), "block pairing")
        require(record.get("tokenIdsSHA256") == baseline.get("tokenIdsSHA256"), "token pairing")
        require(
            record.get("canonicalCacheBF16SHA256")
            == baseline.get("canonicalCacheBF16SHA256"),
            "cache pairing",
        )
        validate_containers(
            result_path,
            record,
            baseline,
            configuration,
            expected_model,
            backend,
        )
    recomputed = recompute_aggregate(result, records, configuration)
    aggregate = result.get("aggregate")
    require(isinstance(aggregate, dict), "aggregate is missing")
    for field in (
        "configuration",
        "configurationId",
        "blocks",
        "predictionTokens",
        "denseBF16Bytes",
        "encodedFileBytes",
        "gates",
        "pass",
    ):
        require(aggregate.get(field) == recomputed[field], f"aggregate {field}")
    for field in (
        "compressionRatioVsBF16",
        "baselineNLLNatPerToken",
        "candidateNLLNatPerToken",
        "deltaNLLNatPerToken",
        "perplexityRatio",
        "top1Agreement",
        "meanKLDivergenceNat",
    ):
        same_float(aggregate.get(field), recomputed[field], f"aggregate {field}")
    expected_verdict = "PASS" if recomputed["pass"] else "FAIL"
    require(result.get("diagnosticVerdict") == expected_verdict, "verdict mismatch")
    expected_containers = len(records) * LAYERS
    observed_containers = len(list((result_path.parent / "containers").rglob("*.vtl5")))
    require(observed_containers == expected_containers, "unexpected container count")
    return {
        "status": "VERIFIED",
        "modelKey": result["modelKey"],
        "blocks": len(records),
        "predictionTokens": recomputed["predictionTokens"],
        "compressionRatioVsBF16": recomputed["compressionRatioVsBF16"],
        "deltaNLLNatPerToken": recomputed["deltaNLLNatPerToken"],
        "top1Agreement": recomputed["top1Agreement"],
        "diagnosticVerdict": expected_verdict,
        "countsTowardScientificVerdict": False,
    }


def main() -> int:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("result", type=Path)
    value.add_argument("--codec-root", type=Path, required=True)
    arguments = value.parse_args()
    print(json.dumps(verify(arguments.result, arguments.codec_root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
