#!/usr/bin/env python3
"""Pure, offline protocol controls for the prospective blind v2 suite."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v2"
DOMAIN = b"corelm-voidtoken-crossmodel-livewiki-v2/select\0"
HEX_64 = re.compile(r"[0-9a-fA-F]{128}\Z")
CANDIDATE_RULE = {
    "backend": "voidtoken-v5",
    "groupSize": 128,
    "transformBlockSize": 128,
    "codeCompression": "zlib-9",
    "scaleCompression": "zlib-9",
    "signMode": "none",
    "bitSchedule": "9 bits at layers 0 and floor(layerCount / 3); 8 bits otherwise",
}
EXPECTED_TOP_LEVEL_FIELDS = {
    "schemaVersion",
    "status",
    "suiteId",
    "readyToFreeze",
    "countsTowardScientificVerdict",
    "claim",
    "scientificBoundary",
    "designRelease",
    "futureCorpus",
    "snapshotRelease",
    "codecSource",
    "labSource",
    "runtime",
    "models",
    "candidate",
    "execution",
    "beacon",
    "selection",
    "cellGates",
    "modelAggregateGates",
    "oneShotStateMachine",
    "freezeBlockers",
}

PROJECTS = [
    "de.wikipedia.org",
    "en.wikipedia.org",
    "fr.wikipedia.org",
]
MODELS = ["gpt-neo-125m", "smollm2-360m", "tiny-starcoder-py"]
CORPUS_START = datetime(2026, 8, 10, tzinfo=timezone.utc)
CORPUS_END = datetime(2026, 8, 24, tzinfo=timezone.utc)
DESIGN_RELEASE_DEADLINE = datetime(2026, 8, 9, tzinfo=timezone.utc)
SNAPSHOT_RELEASE_NOT_BEFORE = datetime(2026, 8, 25, 6, tzinfo=timezone.utc)
SNAPSHOT_RELEASE_DEADLINE = datetime(2026, 8, 26, 18, tzinfo=timezone.utc)
MODEL_AGGREGATE_T = 1.6955187825458675
MODEL_AGGREGATE_Z = 1.6448536269514715


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


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite JSON number is forbidden: {value}")
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json_unicode(value: Any, *, path: str = "$") -> None:
    if isinstance(value, str):
        for character in value:
            if 0xD800 <= ord(character) <= 0xDFFF:
                raise ValueError(f"lone surrogate is forbidden at {path}")
        value.encode("utf-8", errors="strict")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_unicode(item, path=f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_json_unicode(key, path=f"{path}.<key>")
            _validate_json_unicode(item, path=f"{path}.{key}")


def load_json_strict_bytes(value: bytes, *, label: str) -> Any:
    try:
        text = value.decode("utf-8", errors="strict")
        result = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        _validate_json_unicode(result)
        return result
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid strict JSON for {label}: {error}") from error


def load_json_strict(path: Path) -> Any:
    return load_json_strict_bytes(path.read_bytes(), label=str(path))


def uint64be(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        raise ValueError("value is outside uint64")
    return value.to_bytes(8, "big")


def decode_output_value(value: str) -> bytes:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise ValueError("NIST outputValue must be exactly 64 hexadecimal bytes")
    return bytes.fromhex(value)


def unbiased_draw(
    snapshot_registration_bytes: bytes,
    output_value: bytes,
    *,
    draw_index: int,
    population_size: int,
) -> dict[str, int | str]:
    if not snapshot_registration_bytes:
        raise ValueError("snapshot registration bytes must not be empty")
    if len(output_value) != 64:
        raise ValueError("NIST outputValue must contain exactly 64 bytes")
    if type(population_size) is not int or population_size < 1:
        raise ValueError("population size must be a positive integer")
    uint64be(draw_index)
    limit = 2**512 - (2**512 % population_size)
    counter = 0
    while True:
        digest = hashlib.sha512(
            DOMAIN
            + uint64be(len(snapshot_registration_bytes))
            + snapshot_registration_bytes
            + output_value
            + uint64be(draw_index)
            + uint64be(counter)
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate < limit:
            return {
                "counter": counter,
                "digestSHA512": digest.hex(),
                "populationSizeBefore": population_size,
                "selectedPosition": candidate % population_size,
            }
        counter += 1


def _select_one(
    pool: list[Any],
    snapshot_registration_bytes: bytes,
    output_value: bytes,
    draw_index: int,
) -> tuple[Any, dict[str, int | str]]:
    draw = unbiased_draw(
        snapshot_registration_bytes,
        output_value,
        draw_index=draw_index,
        population_size=len(pool),
    )
    selected = pool.pop(int(draw["selectedPosition"]))
    return selected, {"drawIndex": draw_index, **draw}


def _validate_unique_strings(values: Iterable[str], *, label: str) -> list[str]:
    result = list(values)
    if len(result) != 3 or any(not isinstance(value, str) or not value for value in result):
        raise ValueError(f"{label} must contain exactly three non-empty strings")
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _parse_utc_seconds(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError(f"{label} must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError(f"{label} is not a real UTC timestamp") from error


def validate_ledger(
    project: str,
    records: Any,
    *,
    minimum_records: int = 16,
    timestamp_start: datetime | None = None,
    timestamp_end: datetime | None = None,
) -> list[dict[str, Any]]:
    if type(minimum_records) is not int or minimum_records < 16:
        raise ValueError("minimum ledger size must be at least sixteen")
    if not isinstance(records, list) or len(records) < minimum_records:
        raise ValueError(
            f"ledger {project} must contain at least {minimum_records} records"
        )
    result: list[dict[str, Any]] = []
    revision_ids: set[int] = set()
    page_ids: set[int] = set()
    previous: tuple[str, int] | None = None
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"ledger {project} contains a non-object record")
        timestamp = record.get("timestamp")
        pageid = record.get("pageid")
        revid = record.get("revid")
        parsed_timestamp = _parse_utc_seconds(
            timestamp, label=f"ledger {project} record timestamp"
        )
        if timestamp_start is not None and parsed_timestamp < timestamp_start:
            raise ValueError(f"ledger {project} record precedes the corpus interval")
        if timestamp_end is not None and parsed_timestamp >= timestamp_end:
            raise ValueError(f"ledger {project} record is outside the corpus interval")
        if type(pageid) is not int or pageid < 1:
            raise ValueError(f"ledger {project} record pageid is invalid")
        if type(revid) is not int or revid < 1:
            raise ValueError(f"ledger {project} record revid is invalid")
        identity = (timestamp, revid)
        if revid in revision_ids:
            raise ValueError(f"ledger {project} contains a duplicate revision")
        if pageid in page_ids:
            raise ValueError(f"ledger {project} contains two revisions for one page")
        if previous is not None and identity <= previous:
            raise ValueError(f"ledger {project} is not sorted by timestamp/revid")
        revision_ids.add(revid)
        page_ids.add(pageid)
        previous = identity
        result.append(
            {
                "project": project,
                "timestamp": timestamp,
                "pageid": pageid,
                "revid": revid,
            }
        )
    return result


def validate_snapshot_registration(snapshot: Any, *, allow_fixture: bool) -> None:
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot registration must be a JSON object")
    schema = snapshot.get("schemaVersion")
    if schema == "corelm-crossmodel-livewiki-v2-snapshot-fixture-v1":
        if not allow_fixture:
            raise ValueError("protocol-control snapshot fixture is forbidden here")
        expected_fixture = {
            "schemaVersion": "corelm-crossmodel-livewiki-v2-snapshot-fixture-v1",
            "fixtureOnly": True,
            "purpose": "known-answer protocol control; contains no model or corpus evidence",
        }
        if snapshot != expected_fixture:
            raise ValueError("snapshot fixture fields differ")
        return
    if schema != "corelm-crossmodel-livewiki-v2-snapshot-registration-v1":
        raise ValueError("unexpected snapshot registration schemaVersion")
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "status",
        "designRelease",
        "snapshotRelease",
        "projects",
        "models",
        "ledgers",
        "modelAssetManifestSHA256",
        "corpusManifestSHA256",
        "createdAt",
    }
    if set(snapshot) != expected_fields:
        raise ValueError("snapshot registration fields differ")
    if snapshot.get("suiteId") != SUITE_ID:
        raise ValueError("snapshot suiteId differs")
    if snapshot.get("status") != "PUBLIC_SNAPSHOT_FROZEN":
        raise ValueError("snapshot is not in the frozen public state")
    if snapshot.get("projects") != PROJECTS:
        raise ValueError("snapshot projects differ")
    if snapshot.get("models") != MODELS:
        raise ValueError("snapshot models differ")
    release_fields = {
        "tag",
        "commit",
        "tree",
        "publishedAt",
        "freezeManifestSHA256",
    }
    release_times: dict[str, datetime] = {}
    for field, expected_tag in (
        ("designRelease", "corelm-crossmodel-livewiki-v2-design"),
        ("snapshotRelease", "corelm-crossmodel-livewiki-v2-snapshot"),
    ):
        release = snapshot.get(field)
        if not isinstance(release, dict) or set(release) != release_fields:
            raise ValueError(f"snapshot {field} fields differ")
        if release.get("tag") != expected_tag:
            raise ValueError(f"snapshot {field} tag differs")
        for identity in ("commit", "tree"):
            if not isinstance(release.get(identity), str) or not re.fullmatch(
                r"[0-9a-f]{40}", release[identity]
            ):
                raise ValueError(f"snapshot {field} {identity} is invalid")
        if not isinstance(release.get("freezeManifestSHA256"), str) or not re.fullmatch(
            r"[0-9a-f]{64}", release["freezeManifestSHA256"]
        ):
            raise ValueError(f"snapshot {field} manifest digest is invalid")
        release_times[field] = _parse_utc_seconds(
            release.get("publishedAt"), label=f"snapshot {field} publishedAt"
        )
    if release_times["designRelease"] > DESIGN_RELEASE_DEADLINE:
        raise ValueError("design release missed its registered deadline")
    if not (
        SNAPSHOT_RELEASE_NOT_BEFORE
        <= release_times["snapshotRelease"]
        <= SNAPSHOT_RELEASE_DEADLINE
    ):
        raise ValueError("snapshot release is outside its registered window")
    created_at = _parse_utc_seconds(
        snapshot.get("createdAt"), label="snapshot createdAt"
    )
    if created_at < SNAPSHOT_RELEASE_NOT_BEFORE:
        raise ValueError("snapshot was created before the second registered crawl")
    if created_at > release_times["snapshotRelease"]:
        raise ValueError("snapshot cannot be created after its public release")
    ledgers = snapshot.get("ledgers")
    if not isinstance(ledgers, dict) or set(ledgers) != set(PROJECTS):
        raise ValueError("snapshot ledger commitments differ")
    digests = [
        snapshot.get("modelAssetManifestSHA256"),
        snapshot.get("corpusManifestSHA256"),
        *ledgers.values(),
    ]
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in digests):
        raise ValueError("snapshot contains an invalid digest")


def resolve_selection(
    snapshot_registration_bytes: bytes,
    output_value_hex: str,
    *,
    projects: Iterable[str],
    models: Iterable[str],
    ledgers: dict[str, bytes | Any],
    allow_fixture: bool = False,
) -> dict[str, Any]:
    # Parsing is part of the commitment: selection is bound to exact valid JSON
    # bytes, not merely to an arbitrary byte string with the same file name.
    snapshot = load_json_strict_bytes(
        snapshot_registration_bytes, label="snapshot registration"
    )
    validate_snapshot_registration(snapshot, allow_fixture=allow_fixture)
    fixture_mode = (
        snapshot.get("schemaVersion")
        == "corelm-crossmodel-livewiki-v2-snapshot-fixture-v1"
    )
    output_value = decode_output_value(output_value_hex)
    project_pool = _validate_unique_strings(projects, label="projects")
    model_pool = _validate_unique_strings(models, label="models")
    if not fixture_mode:
        if project_pool != snapshot["projects"]:
            raise ValueError("caller projects differ from the frozen snapshot")
        if model_pool != snapshot["models"]:
            raise ValueError("caller models differ from the frozen snapshot")
    if set(ledgers) != set(project_pool):
        raise ValueError("ledger projects differ from the registered projects")
    validated_ledgers: dict[str, list[dict[str, Any]]] = {}
    for project in project_pool:
        value = ledgers[project]
        if fixture_mode:
            parsed_ledger = value
            minimum_records = 16
            timestamp_start = None
            timestamp_end = None
        else:
            if not isinstance(value, bytes):
                raise ValueError(
                    f"normative ledger {project} must be supplied as exact bytes"
                )
            parsed_ledger = load_json_strict_bytes(value, label=f"ledger {project}")
            if sha256_bytes(value) != snapshot["ledgers"][project]:
                raise ValueError(f"ledger commitment mismatch: {project}")
            minimum_records = 64
            timestamp_start = CORPUS_START
            timestamp_end = CORPUS_END
        validated_ledgers[project] = validate_ledger(
            project,
            parsed_ledger,
            minimum_records=minimum_records,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )

    draws: list[dict[str, Any]] = []
    corpus_a, draw = _select_one(
        project_pool, snapshot_registration_bytes, output_value, 0
    )
    draws.append({**draw, "kind": "corpus", "selected": corpus_a})
    corpus_b, draw = _select_one(
        project_pool, snapshot_registration_bytes, output_value, 1
    )
    draws.append({**draw, "kind": "corpus", "selected": corpus_b})

    selected_pages: dict[str, list[dict[str, Any]]] = {}
    draw_index = 2
    for project in (corpus_a, corpus_b):
        pool = validated_ledgers[project].copy()
        chosen: list[dict[str, Any]] = []
        for _ in range(16):
            selected, draw = _select_one(
                pool, snapshot_registration_bytes, output_value, draw_index
            )
            chosen.append(selected)
            draws.append({**draw, "kind": "page", "selected": selected})
            draw_index += 1
        selected_pages[project] = chosen

    selected_models: list[str] = []
    for _ in range(2):
        selected, draw = _select_one(
            model_pool, snapshot_registration_bytes, output_value, draw_index
        )
        selected_models.append(selected)
        draws.append({**draw, "kind": "model", "selected": selected})
        draw_index += 1
    selected_models.extend(model_pool)

    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-selection-v1",
        "suiteId": SUITE_ID,
        "snapshotRegistrationSHA256": sha256_bytes(snapshot_registration_bytes),
        "nistOutputValue": output_value.hex().upper(),
        "selectedCorpora": [corpus_a, corpus_b],
        "selectedPages": selected_pages,
        "modelExecutionOrder": selected_models,
        "draws": draws,
    }


def candidate_bits(layer_count: int) -> list[int]:
    if type(layer_count) is not int or layer_count < 3:
        raise ValueError("registered models must contain at least three layers")
    high_precision = {0, layer_count // 3}
    return [
        9 if layer_index in high_precision else 8
        for layer_index in range(layer_count)
    ]


def candidate_configuration(layer_count: int) -> dict[str, Any]:
    return {**CANDIDATE_RULE, "bitsByLayer": candidate_bits(layer_count)}


def evaluate_model_aggregate(
    block_delta_nll: Iterable[float],
    block_exact_matches: Iterable[int],
) -> dict[str, float | int | bool]:
    """Apply the registered model-level gates to 32 canonical page blocks."""

    deltas = list(block_delta_nll)
    matches = list(block_exact_matches)
    if len(deltas) != 32 or len(matches) != 32:
        raise ValueError("model aggregate requires exactly 32 page blocks")
    if any(
        type(value) not in {float, int} or not math.isfinite(value)
        for value in deltas
    ):
        raise ValueError("model aggregate contains an invalid delta-NLL")
    if any(type(value) is not int or not 0 <= value <= 128 for value in matches):
        raise ValueError("model aggregate contains an invalid exact-match count")
    block_top1 = [value / 128 for value in matches]
    delta_upper = statistics.fmean(deltas) + (
        MODEL_AGGREGATE_T * statistics.stdev(deltas) / math.sqrt(32)
    )
    top1_lower = statistics.fmean(block_top1) - (
        MODEL_AGGREGATE_T * statistics.stdev(block_top1) / math.sqrt(32)
    )
    total_matches = sum(matches)
    trials = 4096
    p = total_matches / trials
    z = MODEL_AGGREGATE_Z
    wilson_lower = (
        p
        + z * z / (2 * trials)
        - z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    ) / (1 + z * z / trials)
    passed = delta_upper <= 0.01 and top1_lower >= 0.99 and wilson_lower >= 0.99
    return {
        "blocks": 32,
        "predictions": trials,
        "totalExactMatches": total_matches,
        "deltaUpper": delta_upper,
        "top1Lower": top1_lower,
        "wilsonLower": wilson_lower,
        "pass": passed,
    }


def validate_design_registration(registration: Any) -> list[str]:
    if not isinstance(registration, dict):
        raise ValueError("design registration must be an object")
    if set(registration) != EXPECTED_TOP_LEVEL_FIELDS:
        raise ValueError("design registration top-level fields differ")
    if registration.get("schemaVersion") != "corelm-crossmodel-livewiki-v2-design-draft-v1":
        raise ValueError("unexpected design schemaVersion")
    status = registration.get("status")
    if status != "DRAFT_NOT_PREREGISTERED":
        raise ValueError(
            "freeze-candidate validation is fail-closed until all concrete "
            "artifact and execution gates are implemented"
        )
    if registration.get("suiteId") != SUITE_ID:
        raise ValueError("unexpected suiteId")
    if registration.get("countsTowardScientificVerdict") is not False:
        raise ValueError("unpublished design must not count toward a scientific verdict")
    for field in ("claim", "scientificBoundary"):
        if not isinstance(registration.get(field), str) or not registration[field]:
            raise ValueError(f"design text field is empty: {field}")
    expected_design_release = {
        "tag": "corelm-crossmodel-livewiki-v2-design",
        "publishNoLaterThan": "2026-08-09T00:00:00Z",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
    }
    if registration.get("designRelease") != expected_design_release:
        raise ValueError("design release boundary differs")
    expected_future_corpus = {
        "projects": [
            "de.wikipedia.org",
            "en.wikipedia.org",
            "fr.wikipedia.org",
        ],
        "creationInterval": {
            "startInclusive": "2026-08-10T00:00:00Z",
            "endExclusive": "2026-08-24T00:00:00Z",
        },
        "snapshotPolicy": "union-of-two-complete-archived-recentchanges-crawls",
        "firstCrawlNotBefore": "2026-08-24T06:00:00Z",
        "secondCrawlNotBefore": "2026-08-25T06:00:00Z",
        "minimumEligibleRevisionsPerProject": 64,
        "pagesSelectedPerCorpus": 16,
        "tokenization": {
            "input": "title + two LF bytes + raw creation-revision wikitext",
            "unicodeNormalization": "none",
            "utf8": "strict",
            "addSpecialTokens": False,
            "minimumTokensUnderEveryRegisteredTokenizer": 512,
        },
        "license": "CC-BY-SA-4.0",
        "attributionLedgerRequired": True,
    }
    if registration.get("futureCorpus") != expected_future_corpus:
        raise ValueError("future corpus boundary differs")
    _validate_unique_strings(
        expected_future_corpus["projects"], label="future corpus projects"
    )
    expected_snapshot_release = {
        "tag": "corelm-crossmodel-livewiki-v2-snapshot",
        "publishNoLaterThan": "2026-08-26T18:00:00Z",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
    }
    if registration.get("snapshotRelease") != expected_snapshot_release:
        raise ValueError("snapshot release boundary differs")
    expected_codec_source = {
        "repository": "https://github.com/ALLPROTO/core-lm-benchmark.git",
        "commit": "2e8d3b1591ee4a1ed822310f330317936871ff2b",
        "tree": "c0bb15784d252cd5036757bc64765c773a5f16e8",
        "requiredFiles": {
            "RealLLM/app_proof_core.py": {
                "bytes": 43127,
                "sha256": "16940683af7b182a588404a493d54e17e029288f4947f2e7e9ab6a4f1c106bd4",
            },
            "RealLLM/benchmark_real_llm.py": {
                "bytes": 67362,
                "sha256": "b5e7b301222501e148d54cda3f0d04997e6a061051cedc6393d1a87b638522d0",
            },
            "RealLLM/codecs.py": {
                "bytes": 23987,
                "sha256": "fe5763b7cb0b2e775436c7414a1af48704095518e0428fe4a7965b84f0ce7a05",
            },
            "RealLLM/requirements.lock": {
                "bytes": 55781,
                "sha256": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
            },
            "RealLLM/voidtoken_v5.py": {
                "bytes": 35374,
                "sha256": "80ed51aa2a201dbdaae36434709a50a8a679fa84d29b08ad7b083c14cec33758",
            },
        },
    }
    if registration.get("codecSource") != expected_codec_source:
        raise ValueError("codec source boundary differs")
    lab_source = registration.get("labSource")
    runtime = registration.get("runtime")
    expected_lab_source = {
        "repository": "https://github.com/ALLPROTO/core-lm-cross-model-lab.git",
        "status": "UNBOUND_DRAFT",
        "commit": None,
        "tree": None,
        "freezeManifestSHA256": None,
    }
    if lab_source != expected_lab_source:
        raise ValueError("draft lab source boundary differs")
    expected_runtime = {
        "python": "3.12.13",
        "primaryPlatform": "macOS-arm64-local-offline",
        "postEvidenceReplication": "Linux-x86_64-GitHub-Actions",
        "requirementsLockSHA256": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
        "status": "UNBOUND_DRAFT",
        "runtimeManifestSHA256": None,
    }
    if runtime != expected_runtime:
        raise ValueError("draft runtime boundary differs")
    models = registration.get("models")
    if not isinstance(models, list) or len(models) != 3:
        raise ValueError("exactly three model specifications are required")
    keys = _validate_unique_strings(
        [model.get("key") for model in models if isinstance(model, dict)],
        label="model keys",
    )
    if len(keys) != 3:
        raise ValueError("model entries are invalid")
    expected_model_fields = {
        "key",
        "repository",
        "revision",
        "architecture",
        "layers",
        "kvHeads",
        "weightFile",
        "weightBytes",
        "weightSHA256",
        "license",
        "candidateBitsByLayer",
        "candidateConfigurationSHA256",
        "previouslyRunByThisLab",
    }
    expected_models = {
        "gpt-neo-125m": {
            "repository": "EleutherAI/gpt-neo-125m",
            "revision": "21def0189f5705e2521767faed922f1f15e7d7db",
            "architecture": "gpt-neo-mixed-global-local",
            "layers": 12,
            "kvHeads": 12,
            "weightBytes": 525979192,
            "weightSHA256": "52738cbfb54e25a232598242f60ef19ee193d36090b98fe649b10c02724b3521",
            "license": "mit",
        },
        "smollm2-360m": {
            "repository": "HuggingFaceTB/SmolLM2-360M",
            "revision": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
            "architecture": "llama-gqa",
            "layers": 32,
            "kvHeads": 5,
            "weightBytes": 723674912,
            "weightSHA256": "7aaff6661428bed033abba9522bec81938678642cca3181fe752b6ca9e1e540f",
            "license": "apache-2.0",
        },
        "tiny-starcoder-py": {
            "repository": "bigcode/tiny_starcoder_py",
            "revision": "8547527bef0bc927268c1653cce6948c5c242dd1",
            "architecture": "gpt-bigcode-mqa",
            "layers": 20,
            "kvHeads": 1,
            "weightBytes": 656601304,
            "weightSHA256": "15fa942f055b618d5ca6283f5c27278a475ff12e53dc704b9658ffd5160d4021",
            "license": "bigcode-openrail-m",
        },
    }
    if keys != list(expected_models):
        raise ValueError("registered model order differs")
    for model in models:
        if set(model) != expected_model_fields:
            raise ValueError(f"model fields differ: {model.get('key')}")
        expected_model = expected_models[model["key"]]
        for field, expected in expected_model.items():
            if model.get(field) != expected:
                raise ValueError(f"model field differs: {model.get('key')}/{field}")
        if model.get("weightFile") != "model.safetensors":
            raise ValueError(f"unsafe weight file: {model.get('key')}")
        if model.get("previouslyRunByThisLab") is not False:
            raise ValueError("every v2 model must remain previously unrun")
        if not re.fullmatch(r"[0-9a-f]{40}", str(model.get("revision", ""))):
            raise ValueError(f"model revision is not a full commit: {model.get('key')}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(model.get("weightSHA256", ""))):
            raise ValueError(f"model weight digest is invalid: {model.get('key')}")
        if type(model.get("weightBytes")) is not int or model["weightBytes"] < 1:
            raise ValueError(f"model weight size is invalid: {model.get('key')}")
        expected_bits = candidate_bits(model.get("layers"))
        if model.get("candidateBitsByLayer") != expected_bits:
            raise ValueError(f"candidate bit schedule mismatch: {model.get('key')}")
        expected_configuration_sha256 = sha256_bytes(
            canonical_json_bytes(candidate_configuration(model["layers"]))
        )
        if model.get("candidateConfigurationSHA256") != expected_configuration_sha256:
            raise ValueError(f"candidate configuration digest mismatch: {model.get('key')}")
    candidate = registration.get("candidate")
    expected_rule_sha256 = sha256_bytes(canonical_json_bytes(CANDIDATE_RULE))
    expected_candidate = {
        "backend": "voidtoken-v5",
        "groupSize": 128,
        "transformBlockSize": 128,
        "codeCompression": "zlib-9",
        "scaleCompression": "zlib-9",
        "signMode": "none",
        "bitScheduleRule": "9 bits when zero-based layer index is 0 or floor(layerCount / 3); 8 bits otherwise",
        "candidateRuleSHA256": expected_rule_sha256,
        "calibration": "forbidden",
        "architectureSpecificRetuning": "forbidden",
    }
    if candidate != expected_candidate:
        raise ValueError("candidate boundary differs")
    expected_execution = {
        "device": "cpu",
        "intraOpThreads": 2,
        "interOpThreads": 1,
        "modelDtype": "float32",
        "cacheBaseline": "float32-to-bfloat16-to-float32",
        "attentionImplementation": "eager",
        "prefillTokens": 383,
        "predictionTokensPerPage": 128,
        "modelProcessIsolation": "one-model-per-process",
        "acPowerRequired": True,
        "minimumFreeMemoryPercent": 50,
        "deterministicAlgorithms": "fail-closed",
        "networkAfterAttemptMarker": "forbidden",
        "pickle": "forbidden",
        "trustRemoteCode": "forbidden",
        "filesystemModelLoadAfterMarker": "forbidden",
        "hardDeadline": "2026-08-29T18:00:00Z",
    }
    if registration.get("execution") != expected_execution:
        raise ValueError("execution boundary differs")
    expected_beacon = {
        "targetTimestamp": "2026-08-27T18:00:00.000Z",
        "targetUnixMilliseconds": 1787853600000,
        "pulseEndpoint": "https://beacon.nist.gov/beacon/2.0/pulse/time/1787853600000",
        "fallback": "forbidden",
        "exactTimestampRequired": True,
        "signatureAndOutputVerificationRequired": True,
        "selectionDomainASCIIWithTerminalNUL": DOMAIN[:-1].decode("ascii") + "\\0",
        "selectionDigest": "SHA-512",
        "moduloBias": "rejection-sampling",
    }
    if registration.get("beacon") != expected_beacon:
        raise ValueError("beacon boundary differs")
    expected_selection = {
        "corporaSelected": 2,
        "pagesPerCorpus": 16,
        "allModelsRequired": True,
        "beaconControlsModelOrderOnly": True,
        "drawOrder": "corpus-A, corpus-B, 16 pages A, 16 pages B, first model, second model, append remaining model",
    }
    if registration.get("selection") != expected_selection:
        raise ValueError("selection boundary differs")
    expected_cell_gates = {
        "minimumCompressionRatioVsBF16": 2.0,
        "maximumDeltaNLLNatPerToken": 0.01,
        "minimumTop1Agreement": 0.99,
        "structuralReplayRequiredForEveryContainer": True,
        "allSixCellsMustPass": True,
    }
    if registration.get("cellGates") != expected_cell_gates:
        raise ValueError("cell gates differ")
    expected_model_aggregate_gates = {
        "pagesPerModel": 32,
        "predictionsPerPage": 128,
        "totalPredictionsPerModel": 4096,
        "canonicalBlockOrder": "selected corpus A pages in selection order, then selected corpus B pages in selection order",
        "blockDeltaDefinition": "math.fsum(candidate token loss - baseline token loss in canonical token order) / 128",
        "blockTop1Definition": "integer exact-match count / 128",
        "meanFunction": "statistics.fmean",
        "sampleStandardDeviationFunction": "statistics.stdev",
        "squareRootFunction": "math.sqrt",
        "studentTOneSided95Df31": MODEL_AGGREGATE_T,
        "normalZOneSided95": MODEL_AGGREGATE_Z,
        "deltaUpperFormula": "fmean(blockDelta) + t * stdev(blockDelta) / sqrt(32)",
        "top1LowerFormula": "fmean(blockTop1) - t * stdev(blockTop1) / sqrt(32)",
        "wilsonLowerFormula": "(p + z*z/(2*4096) - z*sqrt(p*(1-p)/4096 + z*z/(4*4096*4096))) / (1 + z*z/4096)",
        "maximumDeltaUpperNLLNatPerToken": 0.01,
        "minimumTop1Lower": 0.99,
        "minimumWilsonLower": 0.99,
        "allThreeModelsMustPass": True,
        "interpretation": "fixed descriptive gates; not IID population confidence claims",
    }
    if registration.get("modelAggregateGates") != expected_model_aggregate_gates:
        raise ValueError("model aggregate gates differ")
    expected_state = {
        "attemptMarkerBeforeSelectionOrDataOpen": True,
        "retryAfterMarker": "forbidden",
        "terminalStates": [
            "PASS",
            "FAIL_GATES",
            "FAIL_EXECUTION",
            "CONSUMED_INCOMPLETE",
            "LATE_PUBLICATION_INVALID",
            "NO_ATTEMPT_EXPIRED",
        ],
        "allLaterRuns": "regression-only",
    }
    if registration.get("oneShotStateMachine") != expected_state:
        raise ValueError("one-shot state machine differs")
    blockers = registration.get("freezeBlockers")
    if not isinstance(blockers, list) or any(
        not isinstance(item, str) or not item for item in blockers
    ):
        raise ValueError("freeze blockers must be a list of non-empty strings")
    ready = registration.get("readyToFreeze")
    if ready is not False or not blockers:
        raise ValueError("draft must fail closed with explicit blockers")
    return blockers


def validate_model_asset_manifest(
    manifest: Any, registration: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("model asset manifest must be an object")
    if manifest.get("schemaVersion") != "corelm-crossmodel-livewiki-v2-model-assets-draft-v1":
        raise ValueError("unexpected model asset manifest schemaVersion")
    if manifest.get("status") != "DRAFT_METADATA_VERIFIED_NO_WEIGHT_DOWNLOAD":
        raise ValueError("unexpected model asset manifest status")
    if manifest.get("completeRuntimeFileList") is not True:
        raise ValueError("runtime file list must be complete")
    if manifest.get("smallRuntimeFilesContentHashed") is not True:
        raise ValueError("small runtime files must be content-hashed")
    if manifest.get("fullSafetensorsBytesLocallyVerified") is not False:
        raise ValueError("draft must not claim local full-weight verification")
    if manifest.get("weightsRedistributed") is not False:
        raise ValueError("model weights must not be redistributed")
    forbidden = manifest.get("forbiddenFormats")
    if not isinstance(forbidden, list) or "pytorch_model.bin" not in forbidden:
        raise ValueError("unsafe pickle weights must be explicitly forbidden")
    specifications = {model["key"]: model for model in registration["models"]}
    models = manifest.get("models")
    if not isinstance(models, dict) or set(models) != set(specifications):
        raise ValueError("asset manifest models differ from design registration")
    required_files = {
        "config.json",
        "generation_config.json",
        "merges.txt",
        "model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    }
    content_hashed_files = 0
    for key, model in models.items():
        specification = specifications[key]
        for field in ("repository", "revision", "license"):
            if model.get(field) != specification.get(field):
                raise ValueError(f"asset {field} mismatch: {key}")
        files = model.get("files")
        if not isinstance(files, dict) or set(files) != required_files:
            raise ValueError(f"runtime asset set mismatch: {key}")
        for filename, item in files.items():
            if not isinstance(item, dict):
                raise ValueError(f"asset entry is invalid: {key}/{filename}")
            if type(item.get("bytes")) is not int or item["bytes"] < 1:
                raise ValueError(f"asset byte count is invalid: {key}/{filename}")
            if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
                raise ValueError(f"asset digest is invalid: {key}/{filename}")
            if filename == "model.safetensors":
                if item["bytes"] != specification["weightBytes"]:
                    raise ValueError(f"weight byte count mismatch: {key}")
                if item["sha256"] != specification["weightSHA256"]:
                    raise ValueError(f"weight digest mismatch: {key}")
                if item.get("digestSource") != "official-lfs-pointer-not-yet-locally-rehashed":
                    raise ValueError(f"draft weight verification status mismatch: {key}")
            else:
                if item.get("digestSource") != "downloaded-content":
                    raise ValueError(f"small asset was not content-hashed: {key}/{filename}")
                content_hashed_files += 1
    return {
        "models": len(models),
        "runtimeFiles": len(models) * len(required_files),
        "smallFilesContentHashed": content_hashed_files,
        "fullSafetensorsBytesLocallyVerified": False,
    }
