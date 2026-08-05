#!/usr/bin/env python3
"""Pure, offline protocol controls for the prospective blind-v1 suite."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SUITE_ID = "corelm-blind-crossmodel-v1"
DOMAIN = b"corelm-blind-crossmodel-v1/select\0"
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
    "priorObservations",
    "modelCardEvidence",
    "modelWeightLayouts",
    "developmentControls",
    "designRelease",
    "futureCorpus",
    "snapshotRelease",
    "reservationRelease",
    "evidenceRelease",
    "closeoutRelease",
    "reschedulePolicy",
    "codecSource",
    "labSource",
    "runtime",
    "continuousIntegration",
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
MODELS = [
    "pythia-160m",
    "pythia-70m",
    "smollm-135m",
    "smollm-360m",
    "gpt2-124m",
    "distilgpt2-82m",
]
SELECTED_MODEL_COUNT = 3
CORPUS_START = datetime(2026, 8, 10, tzinfo=timezone.utc)
CORPUS_END = datetime(2026, 8, 18, tzinfo=timezone.utc)
DESIGN_RELEASE_DEADLINE = datetime(2026, 8, 9, tzinfo=timezone.utc)
SNAPSHOT_RELEASE_NOT_BEFORE = datetime(2026, 8, 19, 6, tzinfo=timezone.utc)
SNAPSHOT_RELEASE_DEADLINE = datetime(2026, 8, 20, 18, tzinfo=timezone.utc)
MODEL_AGGREGATE_T = 1.6955187825458675
MODEL_AGGREGATE_Z = 1.6448536269514715
NIST_TRUST_BUNDLE_SCHEMA = "corelm-blind-crossmodel-v1-nist-trust-bundle-v2"
NIST_CANDIDATE_TRUST_BUNDLE_SHA256 = (
    "cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706"
)
NIST_FROZEN_TRUST_BUNDLE_SHA256 = (
    "5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a"
)
NIST_CERTIFICATE_ID = (
    "528943a555f5f8ca54423be6dfb95925a35c7b552046420e7d7cd072058a14d65"
    "36ad3a8e9754b6582f164a90b0cd86a65d659f5426a2659a947595d1c816c8c"
)
NIST_REVOCATION_RESIDUAL_RISK = (
    "A pinned certificate that is revoked or compromised before the target pulse "
    "can still be accepted; no contemporaneous OCSP or CRL status is checked or "
    "claimed."
)
EXPECTED_DEVELOPMENT_CONTROLS = {
    "status": "NON_SCIENTIFIC_PRE_FREEZE_ONLY",
    "dataset": {
        "datasetId": "UniversalDependencies/UD_English-PUD:r2.18:test",
        "repository": "UniversalDependencies/UD_English-PUD",
        "revision": "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
        "tree": "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde",
        "releaseTag": "r2.18",
        "split": "test",
        "splitPurpose": (
            "upstream test split reused only as a non-scientific development "
            "control; it is not a blind scientific test result"
        ),
        "file": "en_pud-ud-test.conllu",
        "format": "CoNLL-U",
        "bytes": 1_386_858,
        "sha256": "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa",
        "rows": 1_000,
        "rowExtraction": (
            "exactly one '# text = ' value from each LF-delimited CoNLL-U "
            "sentence block; prefix removed; text otherwise unchanged"
        ),
        "joinedTextBytes": 112_419,
        "joinedTextSHA256": (
            "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea"
        ),
        "license": "CC-BY-SA-3.0",
        "manifestPath": "blind_v1/development-corpus.draft.json",
        "manifestBytes": 1_982,
        "manifestSHA256": "6b271476a157677580586b33932febcc83915a4f3cdb632fe227e2accb20a7a5",
    },
    "modelAssets": {
        "path": "blind_v1/development-model-assets.json",
        "bytes": 6_546,
        "sha256": "cb076a166a24f01fb707be871698c0e08b8b7d4929e6717547f5057b46109f9e",
        "modelKeys": [
            "gpt-neo-125m",
            "smollm2-360m",
            "tiny-starcoder-py",
        ],
        "excludedFromConfirmatoryPool": True,
    },
    "allowedEntryPoints": [
        {
            "path": "blind_v1/run_real_e2e_control.py",
            "control": "producer-vtl5-independent-replay",
            "candidateCodecInvoked": True,
            "candidateMetricsComputed": True,
        },
    ],
    "realPretrainedModelsRequired": True,
    "realCorpusBytesRequired": True,
    "syntheticInputsForbidden": True,
    "futureCorpusUsed": False,
    "nistUsed": False,
    "scientificAttemptStateCreated": False,
    "scientificResultRootUsed": False,
    "countsTowardScientificVerdict": False,
    "usedForCandidateSelectionOrTuning": False,
    "configurationChangesAfterOutcome": "NEW_SUITE_AND_COMPLETE_TIMELINE_REQUIRED",
    "unitFixtureBoundary": "ISOLATED_NON_RESULT_PROTOCOL_TESTS_ONLY",
    "hostSafetyMemoryWait": {
        "scope": "NON_SCIENTIFIC_REAL_DATA_DEVELOPMENT_CONTROL_ONLY",
        "timeoutSeconds": 300,
        "pollSeconds": 2,
        "scientificOneShotBehavior": "IMMEDIATE_FAIL_NO_WAIT",
    },
    "realDataE2EFreezeGate": {
        "required": True,
        "reportSchemaVersion": (
            "corelm-blind-crossmodel-v1-real-e2e-development-report-v1"
        ),
        "reportFileName": "development-control-report.json",
        "completeNoLaterThan": "2026-08-09T00:00:00Z",
        "serverTimestampedArchiveRequired": True,
        "archiveTag": "corelm-blind-crossmodel-v1-development-control",
        "archiveRequiredAssetRoles": [
            "development-control-report",
            "development-control-artifacts",
            "sha256-manifest",
        ],
        "status": "UNBOUND_DRAFT",
        "executionId": None,
        "archiveReceiptSHA256": None,
        "archivePublishedAt": None,
        "archiveAttestedAt": None,
        "releaseAttestationBundleSHA256": None,
        "releaseAttestationOutputSHA256": None,
        "reportSHA256": None,
        "artifactSetSHA256": None,
        "controlConfigurationSHA256": None,
        "completedAt": None,
    },
}
EXPECTED_CONTINUOUS_INTEGRATION = {
    "workflowName": "Author-verified blind-v1 development controls",
    "workflowPath": ".github/workflows/blind-v1-development-controls.yml",
    "workflowFileBytes": 14012,
    "workflowFileSHA256": (
        "6c0b54bc4c318a2b55069852e07ae3355686ffb49a72c3ca4542396cf5375e87"
    ),
    "verificationMode": "AUTHOR_SELF_VERIFICATION",
    "authorName": "Ivan Tyshchenko",
    "authorORCID": "https://orcid.org/0009-0000-7935-6090",
    "authorGitHubLogin": "ALLPROTO",
    "authorDeclaration": (
        "I am the author and experiment operator. I verified this exact "
        "implementation commit, its canonical schemas, zero-skip Linux and macOS "
        "arm64 CI, evidence packaging, and real-data development control. No "
        "independent human review was performed. This self-attestation is not "
        "peer review, operator blindness, independent replication, or independent "
        "validation."
    ),
    "independentHumanReviewRequired": False,
    "independentHumanReviewPerformed": False,
    "claimBoundary": (
        "Author-operated and author-self-verified prospective artifact. No "
        "independent human review, peer review, operator blindness, independent "
        "replication, or independent validation is claimed."
    ),
    "allReturnedJobsMustCompleteSuccess": True,
    "zeroSkippedOrCancelledJobs": True,
    "gateReceiptArtifactBytesArchived": False,
    "ciArtifactBytesMustBeArchivedSeparately": True,
    "requiredJobs": [
        {
            "jobName": "Linux x86-64 locked runtime",
            "runnerLabel": "ubuntu-24.04",
            "system": "Linux",
            "machine": "x86_64",
        },
        {
            "jobName": "macOS arm64 clean clone",
            "runnerLabel": "macos-15",
            "system": "Darwin",
            "machine": "arm64",
        },
    ],
}


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


def _validate_unique_strings(
    values: Iterable[str], *, label: str, expected_count: int
) -> list[str]:
    result = list(values)
    if len(result) != expected_count or any(
        not isinstance(value, str) or not value for value in result
    ):
        raise ValueError(
            f"{label} must contain exactly {expected_count} non-empty strings"
        )
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
    if schema == "corelm-blind-crossmodel-v1-snapshot-fixture-v1":
        if not allow_fixture:
            raise ValueError("protocol-control snapshot fixture is forbidden here")
        expected_fixture = {
            "schemaVersion": "corelm-blind-crossmodel-v1-snapshot-fixture-v1",
            "fixtureOnly": True,
            "purpose": "known-answer protocol control; contains no model or corpus evidence",
        }
        if snapshot != expected_fixture:
            raise ValueError("snapshot fixture fields differ")
        return
    if schema != "corelm-blind-crossmodel-v1-snapshot-registration-v1":
        raise ValueError("unexpected snapshot registration schemaVersion")
    expected_fields = {
        "schemaVersion",
        "suiteId",
        "status",
        "designPublicationReceiptSHA256",
        "snapshotReleasePlan",
        "projects",
        "models",
        "ledgers",
        "modelAssetSourceManifestSHA256",
        "fullAssetReceiptSHA256",
        "corpusManifestSHA256",
        "createdAt",
    }
    if set(snapshot) != expected_fields:
        raise ValueError("snapshot registration fields differ")
    if snapshot.get("suiteId") != SUITE_ID:
        raise ValueError("snapshot suiteId differs")
    if snapshot.get("status") != "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION":
        raise ValueError("snapshot is not in the frozen pre-publication state")
    if snapshot.get("projects") != PROJECTS:
        raise ValueError("snapshot projects differ")
    if snapshot.get("models") != MODELS:
        raise ValueError("snapshot models differ")
    expected_release_plan = {
        "tag": "corelm-blind-crossmodel-v1-snapshot",
        "publishNoLaterThan": "2026-08-20T18:00:00Z",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
    }
    if snapshot.get("snapshotReleasePlan") != expected_release_plan:
        raise ValueError("snapshot release plan differs")
    created_at = _parse_utc_seconds(
        snapshot.get("createdAt"), label="snapshot createdAt"
    )
    if created_at < SNAPSHOT_RELEASE_NOT_BEFORE:
        raise ValueError("snapshot was created before the second registered crawl")
    if created_at >= SNAPSHOT_RELEASE_DEADLINE:
        raise ValueError(
            "snapshot was created at or after its registered release deadline"
        )
    ledgers = snapshot.get("ledgers")
    if not isinstance(ledgers, dict) or set(ledgers) != set(PROJECTS):
        raise ValueError("snapshot ledger commitments differ")
    digests = [
        snapshot.get("designPublicationReceiptSHA256"),
        snapshot.get("modelAssetSourceManifestSHA256"),
        snapshot.get("fullAssetReceiptSHA256"),
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
        == "corelm-blind-crossmodel-v1-snapshot-fixture-v1"
    )
    output_value = decode_output_value(output_value_hex)
    project_pool = _validate_unique_strings(
        projects, label="projects", expected_count=len(PROJECTS)
    )
    model_pool = _validate_unique_strings(
        models, label="models", expected_count=len(MODELS)
    )
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
    for _ in range(SELECTED_MODEL_COUNT):
        selected, draw = _select_one(
            model_pool, snapshot_registration_bytes, output_value, draw_index
        )
        selected_models.append(selected)
        draws.append({**draw, "kind": "model", "selected": selected})
        draw_index += 1

    return {
        "schemaVersion": "corelm-blind-crossmodel-v1-selection-v1",
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
    if registration.get("schemaVersion") != "corelm-blind-crossmodel-v1-design-draft-v1":
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
    expected_claim = (
        "One codec candidate fixed before the confirmatory pool and future corpus "
        "are scored meets every registered cell and model gate on three NIST-selected "
        "exact model revisions and two NIST-selected samples of sixteen eligible "
        "future Wikipedia creation revisions."
    )
    expected_scientific_boundary = (
        "A PASS applies only to the three exact revisions selected from the six-revision "
        "confirmatory pool, the thirty-two selected creation revisions, future-corpus "
        "snapshot, selection pulse, candidate, runtime, codec, and fixed metrics. The "
        "exact pool revisions have not been run by this project before the one-shot, "
        "but broad GPT-2, GPT-NeoX/Pythia, and Llama architecture families have prior "
        "observations disclosed in prior-observations.json. This is not an "
        "architecture-blind or population claim about all LLMs, either complete "
        "language-edition corpus, all Wikipedia, all text, latency, throughput, weight "
        "compression, or state of the art. It is author-operated and author-self-verified; "
        "no independent human review, peer review, operator blindness, independent "
        "replication, or independent validation is claimed. The target pulse can be "
        "fetched and the deterministic selection can be derived outside the registered "
        "runner; local state cannot prove that no hidden run occurred. The registered "
        "crawl not-before times permit multiple technically valid corpus roots, and "
        "local code cannot prove that the author did not shop among snapshots; the "
        "signed snapshot release fixes the chosen bytes before the pulse but is not an "
        "externally witnessed first-crawl proof. The anonymous-pipe private-child "
        "handoff establishes only live parent/child, new-process-group, canonical-path, "
        "deadline, poll, nonce, and no-retry bindings. It does not authenticate the "
        "parent implementation or prove watchdog behavior; a custom parent controlled "
        "by the same user can construct a conforming handoff."
    )
    if registration.get("claim") != expected_claim:
        raise ValueError("scientific claim boundary differs")
    if registration.get("scientificBoundary") != expected_scientific_boundary:
        raise ValueError("scientific interpretation boundary differs")
    expected_prior = {
        "path": "blind_v1/prior-observations.json",
        "bytes": 3806,
        "sha256": "411fdc5b5a8e26c1de7e94eb7e146ddd7ae6b9682aeb622fc6783baa4baaa61c",
        "status": "COMPLETE_DISCLOSED_PRIOR_LINEAGE",
    }
    if registration.get("priorObservations") != expected_prior:
        raise ValueError("prior-observation lineage binding differs")
    expected_model_card_evidence = {
        "path": "LICENSES/blind-v1-model-card-evidence.json",
        "bytes": 3421,
        "sha256": "fcee9ffcc88b6fef26d092c29214fd43125f77ee6c1bca9894eedb5cb15bee23",
        "schemaVersion": "corelm-blind-crossmodel-v1-model-card-evidence-v1",
        "cardCount": 6,
        "weightsRedistributed": False,
    }
    if registration.get("modelCardEvidence") != expected_model_card_evidence:
        raise ValueError("model-card evidence binding differs")
    expected_model_weight_layouts = {
        "path": "blind_v1/model-weight-layouts.json",
        "bytes": 83_789,
        "sha256": "cee28426296047d6cccab65866452e747dfdb8ee99ec594f1accd8e792af54a9",
        "schemaVersion": "corelm-blind-crossmodel-v1-model-weight-layouts-v1",
        "modelCount": 6,
        "tensorCount": 1_082,
        "payloadBytesIncluded": False,
    }
    if registration.get("modelWeightLayouts") != expected_model_weight_layouts:
        raise ValueError("model-weight layout binding differs")
    if registration.get("developmentControls") != EXPECTED_DEVELOPMENT_CONTROLS:
        raise ValueError("non-scientific development-control boundary differs")
    expected_design_release = {
        "tag": "corelm-blind-crossmodel-v1-design",
        "publishNoLaterThan": "2026-08-09T00:00:00Z",
        "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
        "signatureType": "SSH",
        "signingKeyFingerprint": "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        "signingPublicKeySHA256": "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274",
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
            "endExclusive": "2026-08-18T00:00:00Z",
        },
        "snapshotPolicy": "union-of-two-complete-archived-recentchanges-crawls",
        "firstCrawlNotBefore": "2026-08-18T06:00:00Z",
        "secondCrawlNotBefore": "2026-08-19T06:00:00Z",
        "minimumEligibleRevisionsPerProject": 64,
        "maximumCanonicalRecordBytes": 8_388_608,
        "pagesSelectedPerCorpus": 16,
        "tokenization": {
            "input": "title + two LF bytes + raw creation-revision wikitext",
            "unicodeNormalization": "none",
            "utf8": "strict",
            "addSpecialTokens": False,
            "minimumTokensUnderEveryRegisteredTokenizer": 512,
        },
        "prospectiveHoldout": {
            "claimType": "PROSPECTIVE_BEACON_SELECTED_HOLDOUT",
            "operatorBlindnessClaimed": False,
            "futureCorpusUnavailableAtDesignFreeze": True,
            "exactSelectionUnavailableUntilTargetPulse": True,
            "preAttemptModelInferenceOnEligibleRecords": (
                "FORBIDDEN_FROM_FIRST_COLLECTION_THROUGH_ATTEMPT_MARKER"
            ),
            "metricOrCandidateTuningUsingEligibleRecords": "FORBIDDEN",
            "permittedPreAttemptProcessing": [
                "collection",
                "eligibility-validation",
                "canonicalization",
                "tokenization-for-minimum-length-only",
                "hashing",
                "packaging",
            ],
            "behavioralComplianceCryptographicallyAttested": False,
        },
        "license": "CC-BY-SA-4.0",
        "attributionLedgerRequired": True,
    }
    if registration.get("futureCorpus") != expected_future_corpus:
        raise ValueError("future corpus boundary differs")
    _validate_unique_strings(
        expected_future_corpus["projects"],
        label="future corpus projects",
        expected_count=len(PROJECTS),
    )
    expected_snapshot_release = {
        "tag": "corelm-blind-crossmodel-v1-snapshot",
        "publishNoLaterThan": "2026-08-20T18:00:00Z",
        "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
        "signatureType": "SSH",
        "signingKeyFingerprint": "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        "signingPublicKeySHA256": "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274",
    }
    if registration.get("snapshotRelease") != expected_snapshot_release:
        raise ValueError("snapshot release boundary differs")
    expected_reservation_release = {
        "tag": "corelm-blind-crossmodel-v1-execution-reservation",
        "publishNotBefore": "2026-08-20T18:00:00Z",
        "publishNoLaterThan": "2026-08-21T17:45:00Z",
        "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
        "signatureType": "SSH",
        "signingKeyFingerprint": "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        "signingPublicKeySHA256": "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274",
        "requiredAssetRoles": [
            "execution-reservation",
            "snapshot-publication-receipt",
            "sha256-manifest",
        ],
        "nonPublicationOrLatePublication": "CONFIRMATORY_CLAIM_UNSUPPORTED",
    }
    if registration.get("reservationRelease") != expected_reservation_release:
        raise ValueError("public execution-reservation boundary differs")
    expected_evidence_release = {
        "tag": "corelm-blind-crossmodel-v1-evidence",
        "publishNoLaterThan": "2026-08-26T18:00:00Z",
        "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
        "signatureType": "SSH",
        "signingKeyFingerprint": "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        "signingPublicKeySHA256": "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274",
    }
    if registration.get("evidenceRelease") != expected_evidence_release:
        raise ValueError("evidence release boundary differs")
    expected_closeout_release = {
        "tag": "corelm-blind-crossmodel-v1-closeout",
        "publishNoLaterThan": "2026-08-30T18:00:00Z",
        "sourcePolicy": "EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE",
        "serverTimestampRequired": True,
        "immutableReleaseRequired": True,
        "signedAnnotatedTagRequired": True,
        "signatureType": "SSH",
        "signingKeyFingerprint": "SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM",
        "signingPublicKeySHA256": "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274",
    }
    if registration.get("closeoutRelease") != expected_closeout_release:
        raise ValueError("closeout release boundary differs")
    expected_reschedule_policy = {
        "decisionCheckpoint": "2026-08-08T12:00:00Z",
        "requiredStateAtCheckpoint": (
            "all pre-publication P0 inputs complete; author self-verification recorded; "
            "exact-commit CI observed through direct verified TLS and archived with no GitHub response "
            "signature and offline structural-consistency-only verification; only immutable "
            "design publication remains"
        ),
        "actionIfNotReady": "DO_NOT_FREEZE_OR_PUBLISH_THIS_SUITE",
        "newSuiteIdRequired": True,
        "minimumLeadTimesMustBePreserved": True,
        "moveTogether": [
            "designRelease.publishNoLaterThan",
            "futureCorpus.creationInterval",
            "futureCorpus.firstCrawlNotBefore",
            "futureCorpus.secondCrawlNotBefore",
            "snapshotRelease.publishNoLaterThan",
            "reservationRelease.publishNotBefore",
            "reservationRelease.publishNoLaterThan",
            "beacon.targetTimestamp",
            "beacon.targetUnixMilliseconds",
            "beacon.pulseEndpoint",
            "execution.oneShotNotBefore",
            "execution.markerNoLaterThan",
            "execution.hardDeadline",
            "evidenceRelease.publishNoLaterThan",
            "closeoutRelease.publishNoLaterThan",
        ],
    }
    if registration.get("reschedulePolicy") != expected_reschedule_policy:
        raise ValueError("whole-window reschedule policy differs")
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
        "python": "3.12.10",
        "primaryPlatform": "macOS-arm64-local-offline",
        "postEvidenceReplication": "NOT_IMPLEMENTED_OR_REGISTERED",
        "pipBootstrapLockSHA256": "587c4946469d33bb2e83b0d34cbe54d0c4c4799896e5af672331e108743f1fca",
        "requirementsLockSHA256": "e731ab2076b171d731b42ee8609d5943954911a10c92564ab52b7bed7a9fa561",
        "status": "UNBOUND_DRAFT",
        "runtimeManifestSHA256": None,
    }
    if runtime != expected_runtime:
        raise ValueError("draft runtime boundary differs")
    if registration.get("continuousIntegration") != EXPECTED_CONTINUOUS_INTEGRATION:
        raise ValueError("continuous integration/review boundary differs")
    models = registration.get("models")
    if not isinstance(models, list) or len(models) != len(MODELS):
        raise ValueError("exactly six confirmatory model specifications are required")
    keys = _validate_unique_strings(
        [model.get("key") for model in models if isinstance(model, dict)],
        label="model keys",
        expected_count=len(MODELS),
    )
    if len(keys) != len(MODELS):
        raise ValueError("model entries are invalid")
    expected_model_fields = {
        "key",
        "repository",
        "revision",
        "architecture",
        "layers",
        "kvHeads",
        "vocabSize",
        "tokenizerVocabSize",
        "weightFile",
        "weightBytes",
        "weightSHA256",
        "license",
        "candidateBitsByLayer",
        "candidateConfigurationSHA256",
        "exactRevisionPreviouslyRun",
        "architectureFamilyPreviouslyObserved",
        "usedForCandidateSelectionOrTuning",
    }
    expected_models = {
        "pythia-160m": {
            "repository": "EleutherAI/pythia-160m",
            "revision": "50f5173d932e8e61f858120bcb800b97af589f46",
            "architecture": "gpt-neox-mha",
            "layers": 12,
            "kvHeads": 12,
            "vocabSize": 50304,
            "tokenizerVocabSize": 50277,
            "weightBytes": 374998696,
            "weightSHA256": "29d2e457a664e41c12c735f20a36dc0956a665f614a54ce5db21a32e75965270",
            "license": "apache-2.0",
        },
        "pythia-70m": {
            "repository": "EleutherAI/pythia-70m",
            "revision": "a39f36b100fe8a5377810d56c3f4789b9c53ac42",
            "architecture": "gpt-neox-mha",
            "layers": 6,
            "kvHeads": 8,
            "vocabSize": 50304,
            "tokenizerVocabSize": 50277,
            "weightBytes": 166029852,
            "weightSHA256": "ebfa4e2f18696ebd83716a0d39fe2c025f2ff8483f72a83ca59c475692fc9d15",
            "license": "apache-2.0",
        },
        "smollm-135m": {
            "repository": "HuggingFaceTB/SmolLM-135M",
            "revision": "1d461723eec654e65efdc40cf49301c89c0c92f4",
            "architecture": "llama-gqa",
            "layers": 30,
            "kvHeads": 3,
            "vocabSize": 49152,
            "tokenizerVocabSize": 49152,
            "weightBytes": 538090408,
            "weightSHA256": "c7a387d6fe81ca6dd304aeb809bda3932ff1bbef3ca41c9484502f2f448dc093",
            "license": "apache-2.0",
        },
        "smollm-360m": {
            "repository": "HuggingFaceTB/SmolLM-360M",
            "revision": "59f7ef243ee09a72cbc14cb054393a3e3b771d41",
            "architecture": "llama-gqa",
            "layers": 32,
            "kvHeads": 5,
            "vocabSize": 49152,
            "tokenizerVocabSize": 49152,
            "weightBytes": 1447317080,
            "weightSHA256": "e91f05d8506ee5efbd8c0fbfc1799c49af2b2f2cce824bc2d801d5af2a716cc2",
            "license": "apache-2.0",
        },
        "gpt2-124m": {
            "repository": "openai-community/gpt2",
            "revision": "607a30d783dfa663caf39e06633721c8d4cfcd7e",
            "architecture": "gpt2-mha",
            "layers": 12,
            "kvHeads": 12,
            "vocabSize": 50257,
            "tokenizerVocabSize": 50257,
            "weightBytes": 548105171,
            "weightSHA256": "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707",
            "license": "mit",
        },
        "distilgpt2-82m": {
            "repository": "distilbert/distilgpt2",
            "revision": "2290a62682d06624634c1f46a6ad5be0f47f38aa",
            "architecture": "gpt2-mha",
            "layers": 6,
            "kvHeads": 12,
            "vocabSize": 50257,
            "tokenizerVocabSize": 50257,
            "weightBytes": 352824413,
            "weightSHA256": "e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b",
            "license": "apache-2.0",
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
        if model.get("usedForCandidateSelectionOrTuning") is not False:
            raise ValueError("blind_v1 model was used for candidate selection or tuning")
        if model.get("exactRevisionPreviouslyRun") is not False:
            raise ValueError("confirmatory exact model revision was previously run")
        if model.get("architectureFamilyPreviouslyObserved") is not True:
            raise ValueError("architecture-family prior observation is not disclosed")
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
        "weightLoadOrder": "verified-owned-bytes->deserialize-owned-state->destroy-weight-bytes->construct-fp32-model->strict-copy",
        "maximumSimultaneousWeightPayloadCopies": 2,
        "weightBytesDestroyedBeforeModelConstruction": True,
        "staticWorstCaseWeightStorageOverlapBytes": 2_894_634_160,
        "supersededTriplePayloadLowerBoundBytes": 4_341_886_040,
        "cacheBaseline": "float32-to-bfloat16-to-float32",
        "attentionImplementation": "eager",
        "prefillTokens": 383,
        "predictionTokensPerPage": 128,
        "modelProcessIsolation": "producer-one-model-per-process; independent verifier loads one model at a time sequentially",
        "acPowerRequired": True,
        "minimumFreeMemoryPercent": 50,
        "maximumWorkerRSSBytes": 4294967296,
        "watchdogPollMilliseconds": 250,
        "workerRSSMeasurement": "sampled aggregate process-group RSS every 250 ms plus one final exit observation; not a kernel RLIMIT; sub-interval peaks may be unobserved",
        "outerSupervisorRequired": True,
        "privateChildHandoff": "one-use-anonymous-pipe-bound-to-live-parent-child-pids-new-process-group-and-canonical-private/result-paths",
        "outerSupervisorIdentityClaim": "none;the-handoff-does-not-authenticate-parent-implementation-or-prove-watchdog-behavior-and-a-custom-same-user-parent-can-reproduce-it",
        "directPrivateExecution": "forbidden-by-protocol;without-a-conforming-inherited-handoff-fails-closed",
        "outerSupervisorPollMilliseconds": 250,
        "minimumFreeDiskBytes": 12884901888,
        "deterministicAlgorithms": "fail-closed",
        "pulseFetchAfterAttemptMarker": True,
        "pulseFetchAuthority": "supervisor-only",
        "pulseFetchTotalTimeoutSeconds": 30,
        "pulseFetchNetworkScope": "one HTTP/1.1 GET transaction to the exact registered NIST endpoint; system DNS may yield multiple addresses and socket.create_connection may attempt only those addresses for that hostname within one total timeout; redirects, proxies, alternate hosts or endpoints, a second GET, and application-level retry or fallback are forbidden",
        "networkAfterPulseSeal": "trusted-supervisor-python-socket-denial; OS-sandbox network denial for registered children",
        "supervisorNetworkIsolationClaim": "trusted-control-flow guard, not OS capability isolation",
        "inferenceChildNetwork": "forbidden-from-process-creation",
        "networkIsolationBackend": "macOS sandbox-exec before Python startup",
        "networkIsolationProfile": "(version 1)(allow default)(deny network*)",
        "pickle": "forbidden",
        "trustRemoteCode": "forbidden",
        "assetReadAfterMarker": "one no-follow read per model evaluation in each registered producer or independent-verifier process from frozen private snapshot into verified anonymous buffers",
        "selectedCorpusRecordReadPolicy": "producer loads model, releases all model-asset byte buffers, then retains exactly one verified canonical selected record at a time",
        "maximumSelectedCorpusRecordsRetainedPerProducer": 1,
        "pathBasedModelParsing": "forbidden",
        "mmap": "forbidden",
        "fromPretrained": "forbidden",
        "independentModelReplay": {
            "requiredForTerminalGateVerdict": True,
            "implementation": "blind_v1/independent_model_replay.py",
            "producerModuleImports": "forbidden",
            "modelOrder": "selection.modelExecutionOrder",
            "modelsSequential": True,
            "device": "cpu",
            "modelDtype": "float32",
            "retokenizeFrozenCorpusBytes": True,
            "baselineCache": "regenerated-float32-to-bfloat16-to-float32",
            "candidateCache": "independently-decode-archived-vtl5-and-bind-inputSha256-to-regenerated-baseline",
            "compareEveryPrediction": True,
            "comparisons": [
                "first512TokenIds",
                "targetTokenId",
                "baselineLossF32Bits",
                "candidateLossF32Bits",
                "baselineTop1TokenId",
                "candidateTop1TokenId",
            ],
            "network": "forbidden-from-process-creation",
            "fixtureBackendScientificUse": "forbidden",
            "bitExactReplayScope": "one-shot host and frozen runtime; archival cross-environment mismatches are failures, never tolerance",
        },
        "attemptStartTimeAuthority": "live NIST HTTPS Date observed over pinned hostname-verified TLS must be inside registered one-shot window; pulse signature does not cover HTTP Date",
        "completionTimeAuthority": "host UTC clock plus process monotonic durations; no external completion attestation",
        "oneShotNotBefore": "2026-08-21T18:00:00Z",
        "markerNoLaterThan": "2026-08-21T18:15:00Z",
        "hardDeadline": "2026-08-22T18:00:00Z",
    }
    if registration.get("execution") != expected_execution:
        raise ValueError("execution boundary differs")
    expected_beacon = {
        "targetTimestamp": "2026-08-21T18:00:00.000Z",
        "targetUnixMilliseconds": 1787335200000,
        "pulseEndpoint": "https://beacon.nist.gov/beacon/2.0/pulse/time/1787335200000",
        "pulseVersion": "2.0",
        "pulseCipherSuite": 0,
        "pulsePeriodMilliseconds": 60000,
        "pulseStatusCode": 0,
        "trustBundleSchemaVersion": NIST_TRUST_BUNDLE_SCHEMA,
        "trustBundleStatus": "CANDIDATE_OFFLINE_TRUST_BUNDLE",
        "candidateOfflineTrustBundleSHA256": (
            NIST_CANDIDATE_TRUST_BUNDLE_SHA256
        ),
        "frozenOfflineTrustBundleSHA256": NIST_FROZEN_TRUST_BUNDLE_SHA256,
        "transportCABundleSHA256": "22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1",
        "offlineTrustBundleSHA256": NIST_CANDIDATE_TRUST_BUNDLE_SHA256,
        "trustBundlePromotionPolicy": (
            "STATUS_ONLY_CANDIDATE_TO_FROZEN_WITH_DUAL_OFFLINE_VERIFICATION"
        ),
        "allowedCertificateIds": [NIST_CERTIFICATE_ID],
        "rotationPolicy": "NO_ROTATION_AFTER_FREEZE",
        "revocationPolicy": "EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK",
        "revocationChecked": False,
        "revocationResidualRisk": NIST_REVOCATION_RESIDUAL_RISK,
        "acceptedLeafExtendedKeyUsages": [
            "1.3.6.1.5.5.7.3.1",
            "1.3.6.1.5.5.7.3.2",
        ],
        "nistTrustRootDERsSHA256": [
            "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
        ],
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
        "modelPoolSize": 6,
        "modelsSelected": 3,
        "selectedModelsWithoutReplacement": True,
        "beaconControlsCorpusPageModelSelectionAndOrder": True,
        "drawOrder": (
            "corpus-A, corpus-B, 16 pages A, 16 pages B, "
            "model-A, model-B, model-C"
        ),
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
        "publicReservationBeforeTargetPulse": True,
        "publicReservationReceiptRequiredBeforeLocalAttempt": True,
        "publicReservationNonpublication": "CONFIRMATORY_CLAIM_UNSUPPORTED",
        "publicAttemptIdDerivation": (
            "20260821T180000Z- + first16hex(SHA-256(canonical reservation JSON "
            "before attemptId and reservationContentSHA256))"
        ),
        "attemptReservationBeforeMarker": True,
        "attemptMarkerBeforeSelectionOrSelectedDataOpen": True,
        "atomicStatePublication": (
            "exclusive-pending-file-fsync-hardlink-directory-fsync-"
            "unlink-directory-fsync"
        ),
        "phaseOrder": [
            "verify-public-execution-reservation-receipt",
            "preflight-seal-assets",
            "pre-marker-networkless-locked-runtime-import-probe",
            "durable-attempt-reservation",
            "durable-attempt-marker",
            "supervisor-fetch-and-verify-exact-nist-pulse",
            "seal-pulse-and-install-scoped-supervisor-socket-denial",
            "derive-selection",
            "spawn-networkless-inference-workers-in-registered-order",
            "consolidate-worker-evidence",
            "publish-producer-result",
            "publish-producer-evidence-manifest",
            "spawn-networkless-independent-verifier",
            "require-independent-real-model-replay-and-exact-result-match",
            "publish-terminal-outcome",
        ],
        "durablePulseSealBeforeSelection": True,
        "networklessChildStartsAfterPulseSeal": True,
        "retryAfterReservation": "forbidden",
        "retryAfterMarker": "forbidden",
        "terminalStates": [
            "PASS",
            "FAIL_GATES",
            "FAIL_EXECUTION",
            "CONSUMED_INCOMPLETE",
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


def validate_frozen_design_registration(registration: Any) -> list[str]:
    """Validate the frozen lifecycle plus every lifecycle-independent field.

    The prospective and frozen documents intentionally share one normative
    design body.  We first fail closed on every frozen-only binding, then
    normalize only those lifecycle fields into their draft forms and reuse the
    exhaustive draft-body validator.  No scientific parameter is normalized.
    """

    if not isinstance(registration, dict):
        raise ValueError("design registration must be an object")
    if set(registration) != EXPECTED_TOP_LEVEL_FIELDS:
        raise ValueError("design registration top-level fields differ")
    if registration.get("schemaVersion") != "corelm-blind-crossmodel-v1-design-v1":
        raise ValueError("unexpected frozen design schemaVersion")
    if registration.get("status") != "PUBLIC_DESIGN_FROZEN":
        raise ValueError("design is not in the public frozen state")
    if registration.get("readyToFreeze") is not True:
        raise ValueError("frozen design does not declare readiness")
    if registration.get("countsTowardScientificVerdict") is not False:
        raise ValueError("design registration must not itself claim a verdict")
    if registration.get("freezeBlockers") != []:
        raise ValueError("frozen design must have an empty blocker list")

    controls = registration.get("developmentControls")
    gate = controls.get("realDataE2EFreezeGate") if isinstance(controls, dict) else None
    if not isinstance(gate, dict) or set(gate) != set(
        EXPECTED_DEVELOPMENT_CONTROLS["realDataE2EFreezeGate"]
    ):
        raise ValueError("frozen real-data E2E gate fields differ")
    fixed_gate = {
        key: value
        for key, value in EXPECTED_DEVELOPMENT_CONTROLS[
            "realDataE2EFreezeGate"
        ].items()
        if key
        not in {
            "status",
            "executionId",
            "archiveReceiptSHA256",
            "archivePublishedAt",
            "archiveAttestedAt",
            "releaseAttestationBundleSHA256",
            "releaseAttestationOutputSHA256",
            "reportSHA256",
            "artifactSetSHA256",
            "controlConfigurationSHA256",
            "completedAt",
        }
    }
    if any(gate.get(key) != value for key, value in fixed_gate.items()):
        raise ValueError("frozen real-data E2E gate contract differs")
    if gate.get("status") != "ARCHIVED_VERIFIED_BEFORE_FREEZE":
        raise ValueError("frozen real-data E2E gate is not complete")
    if not isinstance(gate.get("executionId"), str) or re.fullmatch(
        r"development-execution-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}",
        gate["executionId"],
    ) is None:
        raise ValueError("frozen real-data E2E execution identity is invalid")

    lab = registration.get("labSource")
    runtime = registration.get("runtime")
    beacon = registration.get("beacon")
    if not isinstance(lab, dict) or lab.get("status") != "FROZEN_BOUND":
        raise ValueError("frozen lab source binding is absent")
    if not isinstance(runtime, dict) or runtime.get("status") != "FROZEN_BOUND":
        raise ValueError("frozen runtime binding is absent")
    if not isinstance(beacon, dict):
        raise ValueError("frozen beacon binding is absent")
    if (
        beacon.get("trustBundleSchemaVersion") != NIST_TRUST_BUNDLE_SCHEMA
        or beacon.get("trustBundleStatus")
        != "FROZEN_OFFLINE_TRUST_BUNDLE"
        or beacon.get("candidateOfflineTrustBundleSHA256")
        != NIST_CANDIDATE_TRUST_BUNDLE_SHA256
        or beacon.get("frozenOfflineTrustBundleSHA256")
        != NIST_FROZEN_TRUST_BUNDLE_SHA256
        or beacon.get("offlineTrustBundleSHA256")
        != NIST_FROZEN_TRUST_BUNDLE_SHA256
    ):
        raise ValueError("frozen NIST trust lifecycle binding differs")

    def require_hex(value: Any, width: int, label: str) -> None:
        if not isinstance(value, str) or re.fullmatch(
            rf"[0-9a-f]{{{width}}}", value
        ) is None:
            raise ValueError(f"frozen {label} is invalid")

    require_hex(lab.get("commit"), 40, "lab commit")
    require_hex(lab.get("tree"), 40, "lab tree")
    require_hex(lab.get("freezeManifestSHA256"), 64, "lab freeze manifest")
    require_hex(runtime.get("runtimeManifestSHA256"), 64, "runtime manifest")
    require_hex(
        gate.get("archiveReceiptSHA256"),
        64,
        "development-control archive receipt",
    )
    require_hex(
        gate.get("releaseAttestationBundleSHA256"),
        64,
        "development-control release attestation bundle",
    )
    require_hex(
        gate.get("releaseAttestationOutputSHA256"),
        64,
        "development-control release attestation output",
    )
    require_hex(gate.get("reportSHA256"), 64, "development-control report")
    require_hex(
        gate.get("artifactSetSHA256"),
        64,
        "development-control artifact set",
    )
    require_hex(
        gate.get("controlConfigurationSHA256"),
        64,
        "development-control configuration",
    )
    completed_at = gate.get("completedAt")
    if not isinstance(completed_at, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", completed_at
    ) is None:
        raise ValueError("frozen development-control completion time is invalid")
    try:
        completed_time = datetime.strptime(
            completed_at, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError(
            "frozen development-control completion time is invalid"
        ) from error
    if completed_time >= DESIGN_RELEASE_DEADLINE:
        raise ValueError("frozen development control missed the design deadline")
    archive_times: dict[str, datetime] = {}
    for field, label in (
        ("archivePublishedAt", "publication"),
        ("archiveAttestedAt", "attestation"),
    ):
        value = gate.get(field)
        if not isinstance(value, str) or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
        ) is None:
            raise ValueError(
                f"frozen development archive {label} time is invalid"
            )
        try:
            archive_times[field] = datetime.strptime(
                value, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as error:
            raise ValueError(
                f"frozen development archive {label} time is invalid"
            ) from error
    if (
        archive_times["archivePublishedAt"] < completed_time
        or archive_times["archivePublishedAt"]
        > archive_times["archiveAttestedAt"]
        or archive_times["archiveAttestedAt"] >= DESIGN_RELEASE_DEADLINE
    ):
        raise ValueError("frozen development archive timing differs")
    require_hex(beacon.get("transportCABundleSHA256"), 64, "transport CA bundle")
    require_hex(beacon.get("offlineTrustBundleSHA256"), 64, "offline trust bundle")
    roots = beacon.get("nistTrustRootDERsSHA256")
    if not isinstance(roots, list) or not roots or len(set(roots)) != len(roots):
        raise ValueError("frozen NIST trust-root pins are invalid")
    for root in roots:
        require_hex(root, 64, "NIST trust-root DER")
    for field in (
        "designRelease",
        "snapshotRelease",
        "reservationRelease",
        "evidenceRelease",
        "closeoutRelease",
    ):
        release = registration.get(field)
        if not isinstance(release, dict):
            raise ValueError(f"frozen {field} is absent")
        fingerprint = release.get("signingKeyFingerprint")
        if (
            release.get("signedAnnotatedTagRequired") is not True
            or release.get("signatureType") != "SSH"
            or not isinstance(fingerprint, str)
            or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None
        ):
            raise ValueError(f"frozen {field} signing identity is invalid")
        require_hex(
            release.get("signingPublicKeySHA256"),
            64,
            f"{field} signing public key",
        )

    normalized = copy.deepcopy(registration)
    normalized["schemaVersion"] = "corelm-blind-crossmodel-v1-design-draft-v1"
    normalized["status"] = "DRAFT_NOT_PREREGISTERED"
    normalized["readyToFreeze"] = False
    normalized["freezeBlockers"] = ["frozen-lifecycle-validation-sentinel"]
    normalized["labSource"].update(
        status="UNBOUND_DRAFT",
        commit=None,
        tree=None,
        freezeManifestSHA256=None,
    )
    normalized["runtime"].update(
        status="UNBOUND_DRAFT",
        runtimeManifestSHA256=None,
    )
    normalized["developmentControls"]["realDataE2EFreezeGate"] = copy.deepcopy(
        EXPECTED_DEVELOPMENT_CONTROLS["realDataE2EFreezeGate"]
    )
    normalized["beacon"].update(
        trustBundleStatus="CANDIDATE_OFFLINE_TRUST_BUNDLE",
        transportCABundleSHA256="22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1",
        offlineTrustBundleSHA256=NIST_CANDIDATE_TRUST_BUNDLE_SHA256,
    )
    release_identities: list[tuple[str, str]] = []
    for field in (
        "designRelease",
        "snapshotRelease",
        "reservationRelease",
        "evidenceRelease",
        "closeoutRelease",
    ):
        release_identities.append(
            (
                registration[field]["signingKeyFingerprint"],
                registration[field]["signingPublicKeySHA256"],
            )
        )
    if len(set(release_identities)) != 1:
        raise ValueError("all frozen release plans must use one signing identity")
    validate_design_registration(normalized)
    return []


def validate_design_registration_lifecycle(registration: Any) -> list[str]:
    """Dispatch to the only two permitted design lifecycle states."""

    if not isinstance(registration, dict):
        raise ValueError("design registration must be an object")
    identity = (registration.get("schemaVersion"), registration.get("status"))
    if identity == (
        "corelm-blind-crossmodel-v1-design-draft-v1",
        "DRAFT_NOT_PREREGISTERED",
    ):
        return validate_design_registration(registration)
    if identity == (
        "corelm-blind-crossmodel-v1-design-v1",
        "PUBLIC_DESIGN_FROZEN",
    ):
        return validate_frozen_design_registration(registration)
    raise ValueError("design schemaVersion/status lifecycle pair differs")


def validate_model_asset_manifest(
    manifest: Any, registration: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("model asset manifest must be an object")
    if manifest.get("schemaVersion") != "corelm-blind-crossmodel-v1-model-assets-draft-v1":
        raise ValueError("unexpected model asset manifest schemaVersion")
    if (
        manifest.get("status")
        != "DRAFT_OFFICIAL_METADATA_PINNED_LOCAL_FULL_REHASH_REQUIRED"
    ):
        raise ValueError("unexpected model asset manifest status")
    if manifest.get("completeRuntimeFileList") is not True:
        raise ValueError("runtime file list must be complete")
    if manifest.get("smallRuntimeFilesContentHashed") is not False:
        raise ValueError("draft must not claim local small-file verification")
    if manifest.get("fullSafetensorsBytesLocallyVerified") is not False:
        raise ValueError("draft must not claim local full-weight verification")
    if manifest.get("scientificModelInferencePerformed") is not False:
        raise ValueError("confirmatory model inference must not occur before pulse")
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
        "model.safetensors",
        "tokenizer.json",
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
            else:
                content_hashed_files += 1
    return {
        "models": len(models),
        "runtimeFiles": len(models) * len(required_files),
        "smallFilesPinnedByDigest": content_hashed_files,
        "smallFilesContentHashedLocally": False,
        "fullSafetensorsBytesLocallyVerified": False,
    }


def validate_development_model_asset_manifest(
    manifest: Any, registration: dict[str, Any]
) -> dict[str, Any]:
    """Validate the separately bound, confirmatory-excluded pilot assets.

    These models may be used for real-data development E2E. They are never
    members of the six-revision confirmatory pool and cannot contribute to the
    scientific verdict.
    """

    if not isinstance(manifest, dict):
        raise ValueError("development model asset manifest must be an object")
    if (
        manifest.get("schemaVersion")
        != "corelm-blind-crossmodel-v1-development-model-assets-v1"
        or manifest.get("status")
        != "PINNED_EXCLUDED_PILOT_MODELS_FOR_DEVELOPMENT_CONTROLS"
    ):
        raise ValueError("development model asset manifest identity differs")
    if (
        manifest.get("countsTowardScientificVerdict") is not False
        or manifest.get("excludedFromConfirmatoryPool") is not True
        or manifest.get("modelInferenceScope")
        != "NON_SCIENTIFIC_DEVELOPMENT_CONTROLS_ONLY"
    ):
        raise ValueError("development model scientific boundary differs")
    if (
        manifest.get("completeRuntimeFileList") is not True
        or manifest.get("smallRuntimeFilesContentHashed") is not True
        or manifest.get("fullSafetensorsBytesLocallyVerified") is not False
        or manifest.get("weightsRedistributed") is not False
    ):
        raise ValueError("development model asset verification state differs")
    forbidden = manifest.get("forbiddenFormats")
    if not isinstance(forbidden, list) or "pytorch_model.bin" not in forbidden:
        raise ValueError("development model unsafe formats are not forbidden")

    binding = registration["developmentControls"]["modelAssets"]
    expected_keys = binding["modelKeys"]
    models = manifest.get("models")
    if not isinstance(models, dict) or list(models) != expected_keys:
        raise ValueError("development model asset order differs")
    confirmatory_keys = {item["key"] for item in registration["models"]}
    if confirmatory_keys.intersection(models):
        raise ValueError("development and confirmatory model pools overlap")

    expected_files = {
        "config.json",
        "generation_config.json",
        "merges.txt",
        "model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    }
    file_count = 0
    total_bytes = 0
    for key, model in models.items():
        if not isinstance(model, dict):
            raise ValueError(f"invalid development model entry: {key}")
        if not re.fullmatch(r"[0-9a-f]{40}", str(model.get("revision", ""))):
            raise ValueError(f"development model revision is not immutable: {key}")
        files = model.get("files")
        if not isinstance(files, dict) or set(files) != expected_files:
            raise ValueError(f"development model runtime files differ: {key}")
        for filename, item in files.items():
            if (
                not isinstance(item, dict)
                or type(item.get("bytes")) is not int
                or item["bytes"] < 1
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
            ):
                raise ValueError(f"invalid development asset: {key}/{filename}")
            expected_source = (
                "official-lfs-pointer-not-yet-locally-rehashed"
                if filename == "model.safetensors"
                else "downloaded-content"
            )
            if item.get("digestSource") != expected_source:
                raise ValueError(f"development asset digest source differs: {key}/{filename}")
            file_count += 1
            total_bytes += item["bytes"]
    return {
        "models": len(models),
        "runtimeFiles": file_count,
        "totalBytes": total_bytes,
        "countsTowardScientificVerdict": False,
    }
