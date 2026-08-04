from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import types
import unittest
import sys
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import Mock, patch

from v2 import independent_verifier_core as independent_subject
from v2 import evidence as producer_evidence
from v2 import nist_beacon as producer_nist
from v2 import protocol as producer_protocol
from v2.independent_verifier_core import (
    IndependentVerificationError,
    canonical_json_bytes,
    canonical_nist_verification_bytes,
    decode_float32_bits,
    derive_selection,
    evaluate_evidence,
    extract_ledger_token_commitments,
    load_independent_trust_bundle,
    validate_worker_job,
    verify_nist_response,
    verify_page_token_bindings,
)
from v2.mediawiki_snapshot import ArchivedHTTPResponse
from v2.github_gate_receipt import verify_github_gate_receipt
from v2.state_machine import create_attempt_marker
from v2.tests.test_evidence import (
    ATTEMPT,
    BITS,
    CORPORA,
    LAYERS,
    MODELS,
    SUITE,
    evidence_fixture,
    page_token_fixture,
)
from v2.tests.test_github_gate_receipt import (
    COMMIT as GATE_COMMIT,
    HTML_BASE as GATE_HTML_BASE,
    REPOSITORY as GATE_REPOSITORY,
    _base_bodies as gate_base_bodies,
    _collect as collect_gate_fixture,
    _expected as expected_gate,
)
from v2.verify_evidence import (
    HOST_ENVIRONMENT_PATH,
    verify_github_gate_binding,
    verify_host_environment,
)


V2_ROOT = Path(__file__).resolve().parents[1]
SELECTION_VECTOR = V2_ROOT / "test-vectors" / "selection-v1.json"
NIST_VECTOR = V2_ROOT / "test-vectors" / "nist-chain1-pulse1.json"
NIST_PEM = V2_ROOT / "test-vectors" / "nist-chain1-cert.pem"


def _pem_to_der_without_producer(pem: bytes) -> bytes:
    text = pem.decode("ascii")
    payload = text.split("-----BEGIN CERTIFICATE-----", 1)[1].split(
        "-----END CERTIFICATE-----", 1
    )[0]
    return base64.b64decode("".join(payload.split()), validate=True)


def _commitment(path: str, raw: bytes, *, sha512: bool) -> dict[str, object]:
    value: dict[str, object] = {
        "relativePath": path,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if sha512:
        value["sha512"] = hashlib.sha512(raw).hexdigest()
    return value


def _nist_fixture(root: Path):
    vector = json.loads(NIST_VECTOR.read_text(encoding="utf-8"))
    pem = NIST_PEM.read_bytes()
    der = _pem_to_der_without_producer(pem)
    certificate_id = hashlib.sha512(der).hexdigest()
    (root / "leaf.pem").write_bytes(pem)
    (root / "leaf.der").write_bytes(der)
    manifest = {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-nist-trust-bundle-v1",
        "status": "KNOWN_ANSWER_FIXTURE_ONLY",
        "fixtureOnly": True,
        "certificates": {
            certificate_id: {
                "chainPolicy": "fixture-leaf-pin-only",
                "pem": _commitment("leaf.pem", pem, sha512=False),
                "chain": [_commitment("leaf.der", der, sha512=True)],
            }
        },
    }
    manifest_path = root / "trust.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    milliseconds = vector["requestUnixMilliseconds"]
    pulse_time = datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    body = canonical_json_bytes(vector["pulseResponse"])
    request_uri = "https://beacon.nist.gov/beacon/2.0/pulse/time/" + str(milliseconds)
    headers = (
        "HTTP/1.1 200 OK\r\n"
        f"Date: {format_datetime(pulse_time + timedelta(seconds=1), usegmt=True)}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return vector, manifest_path, pulse_time, request_uri, headers, body


def _valid_worker_job() -> dict[str, object]:
    digest = "a" * 64
    files = {
        name: {"path": f"models/model-a/{name}", "bytes": 1, "sha256": digest}
        for name in {
            "config.json", "generation_config.json", "merges.txt",
            "model.safetensors", "special_tokens_map.json", "tokenizer.json",
            "tokenizer_config.json", "vocab.json",
        }
    }
    corpora = ["de.wikipedia.org", "fr.wikipedia.org"]
    pages = {
        corpus: [
            {
                "pageSelectionIndex": index,
                "pageRevisionId": offset + index,
                "recordPath": f"records/{corpus}/{offset + index}.bin",
                "recordBytes": 1,
                "recordSHA256": digest,
            }
            for index in range(16)
        ]
        for corpus, offset in zip(corpora, (1000, 2000))
    }
    return {
        "schemaVersion": "corelm-crossmodel-livewiki-v2-worker-job-v1",
        "suiteId": "corelm-voidtoken-crossmodel-livewiki-v2",
        "attemptId": "20260828T180000Z-0123456789abcdef",
        "countsTowardScientificVerdict": True,
        "model": {
            "key": "model-a", "files": files, "layers": 3, "vocabSize": 1024,
            "candidateBitsByLayer": [9, 9, 8],
        },
        "selectedCorpora": corpora,
        "pages": pages,
        "candidate": {
            "backend": "voidtoken-v5", "groupSize": 128,
            "transformBlockSize": 128, "codeCompression": "zlib-9",
            "scaleCompression": "zlib-9", "signMode": "none",
        },
        "seed": 0,
    }


def _full_ledgers_from_page_fixture(
    page_tokens: list[dict[str, object]], corpora: list[str]
) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {corpus: [] for corpus in corpora}
    for page in page_tokens:
        digest = page["first512StreamSHA256"]
        result[page["corpusProject"]].append(
            {
                "project": page["corpusProject"],
                "revid": page["pageRevisionId"],
                "tokenizers": {
                    "model-a": {
                        "tokenCount": 512,
                        "vocabSize": page["vocabSize"],
                        "completeStreamSHA256": digest,
                        "first512StreamSHA256": digest,
                    }
                },
            }
        )
    return result


def _materialize_bound_container_fixture(
    root: Path, containers: list[dict[str, object]]
) -> tuple[list[dict[str, object]], Path]:
    codec_root = root / "codec"
    package = codec_root / "RealLLM"
    package.mkdir(parents=True)
    (package / "codecs.py").write_text(
        '"""Known-answer codec dependency placeholder."""\n', encoding="utf-8"
    )
    (package / "voidtoken_v5.py").write_text(
        "import json\n"
        "from types import SimpleNamespace\n"
        "class VoidTokenV5Backend:\n"
        "    @classmethod\n"
        "    def from_bytes(cls, raw):\n"
        "        metadata = json.loads(raw.decode('utf-8'))\n"
        "        return SimpleNamespace(container=raw, metadata=metadata)\n",
        encoding="utf-8",
    )
    materialized: list[dict[str, object]] = []
    for original in containers:
        record = dict(original)
        metadata = {
            "layerIndex": record["layerIndex"],
            "bits": BITS[record["modelKey"]][record["layerIndex"]],
            "groupSize": 128,
            "transformBlockSize": 128,
            "codeCompression": "zlib-9",
            "scaleCompression": "zlib-9",
            "signMode": "none",
            "shape": [383, 128],
        }
        raw = canonical_json_bytes(metadata)
        destination = root / record["relativePath"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        record["denseBF16Bytes"] = 383 * 128 * 2
        record["containerBytes"] = len(raw)
        record["containerSHA256"] = hashlib.sha256(raw).hexdigest()
        materialized.append(record)
    return materialized, codec_root


class IndependentVerifierDifferentialTests(unittest.TestCase):
    def test_selection_matches_committed_known_answer_and_producer(self) -> None:
        vector = json.loads(SELECTION_VECTOR.read_text(encoding="utf-8"))
        snapshot = canonical_json_bytes(vector["snapshotRegistration"])
        independent = derive_selection(
            snapshot, vector["nistOutputValue"], projects=vector["projects"],
            models=vector["models"], ledgers=vector["ledgers"],
            allow_known_answer_fixture=True,
        )
        producer = producer_protocol.resolve_selection(
            snapshot, vector["nistOutputValue"], projects=vector["projects"],
            models=vector["models"], ledgers=vector["ledgers"], allow_fixture=True,
        )
        self.assertEqual(independent, producer)
        self.assertEqual(independent["selectedCorpora"], vector["expectedSelectedCorpora"])
        self.assertEqual(independent["modelExecutionOrder"], vector["expectedModelExecutionOrder"])
        self.assertEqual(hashlib.sha256(canonical_json_bytes(independent)).hexdigest(), vector["expectedSelectionSHA256"])

    def test_page_binding_and_metrics_match_producer(self) -> None:
        fixture = page_token_fixture()
        page_tokens, raw_page, models, corpora, vocabs, revisions, ledger = fixture
        independent_binding = verify_page_token_bindings(
            page_tokens, raw_page, suite_id=SUITE, attempt_id=ATTEMPT,
            models=models, corpora=corpora, vocabulary_sizes=vocabs,
            selected_revisions=revisions, ledger_token_commitments=ledger,
        )
        producer_binding = producer_evidence.verify_page_token_evidence(
            page_tokens, raw_page, suite_id=SUITE, attempt_id=ATTEMPT,
            models=models, corpora=corpora, vocabulary_sizes=vocabs,
            selected_revisions=revisions, ledger_token_commitments=ledger,
        )
        self.assertEqual(independent_binding, producer_binding)
        full_ledgers = _full_ledgers_from_page_fixture(page_tokens, corpora)
        self.assertEqual(
            extract_ledger_token_commitments(
                full_ledgers, models=models, vocabulary_sizes=vocabs,
                selected_revisions=revisions,
            ),
            producer_evidence.selected_ledger_token_commitments(
                full_ledgers, models=models, vocabulary_sizes=vocabs,
                selected_revisions=revisions,
            ),
        )
        raw, containers = evidence_fixture(mismatches_in_first_cell=3)
        with self.assertRaisesRegex(
            IndependentVerificationError, "byte-level container replay"
        ):
            evaluate_evidence(
                raw, containers, suite_id=SUITE, attempt_id=ATTEMPT,
                models=MODELS, corpora=CORPORA, layer_counts=LAYERS,
                bits_by_model=BITS,
            )
        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = Path(temporary)
            containers, codec_root = _materialize_bound_container_fixture(
                evidence_root, containers
            )
            independent = evaluate_evidence(
                raw, containers, suite_id=SUITE, attempt_id=ATTEMPT,
                models=MODELS, corpora=CORPORA, layer_counts=LAYERS,
                bits_by_model=BITS, evidence_root=evidence_root,
                codec_root=codec_root,
            )
            producer = producer_evidence.evaluate_raw_evidence(
                raw, containers, suite_id=SUITE, attempt_id=ATTEMPT,
                models=MODELS, corpora=CORPORA, layer_counts=LAYERS,
                bits_by_model=BITS,
            )
            self.assertEqual(independent, producer)

    def test_official_nist_known_answer_matches_producer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vector, manifest, pulse_time, uri, headers, body = _nist_fixture(Path(temporary))
            bundle = load_independent_trust_bundle(
                manifest, expected_time=pulse_time,
                expected_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                allow_known_answer_fixture=True,
            )
            independent = verify_nist_response(
                request_uri=uri, response_headers=headers, response_body=body,
                trust_bundle=bundle,
                expected_unix_milliseconds=vector["requestUnixMilliseconds"],
                allow_known_answer_fixture=True,
            )
            producer_bundle = producer_nist.load_offline_trust_bundle(
                manifest, expected_time=pulse_time,
                expected_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                allow_fixture=True,
            )
            producer = producer_nist.verify_nist_pulse_response(
                response=ArchivedHTTPResponse(uri, 200, headers, body),
                trust_bundle=producer_bundle,
                expected_unix_milliseconds=vector["requestUnixMilliseconds"],
                allow_fixture=True,
            )
            self.assertEqual(independent, producer)
            self.assertEqual(independent["outputValue"], vector["expectedOutputValue"])
            self.assertEqual(canonical_nist_verification_bytes(independent), canonical_json_bytes(independent))

    def test_normative_nist_chain_root_and_current_profile_are_independent(self) -> None:
        manifest = V2_ROOT / "trust" / "nist" / "manifest.json"
        bundle = load_independent_trust_bundle(
            manifest,
            expected_time=datetime(2026, 8, 27, 18, tzinfo=timezone.utc),
            expected_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            expected_root_der_sha256=[
                "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
            ],
        )
        self.assertFalse(bundle.fixture_only)
        record = next(iter(bundle.records.values()))
        self.assertTrue(record.chain_verified)
        self.assertEqual(record.chain[-1].der_sha256, independent_subject.REGISTERED_NIST_TRUST_ROOT_DER_SHA256)
        self.assertEqual(record.leaf.dns_names, ("engine.beacon.nist.gov",))
        vector = json.loads(NIST_VECTOR.read_text(encoding="utf-8"))
        pulse = dict(vector["pulseResponse"]["pulse"])
        pulse["version"] = "2.0"
        current = independent_subject._unsigned_pulse(
            pulse, expected_version=independent_subject.REGISTERED_PULSE_VERSION
        )
        self.assertTrue(current)
        with self.assertRaisesRegex(
            IndependentVerificationError, "version/profile"
        ):
            independent_subject._unsigned_pulse(
                pulse,
                expected_version=independent_subject.HISTORICAL_FIXTURE_PULSE_VERSION,
            )
        with self.assertRaisesRegex(
            IndependentVerificationError, "registered public root"
        ):
            load_independent_trust_bundle(
                manifest,
                expected_time=datetime(2026, 8, 27, 18, tzinfo=timezone.utc),
                expected_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                expected_root_der_sha256=["0" * 64],
            )

    def test_scientific_paths_are_unaffected_by_monkeypatched_producer(self) -> None:
        vector = json.loads(SELECTION_VECTOR.read_text(encoding="utf-8"))
        snapshot = canonical_json_bytes(vector["snapshotRegistration"])
        page_tokens, raw_page, models, corpora, vocabs, revisions, ledger = page_token_fixture()
        full_ledgers = _full_ledgers_from_page_fixture(page_tokens, corpora)
        raw, containers = evidence_fixture()
        poison = IndependentVerificationError("producer path was invoked")
        patches = [
            patch.object(producer_protocol, "resolve_selection", side_effect=poison),
            patch.object(producer_protocol, "evaluate_model_aggregate", side_effect=poison),
            patch.object(producer_evidence, "evaluate_raw_evidence", side_effect=poison),
            patch.object(producer_evidence, "evaluate_model_aggregate", side_effect=poison),
            patch.object(producer_evidence, "float32_from_bits", side_effect=poison),
            patch.object(producer_evidence, "selected_ledger_token_commitments", side_effect=poison),
            patch.object(producer_evidence, "verify_page_token_evidence", side_effect=poison),
            patch.object(producer_nist, "load_offline_trust_bundle", side_effect=poison),
            patch.object(producer_nist, "verify_nist_pulse_response", side_effect=poison),
            patch.object(producer_nist, "canonical_verification_bytes", side_effect=poison),
        ]
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        self.assertEqual(decode_float32_bits("3fa00000", label="known"), 1.25)
        fake_worker = types.ModuleType("v2.model_worker")
        fake_worker.validate_job = Mock(side_effect=poison)
        with patch.dict(sys.modules, {"v2.model_worker": fake_worker}):
            validate_worker_job(_valid_worker_job())
        fake_worker.validate_job.assert_not_called()
        self.assertEqual(
            derive_selection(
                snapshot, vector["nistOutputValue"], projects=vector["projects"],
                models=vector["models"], ledgers=vector["ledgers"],
                allow_known_answer_fixture=True,
            )["selectedCorpora"],
            vector["expectedSelectedCorpora"],
        )
        self.assertEqual(
            verify_page_token_bindings(
                page_tokens, raw_page, suite_id=SUITE, attempt_id=ATTEMPT,
                models=models, corpora=corpora, vocabulary_sizes=vocabs,
                selected_revisions=revisions, ledger_token_commitments=ledger,
            )["pages"], 32,
        )
        self.assertEqual(
            len(
                extract_ledger_token_commitments(
                    full_ledgers, models=models, vocabulary_sizes=vocabs,
                    selected_revisions=revisions,
                )
            ),
            32,
        )
        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = Path(temporary)
            containers, codec_root = _materialize_bound_container_fixture(
                evidence_root, containers
            )
            fake_package = types.ModuleType("RealLLM")
            fake_voidtoken = types.ModuleType("RealLLM.voidtoken_v5")
            fake_voidtoken.VoidTokenV5Backend = Mock()
            with patch.dict(
                sys.modules,
                {
                    "RealLLM": fake_package,
                    "RealLLM.voidtoken_v5": fake_voidtoken,
                },
            ):
                self.assertIn(
                    evaluate_evidence(
                        raw, containers, suite_id=SUITE, attempt_id=ATTEMPT,
                        models=MODELS, corpora=CORPORA, layer_counts=LAYERS,
                        bits_by_model=BITS, evidence_root=evidence_root,
                        codec_root=codec_root,
                    )["verdict"],
                    {"PASS", "FAIL_GATES"},
                )
            fake_voidtoken.VoidTokenV5Backend.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            nist_vector, manifest, pulse_time, uri, headers, body = _nist_fixture(
                Path(temporary)
            )
            bundle = load_independent_trust_bundle(
                manifest,
                expected_time=pulse_time,
                expected_manifest_sha256=hashlib.sha256(
                    manifest.read_bytes()
                ).hexdigest(),
                allow_known_answer_fixture=True,
            )
            nist_result = verify_nist_response(
                request_uri=uri,
                response_headers=headers,
                response_body=body,
                trust_bundle=bundle,
                expected_unix_milliseconds=nist_vector[
                    "requestUnixMilliseconds"
                ],
                allow_known_answer_fixture=True,
            )
            self.assertEqual(
                nist_result["outputValue"], nist_vector["expectedOutputValue"]
            )

    def test_module_has_no_producer_scientific_import(self) -> None:
        source = (V2_ROOT / "independent_verifier_core.py").read_text(encoding="utf-8")
        for forbidden in (
            "from v2.evidence", "from v2.protocol", "from v2.nist_beacon",
            "from v2.model_worker", "from v2.mediawiki_snapshot",
        ):
            self.assertNotIn(forbidden, source)

    def test_host_environment_requires_exact_closed_execution_map(self) -> None:
        marker = {
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v2",
            "createdAt": "2026-08-28T18:00:00Z",
            "runtimeManifestSHA256": "1" * 64,
        }
        execution = {
            "maximumWorkerRSSBytes": 4_294_967_296,
            "watchdogPollMilliseconds": 250,
            "minimumFreeDiskBytes": 1_000_000,
            "minimumFreeMemoryPercent": 20,
            "networkIsolationBackend": "sandbox-exec",
            "networkIsolationProfile": "(version 1) (deny default)",
            "intraOpThreads": 2,
        }
        environment = {
            "HF_DATASETS_OFFLINE": "1", "HF_HUB_OFFLINE": "1", "LANG": "C",
            "LC_ALL": "C", "MKL_NUM_THREADS": "2", "NO_PROXY": "*",
            "NUMEXPR_NUM_THREADS": "2", "OMP_NUM_THREADS": "2",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1", "TOKENIZERS_PARALLELISM": "false",
            "TRANSFORMERS_OFFLINE": "1", "VECLIB_MAXIMUM_THREADS": "2",
            "no_proxy": "*",
        }
        record = {
            "schemaVersion": "corelm-crossmodel-livewiki-v2-host-environment-v1",
            "suiteId": marker["suiteId"], "observedAt": marker["createdAt"],
            "system": "Darwin", "machine": "arm64", "osProductVersion": "15.6",
            "osBuildVersion": "24G84", "kernelRelease": "24.6.0",
            "kernelVersion": "Darwin Kernel Version 24.6.0", "cpuBrand": "Apple M3",
            "logicalCPUCount": 8, "physicalMemoryBytes": 16_000_000_000,
            "pythonVersion": "3.12.10", "pythonExecutableSHA256": "2" * 64,
            "effectiveExecutionEnvironment": environment, "acPower": True,
            "freeMemoryPercent": 50, "freeDiskBytes": 2_000_000,
            "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
            "maximumWorkerRSSBytes": execution["maximumWorkerRSSBytes"],
            "watchdogPollMilliseconds": execution["watchdogPollMilliseconds"],
            "minimumFreeDiskBytes": execution["minimumFreeDiskBytes"],
            "networkSandbox": {
                "backend": execution["networkIsolationBackend"],
                "executablePath": "/usr/bin/sandbox-exec", "executableBytes": 1,
                "executableSHA256": "3" * 64,
                "profile": execution["networkIsolationProfile"],
            },
            "countsTowardScientificVerdict": True,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / HOST_ENVIRONMENT_PATH
            target.parent.mkdir()
            target.write_bytes(canonical_json_bytes(record) + b"\n")
            self.assertEqual(
                verify_host_environment(root, marker=marker, design={"execution": execution}),
                record,
            )
            record["effectiveExecutionEnvironment"] = {
                **environment, "HTTPS_PROXY": "http://forbidden.invalid"
            }
            target.write_bytes(canonical_json_bytes(record) + b"\n")
            with self.assertRaisesRegex(
                producer_evidence.EvidenceError, "effective execution"
            ):
                verify_host_environment(root, marker=marker, design={"execution": execution})

    def test_github_gate_is_replayed_against_freeze_review_and_ci(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary)
            gate_raw = collect_gate_fixture(private_root, gate_base_bodies())
            verified = verify_github_gate_receipt(gate_raw, **expected_gate())
            bindings = private_root / "bindings"
            bindings.mkdir()
            gate_path = bindings / "github-gate-receipt.json"
            gate_path.write_bytes(gate_raw)
            gate_sha = hashlib.sha256(gate_raw).hexdigest()
            marker = create_attempt_marker(
                private_root / "attempt-state",
                suite_id="corelm-voidtoken-crossmodel-livewiki-v2",
                attempt_id="20260828T180000Z-0123456789abcdef",
                design_sha256="8" * 64,
                snapshot_registration_sha256="9" * 64,
                design_publication_receipt_sha256="a" * 64,
                snapshot_publication_receipt_sha256="b" * 64,
                private_snapshot_manifest_sha256="c" * 64,
                runtime_manifest_sha256="1" * 64,
                model_asset_source_manifest_sha256="d" * 64,
                full_asset_receipt_sha256="2" * 64,
                github_gate_receipt_sha256=gate_sha,
                corpus_manifest_sha256="e" * 64,
                codec_commit="4" * 40,
                codec_tree="5" * 40,
                lab_commit=GATE_COMMIT,
                lab_tree="3" * 40,
                created_at="2026-08-28T18:00:00Z",
            )
            design = {
                "suiteId": "corelm-voidtoken-crossmodel-livewiki-v2",
                "labSource": {
                    "repository": GATE_HTML_BASE + ".git",
                    "commit": GATE_COMMIT,
                    "tree": "3" * 40,
                    "freezeManifestSHA256": None,
                },
                "codecSource": {
                    "repository": "https://github.com/ALLPROTO/core-lm-benchmark.git",
                    "commit": "4" * 40,
                    "tree": "5" * 40,
                },
                "beacon": {
                    "transportCABundleSHA256": "6" * 64,
                    "offlineTrustBundleSHA256": "7" * 64,
                },
            }
            review = {
                "pullRequestURL": f"{GATE_HTML_BASE}/pull/{verified.pull_request_number}",
                "pullRequestNumber": verified.pull_request_number,
                "approvedReview": {
                    "id": verified.review_id,
                    "reviewerLogin": verified.reviewer_login,
                    "state": "APPROVED",
                    "commitSHA": verified.implementation_commit,
                    "submittedAt": verified.review_submitted_at,
                },
            }
            ci = {
                "runURL": f"{GATE_HTML_BASE}/actions/runs/{verified.workflow_run_id}",
                "runId": verified.workflow_run_id,
                "workflowId": verified.workflow_id,
                "workflowName": verified.workflow_name,
                "workflowPath": verified.workflow_path,
                "status": "completed", "conclusion": "success",
                "headSHA": verified.implementation_commit,
                "allJobsCompletedSuccess": True,
                "zeroSkippedOrCancelledJobs": True,
                "jobIds": list(verified.job_ids),
                "linuxJobIds": list(verified.linux_job_ids),
                "macOSArm64JobIds": list(verified.macos_arm64_job_ids),
                "artifactSHA256": [
                    {"name": name, "sha256": digest}
                    for name, digest in verified.artifact_sha256
                ],
                "gateFirstServerDate": verified.first_server_date,
                "gateLastServerDate": verified.last_server_date,
            }
            freeze = {
                "schemaVersion": "corelm-crossmodel-livewiki-v2-freeze-manifest-v1",
                "status": "IMPLEMENTATION_FREEZE_READY_FOR_DESIGN_BINDING",
                "suiteId": design["suiteId"],
                "countsTowardScientificVerdict": False,
                "freezeProcedure": {
                    "implementationStage": "REVIEWED_GREEN_IMPLEMENTATION_COMMIT",
                    "manifestStage": "CANONICAL_MANIFEST_GENERATED_OUTSIDE_IMPLEMENTATION_TREE",
                    "designBindingStage": "FROZEN_DESIGN_BINDS_EXACT_MANIFEST_FILE_SHA256",
                    "designBindingField": "labSource.freezeManifestSHA256",
                    "designBindingDigest": "sha256(canonical-json-with-contentSHA256-plus-terminal-LF)",
                    "implementationMutationAfterManifest": "FORBIDDEN",
                    "manifestContainsOwnFileSHA256": False,
                },
                "implementation": {
                    "repository": design["labSource"]["repository"],
                    "commit": design["labSource"]["commit"],
                    "tree": design["labSource"]["tree"],
                },
                "codec": {
                    "repository": design["codecSource"]["repository"],
                    "commit": design["codecSource"]["commit"],
                    "tree": design["codecSource"]["tree"],
                },
                "artifacts": {
                    "runtimeManifestSHA256": marker["runtimeManifestSHA256"],
                    "fullAssetReceiptSHA256": marker["fullAssetReceiptSHA256"],
                    "transportCABundleSHA256": design["beacon"]["transportCABundleSHA256"],
                    "offlineTrustBundleSHA256": design["beacon"]["offlineTrustBundleSHA256"],
                    "githubGateReceiptSHA256": gate_sha,
                },
                "review": review, "continuousIntegration": ci,
                "createdAt": "2026-08-03T12:10:00Z",
            }

            def write_freeze() -> tuple[bytes, dict[str, object]]:
                unsigned = dict(freeze)
                unsigned.pop("contentSHA256", None)
                freeze["contentSHA256"] = hashlib.sha256(
                    canonical_json_bytes(unsigned)
                ).hexdigest()
                raw = canonical_json_bytes(freeze) + b"\n"
                (bindings / "freeze-manifest.json").write_bytes(raw)
                design["labSource"]["freezeManifestSHA256"] = hashlib.sha256(raw).hexdigest()
                private_manifest = {
                    "githubGateReceiptSHA256": gate_sha,
                    "files": [
                        {
                            "path": "bindings/freeze-manifest.json",
                            "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "role": "freeze-manifest",
                        },
                        {
                            "path": "bindings/github-gate-receipt.json",
                            "bytes": len(gate_raw),
                            "sha256": gate_sha,
                            "role": "github-gate-receipt",
                        },
                    ],
                }
                return raw, private_manifest

            _, private_manifest = write_freeze()
            self.assertEqual(
                verify_github_gate_binding(
                    private_root, private_manifest, marker=marker, design=design
                ),
                gate_sha,
            )
            freeze["continuousIntegration"]["conclusion"] = "failure"
            _, private_manifest = write_freeze()
            with self.assertRaisesRegex(
                producer_evidence.EvidenceError, "review/CI prose"
            ):
                verify_github_gate_binding(
                    private_root, private_manifest, marker=marker, design=design
                )


if __name__ == "__main__":
    unittest.main()
