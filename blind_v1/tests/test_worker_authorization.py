from __future__ import annotations

import copy
import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blind_v1 import model_worker
from blind_v1.protocol import canonical_json_bytes, sha256_bytes
from blind_v1.runner import (
    _open_worker_authorization_pipe,
    _worker_authorization,
)
import blind_v1.runner as runner_module
from blind_v1.state_machine import create_attempt_marker


SUITE_ID = "corelm-blind-crossmodel-v1"
ATTEMPT_ID = "20260821T180000Z-0123456789abcdef"
MODEL_KEY = "pythia-160m"
SNAPSHOT_REGISTRATION_SHA256 = "a" * 64


def _write_canonical(path: Path, value: dict[str, object]) -> bytes:
    raw = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _authorization_fixture(root: Path) -> dict[str, object]:
    private_root = root / "private"
    (private_root / "codec").mkdir(parents=True)
    private_manifest = {
        "schemaVersion": "corelm-blind-crossmodel-v1-private-snapshot-manifest-v1",
        "suiteId": SUITE_ID,
        "status": "SEALED_BEFORE_ATTEMPT",
        "snapshotRegistrationSHA256": SNAPSHOT_REGISTRATION_SHA256,
    }
    private_manifest_raw = _write_canonical(
        private_root / "private-snapshot-manifest.json", private_manifest
    )

    result_root = root / "result.one-shot-result"
    create_attempt_marker(
        result_root,
        suite_id=SUITE_ID,
        attempt_id=ATTEMPT_ID,
        design_sha256="1" * 64,
        snapshot_registration_sha256=SNAPSHOT_REGISTRATION_SHA256,
        design_publication_receipt_sha256="2" * 64,
        snapshot_publication_receipt_sha256="3" * 64,
        private_snapshot_manifest_sha256=sha256_bytes(private_manifest_raw),
        runtime_manifest_sha256="4" * 64,
        model_asset_source_manifest_sha256="5" * 64,
        full_asset_receipt_sha256="6" * 64,
        github_gate_receipt_sha256="7" * 64,
        corpus_manifest_sha256="8" * 64,
        codec_commit="1" * 40,
        codec_tree="2" * 40,
        lab_commit="3" * 40,
        lab_tree="4" * 40,
        created_at="2026-08-21T18:00:00Z",
    )
    corpora = ["de.wikipedia.org", "en.wikipedia.org"]
    selection = {
        "schemaVersion": "corelm-blind-crossmodel-v1-selection-v1",
        "suiteId": SUITE_ID,
        "snapshotRegistrationSHA256": SNAPSHOT_REGISTRATION_SHA256,
        "nistOutputValue": "00" * 64,
        "selectedCorpora": corpora,
        "selectedPages": {
            corpora[0]: [{"revid": 1001}],
            corpora[1]: [{"revid": 2001}],
        },
        "modelExecutionOrder": [MODEL_KEY],
        "draws": [],
    }
    _write_canonical(result_root / "selection.json", selection)
    job = {
        "schemaVersion": model_worker.SCIENTIFIC_JOB_SCHEMA,
        "suiteId": SUITE_ID,
        "attemptId": ATTEMPT_ID,
        "countsTowardScientificVerdict": True,
        "model": {"key": MODEL_KEY},
        "selectedCorpora": corpora,
        "pages": {
            corpora[0]: [{"pageRevisionId": 1001}],
            corpora[1]: [{"pageRevisionId": 2001}],
        },
    }
    job_path = result_root / "jobs" / f"{MODEL_KEY}.json"
    _write_canonical(job_path, job)
    output_root = result_root / "workers" / MODEL_KEY
    authorization = _worker_authorization(
        private_root=private_root,
        result_root=result_root,
        job_path=job_path,
        output_root=output_root,
        job=job,
        selection=selection,
        model_key=MODEL_KEY,
        attempt=ATTEMPT_ID,
    )
    return {
        "private_root": private_root,
        "result_root": result_root,
        "job_path": job_path,
        "output_root": output_root,
        "job": job,
        "authorization": authorization,
    }


def _verify(fixture: dict[str, object], authorization: dict[str, object]) -> None:
    descriptor = _open_worker_authorization_pipe(authorization)
    model_worker.verify_scientific_authorization(
        descriptor,
        job=fixture["job"],
        job_path=fixture["job_path"],
        snapshot_root=fixture["private_root"],
        codec_root=fixture["private_root"] / "codec",
        output_root=fixture["output_root"],
    )


class ScientificWorkerAuthorizationTests(unittest.TestCase):
    def test_runner_pipe_authorizes_exact_post_marker_selection_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _authorization_fixture(Path(temporary))
            _verify(fixture, fixture["authorization"])

    def test_scientific_run_without_capability_stops_before_model_inputs(self) -> None:
        job = {"schemaVersion": model_worker.SCIENTIFIC_JOB_SCHEMA}
        with (
            mock.patch.object(model_worker, "load_json_strict", return_value=job),
            mock.patch.object(model_worker, "validate_job"),
            mock.patch.object(model_worker, "load_frozen_inputs") as load_inputs,
            self.assertRaisesRegex(model_worker.WorkerError, "authorization FD"),
        ):
            model_worker.run(
                Path("arbitrary-job.json"),
                Path("arbitrary-snapshot"),
                Path("arbitrary-codec"),
                Path("arbitrary-output"),
            )
        load_inputs.assert_not_called()

    def test_regular_file_descriptor_is_not_a_capability(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            descriptor = os.dup(handle.fileno())
            with self.assertRaisesRegex(model_worker.WorkerError, "pipe capability"):
                model_worker._read_authorization_pipe(descriptor)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_every_bound_identity_fails_closed_on_mismatch(self) -> None:
        replacements = {
            "suiteId": "wrong-suite",
            "attemptId": "20260821T180000Z-ffffffffffffffff",
            "attemptMarkerSHA256": "f" * 64,
            "selectionSHA256": "f" * 64,
            "jobSHA256": "f" * 64,
            "modelKey": "pythia-70m",
            "snapshotRegistrationSHA256": "f" * 64,
            "privateSnapshotManifestSHA256": "f" * 64,
            "canonicalJobPath": "/tmp/wrong-job.json",
            "canonicalSnapshotRoot": "/tmp/wrong-snapshot",
            "canonicalCodecRoot": "/tmp/wrong-codec",
            "canonicalOutputRoot": "/tmp/wrong-output",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = _authorization_fixture(Path(temporary))
                authorization = copy.deepcopy(fixture["authorization"])
                authorization[field] = replacement
                with self.assertRaises(model_worker.WorkerError):
                    _verify(fixture, authorization)

    def test_post_authorization_file_change_is_rejected(self) -> None:
        targets = ("attempt-marker.json", "selection.json")
        for filename in targets:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                fixture = _authorization_fixture(Path(temporary))
                path = fixture["result_root"] / filename
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(model_worker.WorkerError):
                    _verify(fixture, fixture["authorization"])
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _authorization_fixture(Path(temporary))
            path = fixture["job_path"]
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaises(model_worker.WorkerError):
                _verify(fixture, fixture["authorization"])

    def test_runner_passes_only_ephemeral_fd_to_scientific_worker(self) -> None:
        source = inspect.getsource(runner_module._run_workers)
        self.assertIn('"--authorization-fd"', source)
        self.assertIn("pass_fds=(authorization_fd,)", source)
        self.assertIn("os.close(authorization_fd)", source)
        self.assertNotIn("authorization.json", source)


if __name__ == "__main__":
    unittest.main()
