from __future__ import annotations

import json
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from v2.state_machine import (
    ATTEMPT_FILENAME,
    ATTEMPT_PENDING_FILENAME,
    OUTCOME_FILENAME,
    OUTCOME_PENDING_FILENAME,
    RESERVATION_FILENAME,
    StateMachineError,
    canonical_json_bytes,
    classify_local_state,
    create_attempt_marker,
    create_terminal_outcome,
    load_attempt_marker,
    load_attempt_reservation,
    load_terminal_outcome,
    sha256_bytes,
)


DIGEST = "1" * 64
ATTEMPT = "20260828T180000Z-0123456789abcdef"


def _race_attempt(root: str, queue: multiprocessing.Queue) -> None:
    try:
        marker = create_attempt_marker(
            Path(root),
            suite_id="corelm-voidtoken-crossmodel-livewiki-v2",
            attempt_id=ATTEMPT,
            design_sha256=DIGEST,
            snapshot_registration_sha256=DIGEST,
            design_publication_receipt_sha256=DIGEST,
            snapshot_publication_receipt_sha256=DIGEST,
            private_snapshot_manifest_sha256=DIGEST,
            runtime_manifest_sha256=DIGEST,
            model_asset_source_manifest_sha256=DIGEST,
            full_asset_receipt_sha256=DIGEST,
            github_gate_receipt_sha256=DIGEST,
            corpus_manifest_sha256=DIGEST,
            codec_commit="1" * 40,
            codec_tree="2" * 40,
            lab_commit="3" * 40,
            lab_tree="4" * 40,
            created_at="2026-08-28T18:00:00Z",
        )
        queue.put(("created", marker["attemptId"]))
    except StateMachineError:
        queue.put(("rejected", None))


class StateMachineTests(unittest.TestCase):
    def marker(self, root: Path) -> dict[str, object]:
        return create_attempt_marker(
            root,
            suite_id="corelm-voidtoken-crossmodel-livewiki-v2",
            attempt_id=ATTEMPT,
            design_sha256="1" * 64,
            snapshot_registration_sha256="2" * 64,
            design_publication_receipt_sha256="7" * 64,
            snapshot_publication_receipt_sha256="8" * 64,
            private_snapshot_manifest_sha256="3" * 64,
            runtime_manifest_sha256="3" * 64,
            model_asset_source_manifest_sha256="4" * 64,
            full_asset_receipt_sha256="5" * 64,
            github_gate_receipt_sha256="9" * 64,
            corpus_manifest_sha256="6" * 64,
            codec_commit="1" * 40,
            codec_tree="2" * 40,
            lab_commit="3" * 40,
            lab_tree="4" * 40,
            created_at="2026-08-28T18:00:00Z",
        )

    def test_marker_is_exclusive_canonical_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = self.marker(root)
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")
            self.assertEqual(load_attempt_marker(root), marker)
            reservation = load_attempt_reservation(root)
            self.assertIsNotNone(reservation)
            assert reservation is not None
            self.assertEqual(reservation["attemptId"], marker["attemptId"])
            self.assertEqual(marker["githubGateReceiptSHA256"], "9" * 64)
            self.assertEqual(
                reservation["githubGateReceiptSHA256"],
                marker["githubGateReceiptSHA256"],
            )
            self.assertFalse(reservation["countsTowardScientificVerdict"])
            self.assertTrue((root / RESERVATION_FILENAME).is_file())
            raw = (root / ATTEMPT_FILENAME).read_bytes()
            self.assertTrue(raw.endswith(b"\n"))
            with self.assertRaises(StateMachineError):
                self.marker(root)

    def test_system_temporary_alias_supports_a_new_result_root(self) -> None:
        # macOS exposes /tmp as a fixed /private/tmp alias.  The secure
        # component walker must normalize that one system alias without ever
        # relaxing its no-follow policy for caller-controlled components.
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary) / "result"
            marker = self.marker(root)
            self.assertEqual(load_attempt_marker(root), marker)
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")

    def test_marker_without_durable_reservation_is_never_loadable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            (root / RESERVATION_FILENAME).unlink()
            with self.assertRaisesRegex(
                StateMachineError, "without its durable attempt reservation"
            ):
                load_attempt_marker(root)
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")

    def test_terminal_outcome_requires_marker_and_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(StateMachineError):
                create_terminal_outcome(
                    root,
                    terminal_state="FAIL_EXECUTION",
                    result_sha256=None,
                    evidence_manifest_sha256=None,
                    independent_verifier_sha256=None,
                    failure_reason="no marker",
                )
            self.marker(root)
            outcome = create_terminal_outcome(
                root,
                terminal_state="FAIL_EXECUTION",
                result_sha256=None,
                evidence_manifest_sha256=None,
                independent_verifier_sha256=None,
                failure_reason="worker crashed",
                completed_at="2026-08-28T18:01:00Z",
            )
            self.assertEqual(load_terminal_outcome(root), outcome)
            self.assertEqual(classify_local_state(root), "FAIL_EXECUTION")
            self.assertTrue((root / OUTCOME_FILENAME).exists())
            with self.assertRaises(StateMachineError):
                create_terminal_outcome(
                    root,
                    terminal_state="PASS",
                    result_sha256="7" * 64,
                    evidence_manifest_sha256="5" * 64,
                    independent_verifier_sha256="6" * 64,
                )

    def test_pass_requires_evidence_and_verifier_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            with self.assertRaises(StateMachineError):
                create_terminal_outcome(
                    root,
                    terminal_state="PASS",
                    result_sha256=None,
                    evidence_manifest_sha256=None,
                    independent_verifier_sha256=None,
                )

    def test_marker_rejects_noncanonical_suite_and_attempt_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = {
                "result_root": root,
                "suite_id": "wrong-suite",
                "attempt_id": ATTEMPT,
                "design_sha256": DIGEST,
                "snapshot_registration_sha256": DIGEST,
                "design_publication_receipt_sha256": DIGEST,
                "snapshot_publication_receipt_sha256": DIGEST,
                "private_snapshot_manifest_sha256": DIGEST,
                "runtime_manifest_sha256": DIGEST,
                "model_asset_source_manifest_sha256": DIGEST,
                "full_asset_receipt_sha256": DIGEST,
                "github_gate_receipt_sha256": DIGEST,
                "corpus_manifest_sha256": DIGEST,
                "codec_commit": "1" * 40,
                "codec_tree": "2" * 40,
                "lab_commit": "3" * 40,
                "lab_tree": "4" * 40,
                "created_at": "2026-08-28T18:00:00Z",
            }
            with self.assertRaisesRegex(StateMachineError, "suite_id"):
                create_attempt_marker(**arguments)
            arguments["suite_id"] = "corelm-voidtoken-crossmodel-livewiki-v2"
            arguments["attempt_id"] = "attempt-fixture-only"
            with self.assertRaisesRegex(StateMachineError, "attempt_id"):
                create_attempt_marker(**arguments)
            arguments["attempt_id"] = ATTEMPT
            arguments["created_at"] = "2026-08-28T17:59:59Z"
            with self.assertRaisesRegex(StateMachineError, "one-shot window"):
                create_attempt_marker(**arguments)

    def test_terminal_outcome_cannot_predate_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            with self.assertRaisesRegex(StateMachineError, "precedes"):
                create_terminal_outcome(
                    root,
                    terminal_state="FAIL_EXECUTION",
                    result_sha256=None,
                    evidence_manifest_sha256=None,
                    independent_verifier_sha256=None,
                    failure_reason="clock-order fixture",
                    completed_at="2026-08-28T17:59:59Z",
                )

    def test_gate_outcome_must_be_durable_strictly_before_hard_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            with self.assertRaisesRegex(StateMachineError, "hard execution deadline"):
                create_terminal_outcome(
                    root,
                    terminal_state="PASS",
                    result_sha256="7" * 64,
                    evidence_manifest_sha256="5" * 64,
                    independent_verifier_sha256="6" * 64,
                    completed_at="2026-08-29T18:00:00Z",
                )
            outcome = create_terminal_outcome(
                root,
                terminal_state="FAIL_EXECUTION",
                result_sha256=None,
                evidence_manifest_sha256=None,
                independent_verifier_sha256=None,
                failure_reason="hard deadline crossed before gate outcome was durable",
                completed_at="2026-08-29T18:00:01Z",
            )
            self.assertEqual(outcome["terminalState"], "FAIL_EXECUTION")
            self.assertFalse(outcome["countsTowardScientificVerdict"])

    def test_symlink_result_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            real = parent / "real"
            real.mkdir()
            link = parent / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(StateMachineError):
                self.marker(link)

    def test_tampered_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            raw = (root / ATTEMPT_FILENAME).read_bytes()
            (root / ATTEMPT_FILENAME).write_bytes(raw.replace(b"STARTED", b"STOPPED"))
            with self.assertRaises(StateMachineError):
                load_attempt_marker(root)

    def test_two_processes_cannot_create_two_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            queue: multiprocessing.Queue = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(target=_race_attempt, args=(temporary, queue))
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)
            outcomes = sorted(queue.get(timeout=2)[0] for _ in range(2))
            self.assertEqual(outcomes, ["created", "rejected"])

    def test_every_marker_publication_crash_is_consumed_and_forensic(self) -> None:
        stages = (
            "pending-created",
            "payload-written",
            "file-fsynced",
            "final-linked",
            "directory-fsynced",
            "pending-unlinked",
            "cleanup-directory-fsynced",
        )
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = f"{ATTEMPT_FILENAME}:{stage}"

                def crash(observed: str) -> None:
                    if observed == target:
                        raise RuntimeError("simulated process crash")

                with mock.patch("v2.state_machine._fault_injection", side_effect=crash):
                    with self.assertRaisesRegex(RuntimeError, "simulated process crash"):
                        self.marker(root)
                self.assertIsNotNone(load_attempt_reservation(root))
                self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")
                self.assertTrue(
                    (root / ATTEMPT_PENDING_FILENAME).exists()
                    or (root / ATTEMPT_FILENAME).exists()
                )
                with self.assertRaises(StateMachineError):
                    self.marker(root)

    def test_every_outcome_publication_crash_preserves_raw_transition(self) -> None:
        stages = (
            "pending-created",
            "payload-written",
            "file-fsynced",
            "final-linked",
            "directory-fsynced",
            "pending-unlinked",
            "cleanup-directory-fsynced",
        )
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.marker(root)
                target = f"{OUTCOME_FILENAME}:{stage}"

                def crash(observed: str) -> None:
                    if observed == target:
                        raise RuntimeError("simulated process crash")

                with mock.patch("v2.state_machine._fault_injection", side_effect=crash):
                    with self.assertRaisesRegex(RuntimeError, "simulated process crash"):
                        create_terminal_outcome(
                            root,
                            terminal_state="FAIL_EXECUTION",
                            result_sha256=None,
                            evidence_manifest_sha256=None,
                            independent_verifier_sha256=None,
                            failure_reason="fault-injection fixture",
                            completed_at="2026-08-28T18:01:00Z",
                        )
                self.assertTrue(
                    (root / OUTCOME_PENDING_FILENAME).exists()
                    or (root / OUTCOME_FILENAME).exists()
                )
                expected = "FAIL_EXECUTION" if index >= 3 else "CONSUMED_INCOMPLETE"
                self.assertEqual(classify_local_state(root), expected)

    def test_every_reservation_publication_crash_blocks_marker_and_retry(self) -> None:
        stages = (
            "pending-created",
            "payload-written",
            "file-fsynced",
            "final-linked",
            "directory-fsynced",
            "pending-unlinked",
            "cleanup-directory-fsynced",
            "published",
        )
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = f"{RESERVATION_FILENAME}:{stage}"

                def crash(observed: str) -> None:
                    if observed == target:
                        raise RuntimeError("simulated process crash")

                with mock.patch("v2.state_machine._fault_injection", side_effect=crash):
                    with self.assertRaisesRegex(RuntimeError, "simulated process crash"):
                        self.marker(root)
                self.assertFalse((root / ATTEMPT_FILENAME).exists())
                expected = (
                    "PRECOMMIT_INCOMPLETE" if index < 3 else "CONSUMED_INCOMPLETE"
                )
                self.assertEqual(classify_local_state(root), expected)
                with self.assertRaises(StateMachineError):
                    self.marker(root)

    def test_partial_legacy_final_files_fail_closed_after_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = f"{ATTEMPT_FILENAME}:pending-created"

            def crash(observed: str) -> None:
                if observed == target:
                    raise RuntimeError("simulated process crash")

            with mock.patch("v2.state_machine._fault_injection", side_effect=crash):
                with self.assertRaises(RuntimeError):
                    self.marker(root)
            (root / ATTEMPT_FILENAME).write_bytes(b'{"partial":')
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")

    def test_canonical_but_non_schema_state_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = self.marker(root)
            marker["unexpected"] = "must not be accepted"
            unsigned = dict(marker)
            unsigned.pop("markerContentSHA256")
            marker["markerContentSHA256"] = sha256_bytes(
                canonical_json_bytes(unsigned)
            )
            (root / ATTEMPT_FILENAME).write_bytes(
                canonical_json_bytes(marker) + b"\n"
            )
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.marker(root)
            create_terminal_outcome(
                root,
                terminal_state="FAIL_EXECUTION",
                result_sha256=None,
                evidence_manifest_sha256=None,
                independent_verifier_sha256=None,
                failure_reason="fixture",
                completed_at="2026-08-28T18:01:00Z",
            )
            outcome = json.loads((root / OUTCOME_FILENAME).read_bytes())
            outcome["unexpected"] = "must not be accepted"
            (root / OUTCOME_FILENAME).write_bytes(
                canonical_json_bytes(outcome) + b"\n"
            )
            self.assertEqual(classify_local_state(root), "CONSUMED_INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
