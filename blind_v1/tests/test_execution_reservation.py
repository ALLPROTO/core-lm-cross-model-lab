from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from blind_v1.package_execution_reservation import (
    ASSET_NAMES,
    ExecutionReservationError,
    HARD_DEADLINE,
    MARKER_NO_LATER_THAN,
    ONE_SHOT_NOT_BEFORE,
    OUTCOME_OBLIGATION,
    RESERVATION_SCHEMA,
    SUITE_ID,
    TARGET_ENDPOINT,
    TARGET_PULSE,
    _file_binding,
    _manifest,
    canonical_json_bytes,
    derive_public_attempt_id,
    sha256_bytes,
    verify_execution_reservation_package,
)


class ExecutionReservationTests(unittest.TestCase):
    def _package(
        self, root: Path, *, reserved_at: str = "2026-08-21T17:00:00Z"
    ) -> dict[str, object]:
        design_raw = b'{"frozen":true}\n'
        snapshot_raw = b'{"snapshot":true}\n'
        receipt_raw = b'{"kind":"snapshot"}\n'
        reservation = {
            "schemaVersion": RESERVATION_SCHEMA,
            "suiteId": SUITE_ID,
            "status": "PUBLIC_EXECUTION_RESERVED",
            "reservedAt": reserved_at,
            "targetPulseTimestamp": TARGET_PULSE,
            "targetPulseEndpoint": TARGET_ENDPOINT,
            "oneShotNotBefore": ONE_SHOT_NOT_BEFORE,
            "markerNoLaterThan": MARKER_NO_LATER_THAN,
            "hardDeadline": HARD_DEADLINE,
            "designRegistration": _file_binding(design_raw),
            "snapshotRegistration": _file_binding(snapshot_raw),
            "snapshotPublicationReceipt": _file_binding(receipt_raw),
            "codecSource": {
                "repository": "https://example.invalid/codec.git",
                "commit": "1" * 40,
                "tree": "2" * 40,
            },
            "labSource": {
                "repository": "https://example.invalid/lab.git",
                "commit": "3" * 40,
                "tree": "4" * 40,
            },
            "candidateRuleSHA256": "5" * 64,
            "confirmatoryModels": [
                {
                    "key": f"model-{index}",
                    "repository": f"owner/model-{index}",
                    "revision": f"{index + 1:x}" * 40,
                    "weightSHA256": f"{index + 6:x}" * 64,
                }
                for index in range(6)
            ],
            "outcomeObligation": OUTCOME_OBLIGATION,
            "retryPermitted": False,
            "countsTowardScientificVerdict": False,
        }
        reservation["attemptId"] = derive_public_attempt_id(reservation)
        reservation["reservationContentSHA256"] = sha256_bytes(
            canonical_json_bytes(reservation)
        )
        reservation_raw = canonical_json_bytes(reservation) + b"\n"
        manifest_raw = canonical_json_bytes(
            _manifest(reservation_raw, receipt_raw)
        ) + b"\n"
        root.mkdir()
        (root / ASSET_NAMES["execution-reservation"]).write_bytes(reservation_raw)
        (root / ASSET_NAMES["snapshot-publication-receipt"]).write_bytes(
            receipt_raw
        )
        (root / ASSET_NAMES["sha256-manifest"]).write_bytes(manifest_raw)
        return reservation

    def test_package_verifies_without_selection_or_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "reservation"
            reservation = self._package(root)
            result = verify_execution_reservation_package(root)
            self.assertEqual(
                result["status"],
                "VERIFIED_EXECUTION_RESERVATION_RELEASE_ASSETS",
            )
            self.assertFalse(result["networkUsed"])
            self.assertFalse(result["modelInferenceUsed"])
            self.assertFalse(result["selectionDerived"])
            self.assertEqual(result["attemptId"], reservation["attemptId"])
            self.assertEqual(result["markerNoLaterThan"], MARKER_NO_LATER_THAN)

    def test_attempt_identity_is_content_derived_and_cannot_be_substituted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "reservation"
            reservation = self._package(root)
            attempt_id = reservation["attemptId"]
            self.assertIsInstance(attempt_id, str)
            self.assertTrue(attempt_id.startswith("20260821T180000Z-"))

            reservation["attemptId"] = "20260821T180000Z-0000000000000000"
            unsigned = dict(reservation)
            unsigned.pop("reservationContentSHA256")
            reservation["reservationContentSHA256"] = sha256_bytes(
                canonical_json_bytes(unsigned)
            )
            reservation_raw = canonical_json_bytes(reservation) + b"\n"
            receipt_raw = (root / ASSET_NAMES["snapshot-publication-receipt"]).read_bytes()
            (root / ASSET_NAMES["execution-reservation"]).write_bytes(reservation_raw)
            (root / ASSET_NAMES["sha256-manifest"]).write_bytes(
                canonical_json_bytes(_manifest(reservation_raw, receipt_raw)) + b"\n"
            )
            with self.assertRaisesRegex(
                ExecutionReservationError, "protocol boundary differs"
            ):
                verify_execution_reservation_package(root)

    def test_late_local_reservation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "reservation"
            self._package(root, reserved_at="2026-08-21T17:45:00Z")
            with self.assertRaisesRegex(
                ExecutionReservationError, "outside the registered pre-pulse window"
            ):
                verify_execution_reservation_package(root)

    def test_tampered_reservation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "reservation"
            self._package(root)
            path = root / ASSET_NAMES["execution-reservation"]
            path.write_bytes(path.read_bytes().replace(b"model-0", b"model-X"))
            with self.assertRaisesRegex(
                ExecutionReservationError, "self-digest|manifest differs"
            ):
                verify_execution_reservation_package(root)


if __name__ == "__main__":
    unittest.main()
