from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blind_v1.collect_empty_result_root import (
    AUDIT_REPORT_NAME,
    OBSERVATION_NAME,
    _historical_collect_to_directory as collect_to_directory,
)
from blind_v1.experiment_closeout import (
    ExperimentCloseoutError,
    validate_empty_result_root_audit_report,
    validate_empty_result_root_observation,
)


class EmptyResultRootCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.result_root = self.root / "result"
        self.result_root.mkdir()
        self.environment = self.root / "environment.json"
        self.environment.write_bytes(b'{"host":"exact test host"}\n')

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_collects_exact_empty_inventory_and_supporting_bytes(self) -> None:
        times = iter(("2026-08-22T18:00:00Z", "2026-08-22T18:00:01Z"))
        output = self.root / "audit"
        with patch("blind_v1.collect_empty_result_root._utc_now", side_effect=lambda: next(times)):
            observation_path, report_path = collect_to_directory(
                result_root=self.result_root,
                host_environment_path=self.environment,
                auditor_identity="unit independent observer",
                output_directory=output,
            )
        self.assertEqual(observation_path.name, OBSERVATION_NAME)
        self.assertEqual(report_path.name, AUDIT_REPORT_NAME)
        self.assertEqual(
            set(path.name for path in output.iterdir()),
            {OBSERVATION_NAME, AUDIT_REPORT_NAME},
        )
        observation = validate_empty_result_root_observation(
            observation_path.read_bytes()
        )
        report = validate_empty_result_root_audit_report(
            report_path.read_bytes(),
            host_environment_raw=self.environment.read_bytes(),
        )
        self.assertEqual(observation["observedAt"], report["observedAt"])
        self.assertEqual(observation["rootDevice"], report["rootDevice"])
        self.assertEqual(observation["rootInode"], report["rootInode"])

    def test_nonempty_symlink_and_predeadline_roots_fail_without_output(self) -> None:
        (self.result_root / "marker.json").write_bytes(b"attempt exists\n")
        with self.assertRaisesRegex(ExperimentCloseoutError, "not empty"):
            collect_to_directory(
                result_root=self.result_root,
                host_environment_path=self.environment,
                auditor_identity="unit observer",
                output_directory=self.root / "nonempty-output",
            )
        self.assertFalse((self.root / "nonempty-output").exists())

        empty = self.root / "empty"
        empty.mkdir()
        link = self.root / "root-link"
        link.symlink_to(empty, target_is_directory=True)
        with self.assertRaisesRegex(ExperimentCloseoutError, "no-follow"):
            collect_to_directory(
                result_root=link,
                host_environment_path=self.environment,
                auditor_identity="unit observer",
                output_directory=self.root / "link-output",
            )

        times = iter(("2026-08-22T17:59:59Z", "2026-08-22T18:00:00Z"))
        with patch("blind_v1.collect_empty_result_root._utc_now", side_effect=lambda: next(times)):
            with self.assertRaisesRegex(ExperimentCloseoutError, "predates"):
                collect_to_directory(
                    result_root=empty,
                    host_environment_path=self.environment,
                    auditor_identity="unit observer",
                    output_directory=self.root / "early-output",
                )
        self.assertFalse((self.root / "early-output").exists())

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_bytes(b"keep\n")
        with self.assertRaisesRegex(ExperimentCloseoutError, "already exists"):
            collect_to_directory(
                result_root=self.result_root,
                host_environment_path=self.environment,
                auditor_identity="unit observer",
                output_directory=output,
            )
        self.assertEqual(sentinel.read_bytes(), b"keep\n")


if __name__ == "__main__":
    unittest.main()
