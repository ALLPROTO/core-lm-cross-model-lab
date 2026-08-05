#!/usr/bin/env python3
"""Run blind-v1 controls and fail when any test is skipped."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(BLIND_V1_ROOT / "tests"),
        pattern="test*.py",
        top_level_dir=str(PROJECT_ROOT),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(
            f"ZERO-SKIP POLICY FAIL: {len(result.skipped)} test(s) skipped",
            file=sys.stderr,
        )
        for test, reason in result.skipped:
            print(f"- {test}: {reason}", file=sys.stderr)
        return 2
    if not result.wasSuccessful():
        return 1
    print(f"ZERO-SKIP POLICY PASS: {result.testsRun} tests, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
