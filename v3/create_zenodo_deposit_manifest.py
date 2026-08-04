#!/usr/bin/env python3
"""Create a deterministic Zenodo manifested-superset root from an exact plan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from v3.protocol import load_json_strict
from v3.release_attestation_crypto import (
    PinnedCosignReleaseAttestationVerifier,
)
from v3.zenodo_archive import ZenodoArchiveError, build_deposit_manifest_to_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deposit-root", type=Path, required=True)
    parser.add_argument(
        "--plan",
        type=Path,
        required=True,
        help="strict JSON plan assigning role, media type, and rights to every payload file",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cosign",
        type=Path,
        required=True,
        help="absolute path to the byte-pinned Cosign 3.0.6 executable",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        plan = load_json_strict(arguments.plan)
        manifest = build_deposit_manifest_to_path(
            arguments.deposit_root,
            plan,
            arguments.output,
            cryptographic_attestation_verifier=(
                PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            ),
        )
    except (OSError, ValueError, ZenodoArchiveError) as error:
        print(f"ZENODO MANIFEST BUILD FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "ZENODO MANIFEST BUILD PASS: "
        f"files={manifest['fileCount']} bytes={manifest['totalBytes']} "
        f"sha256={manifest['contentSHA256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
