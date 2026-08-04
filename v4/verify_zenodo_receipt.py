#!/usr/bin/env python3
"""Verify a canonical Zenodo production receipt entirely offline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from v4.release_attestation_crypto import (
    PinnedCosignReleaseAttestationVerifier,
)
from v4.zenodo_archive import (
    MAXIMUM_RECEIPT_BYTES,
    ZenodoArchiveError,
    _read_stable_bytes,
    verify_zenodo_receipt,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--deposit-root", type=Path, required=True)
    parser.add_argument("--deposition-id", type=int, required=True)
    parser.add_argument("--record-id", type=int, required=True)
    parser.add_argument("--doi", required=True)
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
        raw = _read_stable_bytes(
            arguments.receipt,
            label="Zenodo receipt",
            maximum_bytes=MAXIMUM_RECEIPT_BYTES,
        )
        verified = verify_zenodo_receipt(
            raw,
            manifest_path=arguments.manifest,
            deposit_root=arguments.deposit_root,
            expected_deposition_id=arguments.deposition_id,
            expected_record_id=arguments.record_id,
            expected_doi=arguments.doi,
            cryptographic_attestation_verifier=(
                PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            ),
        )
    except (OSError, ZenodoArchiveError, ValueError) as error:
        print(f"ZENODO RECEIPT VERIFY FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "ZENODO RECEIPT VERIFY PASS: "
        f"record={verified.record_id} doi={verified.doi} files={len(verified.file_sha256)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
