#!/usr/bin/env python3
"""Verify all pinned blind_v1 assets and emit a path-independent local receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.fetch_assets import DEFAULT_MANIFEST, load_manifest  # noqa: E402
from blind_v1.preflight import verify_file_beneath  # noqa: E402
from blind_v1.protocol import (  # noqa: E402
    load_json_strict,
    require_scientific_schedule_open,
)
from blind_v1.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    verify_expected_file,
    with_content_digest,
    write_new_bytes,
)


def build_asset_receipt(manifest_path: Path, asset_root: Path) -> dict[str, Any]:
    require_scientific_schedule_open(operation="build full model-asset receipt")
    return _historical_build_asset_receipt(manifest_path, asset_root)


def _historical_build_asset_receipt(
    manifest_path: Path, asset_root: Path
) -> dict[str, Any]:
    """Build the legacy receipt shape for offline fixtures and regressions."""

    specifications = load_manifest(manifest_path)
    manifest = load_json_strict(manifest_path)
    models: dict[str, Any] = {}
    total_bytes = 0
    weight_bytes = 0
    weight_files = 0
    for specification in specifications:
        path = asset_root / specification.model_key / specification.filename
        verify_file_beneath(
            asset_root,
            Path(specification.model_key) / specification.filename,
            {
                "bytes": specification.expected_bytes,
                "sha256": specification.expected_sha256,
            },
        )
        observed = verify_expected_file(
            path,
            expected_bytes=specification.expected_bytes,
            expected_sha256=specification.expected_sha256,
        )
        model_source = manifest["models"][specification.model_key]
        model = models.setdefault(
            specification.model_key,
            {
                "repository": specification.repository,
                "revision": specification.revision,
                "license": model_source["license"],
                "licenseURL": model_source["licenseURL"],
                "files": {},
            },
        )
        model["files"][specification.filename] = {
            "bytes": observed["bytes"],
            "sha256": observed["sha256"],
        }
        total_bytes += int(observed["bytes"])
        if specification.filename == "model.safetensors":
            weight_bytes += int(observed["bytes"])
            weight_files += 1

    if weight_files != len(models) or weight_files < 1:
        raise ValueError("every registered model must contain one verified safetensors file")

    manifest_bytes = manifest_path.read_bytes()
    payload = {
        "schemaVersion": "corelm-blind-crossmodel-v1-asset-receipt-v1",
        "status": "LOCAL_FULL_ASSET_SNAPSHOT_VERIFIED",
        "countsTowardScientificVerdict": False,
        "networkUsed": False,
        "modelInferenceUsed": False,
        "manifestFile": manifest_path.name,
        "manifestSchemaVersion": manifest["schemaVersion"],
        "manifestDeclaredStatus": manifest.get("status"),
        "manifestDeclaredFullSafetensorsBytesLocallyVerified": manifest.get(
            "fullSafetensorsBytesLocallyVerified"
        ),
        "manifestFileBytes": len(manifest_bytes),
        "manifestFileSHA256": sha256_bytes(manifest_bytes),
        "assetLayout": "<asset-root>/<model-key>/<manifest-relative-file>",
        "fileCount": len(specifications),
        "totalBytes": total_bytes,
        "fullSafetensorsBytesLocallyVerified": True,
        "fullSafetensorsBytes": weight_bytes,
        "models": models,
    }
    return with_content_digest(payload)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--asset-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        require_scientific_schedule_open(
            operation="run Blind V1 model-asset receipt builder"
        )
        receipt = build_asset_receipt(arguments.manifest, arguments.asset_root)
        output_bytes = canonical_json_bytes(receipt) + b"\n"
        write_new_bytes(arguments.output, output_bytes)
    except (OSError, ValueError, KeyError) as error:
        print(f"ASSET RECEIPT FAIL: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "output": str(arguments.output),
                "fileBytes": len(output_bytes),
                "fileSHA256": sha256_bytes(output_bytes),
                "contentSHA256": receipt["contentSHA256"],
                "assetFiles": receipt["fileCount"],
                "assetBytes": receipt["totalBytes"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
