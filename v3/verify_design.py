#!/usr/bin/env python3
"""Verify the offline blind-v3 design draft and known-answer selector."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict,
    resolve_selection,
    sha256_bytes,
    validate_design_registration,
    validate_model_asset_manifest,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-freezable",
        action="store_true",
        help="fail while any declared design freeze blocker remains",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    registration_path = V3_ROOT / "design-registration.draft.json"
    vector_path = V3_ROOT / "test-vectors" / "selection-v1.json"
    registration_bytes = registration_path.read_bytes()
    registration = load_json_strict(registration_path)
    blockers = validate_design_registration(registration)
    continuous_integration = registration["continuousIntegration"]
    workflow_path = PROJECT_ROOT / continuous_integration["workflowPath"]
    workflow_bytes = workflow_path.read_bytes()
    if (
        len(workflow_bytes) != continuous_integration["workflowFileBytes"]
        or sha256_bytes(workflow_bytes)
        != continuous_integration["workflowFileSHA256"]
    ):
        raise ValueError("tracked CI workflow bytes differ from the registered design")
    asset_manifest_path = V3_ROOT / "model-assets.draft.json"
    asset_manifest_bytes = asset_manifest_path.read_bytes()
    asset_manifest = load_json_strict(asset_manifest_path)
    asset_summary = validate_model_asset_manifest(asset_manifest, registration)

    vector = load_json_strict(vector_path)
    if not isinstance(vector, dict) or vector.get("fixtureOnly") is not True:
        raise ValueError("selection vector must be marked fixtureOnly=true")
    snapshot_bytes = canonical_json_bytes(vector["snapshotRegistration"])
    selection = resolve_selection(
        snapshot_bytes,
        vector["nistOutputValue"],
        projects=vector["projects"],
        models=vector["models"],
        ledgers=vector["ledgers"],
        allow_fixture=True,
    )
    observed_selection = sha256_bytes(canonical_json_bytes(selection))
    if observed_selection != vector["expectedSelectionSHA256"]:
        raise ValueError("known-answer selector digest mismatch")
    if selection["selectedCorpora"] != vector["expectedSelectedCorpora"]:
        raise ValueError("known-answer selected corpora mismatch")
    if selection["modelExecutionOrder"] != vector["expectedModelExecutionOrder"]:
        raise ValueError("known-answer model order mismatch")
    selected_revision_ids = {
        project: [record["revid"] for record in records]
        for project, records in selection["selectedPages"].items()
    }
    if selected_revision_ids != vector["expectedSelectedPageRevisionIds"]:
        raise ValueError("known-answer selected page revisions mismatch")
    if selection["draws"][0] != vector["expectedFirstDraw"]:
        raise ValueError("known-answer first draw mismatch")
    if selection["draws"][-1] != vector["expectedLastDraw"]:
        raise ValueError("known-answer last draw mismatch")
    observed_draws = sha256_bytes(canonical_json_bytes(selection["draws"]))
    if observed_draws != vector["expectedDrawsSHA256"]:
        raise ValueError("known-answer draw transcript mismatch")

    # A concrete, fail-closed two-stage freeze validator now exists in
    # freeze_manifest.py.  This draft still cannot become ready merely because
    # the validator exists: every declared artifact and publication blocker
    # must be discharged by independently reviewable inputs first.
    ready_to_freeze = False
    result = {
        "schemaVersion": "corelm-crossmodel-livewiki-v3-design-check-v1",
        "status": "DRAFT_VERIFIED_NOT_PREREGISTERED",
        "readyToFreeze": ready_to_freeze,
        "freezeValidatorImplemented": True,
        "countsTowardScientificVerdict": False,
        "designRegistrationFileSHA256": sha256_bytes(registration_bytes),
        "canonicalDesignSHA256": sha256_bytes(canonical_json_bytes(registration)),
        "modelAssetManifestFileSHA256": sha256_bytes(asset_manifest_bytes),
        "modelAssetSummary": asset_summary,
        "knownAnswerSelectionSHA256": observed_selection,
        "knownAnswerDrawsSHA256": observed_draws,
        "freezeBlockers": blockers,
        "workflowFileBytes": len(workflow_bytes),
        "workflowFileSHA256": sha256_bytes(workflow_bytes),
        "platformSafety": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "networkUsed": False,
        "modelInferenceUsed": False,
        "corpusOpened": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if arguments.require_freezable and not ready_to_freeze:
        print(
            f"NOT FREEZABLE: {len(blockers)} explicit blockers remain; the "
            "freeze validator cannot waive them",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
