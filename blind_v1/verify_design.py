#!/usr/bin/env python3
"""Audit the terminal blind-v1 draft offline without authorizing execution."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.protocol import (  # noqa: E402
    canonical_json_bytes,
    load_json_strict,
    resolve_selection,
    sha256_bytes,
    validate_development_model_asset_manifest,
    validate_design_registration,
    validate_model_asset_manifest,
)
from blind_v1.model_card_evidence import (  # noqa: E402
    validate_design_binding as validate_model_card_design_binding,
    verify_model_card_evidence_tree,
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
    registration_path = BLIND_V1_ROOT / "design-registration.draft.json"
    vector_path = BLIND_V1_ROOT / "test-vectors" / "selection-v1.json"
    registration_bytes = registration_path.read_bytes()
    registration = load_json_strict(registration_path)
    blockers = validate_design_registration(registration)
    prior_binding = registration["priorObservations"]
    prior_path = PROJECT_ROOT / prior_binding["path"]
    prior_bytes = prior_path.read_bytes()
    if (
        len(prior_bytes) != prior_binding["bytes"]
        or sha256_bytes(prior_bytes) != prior_binding["sha256"]
    ):
        raise ValueError("tracked prior-observation lineage differs from the design")
    prior = load_json_strict(prior_path)
    if (
        not isinstance(prior, dict)
        or prior.get("schemaVersion")
        != "corelm-blind-crossmodel-v1-prior-observations-v1"
        or prior.get("status") != prior_binding["status"]
    ):
        raise ValueError("prior-observation lineage identity differs")
    continuous_integration = registration["continuousIntegration"]
    workflow_path = PROJECT_ROOT / continuous_integration["workflowPath"]
    workflow_bytes = workflow_path.read_bytes()
    if (
        len(workflow_bytes) != continuous_integration["workflowFileBytes"]
        or sha256_bytes(workflow_bytes)
        != continuous_integration["workflowFileSHA256"]
    ):
        raise ValueError("tracked CI workflow bytes differ from the registered design")
    asset_manifest_path = BLIND_V1_ROOT / "model-assets.draft.json"
    asset_manifest_bytes = asset_manifest_path.read_bytes()
    asset_manifest = load_json_strict(asset_manifest_path)
    asset_summary = validate_model_asset_manifest(asset_manifest, registration)
    model_card_summary = verify_model_card_evidence_tree(
        PROJECT_ROOT, registration["models"]
    )
    validate_model_card_design_binding(
        registration["modelCardEvidence"], model_card_summary
    )
    weight_layout_binding = registration["modelWeightLayouts"]
    weight_layout_path = PROJECT_ROOT / weight_layout_binding["path"]
    weight_layout_bytes = weight_layout_path.read_bytes()
    if (
        len(weight_layout_bytes) != weight_layout_binding["bytes"]
        or sha256_bytes(weight_layout_bytes) != weight_layout_binding["sha256"]
    ):
        raise ValueError("tracked model-weight layouts differ from the design")
    weight_layouts = load_json_strict(weight_layout_path)
    if (
        not isinstance(weight_layouts, dict)
        or canonical_json_bytes(weight_layouts) + b"\n" != weight_layout_bytes
        or weight_layouts.get("schemaVersion")
        != weight_layout_binding["schemaVersion"]
        or weight_layouts.get("suiteId") != registration["suiteId"]
        or weight_layouts.get("payloadBytesIncluded") is not False
        or not isinstance(weight_layouts.get("models"), dict)
        or len(weight_layouts["models"]) != weight_layout_binding["modelCount"]
        or sum(
            record.get("tensorCount", -1)
            for record in weight_layouts["models"].values()
            if isinstance(record, dict)
        )
        != weight_layout_binding["tensorCount"]
    ):
        raise ValueError("tracked model-weight layout identity differs")
    development_asset_binding = registration["developmentControls"]["modelAssets"]
    development_asset_path = PROJECT_ROOT / development_asset_binding["path"]
    development_asset_bytes = development_asset_path.read_bytes()
    if (
        len(development_asset_bytes) != development_asset_binding["bytes"]
        or sha256_bytes(development_asset_bytes)
        != development_asset_binding["sha256"]
    ):
        raise ValueError("tracked development model assets differ from the design")
    development_asset_summary = validate_development_model_asset_manifest(
        load_json_strict(development_asset_path), registration
    )

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

    # Structural freeze validators are retained only to audit the historical
    # pre-checkpoint design.  The missed checkpoint is a permanent lifecycle
    # closeout: satisfying any old blocker cannot make this suite freezable.
    ready_to_freeze = False
    schedule_closeout = registration["scheduleCloseout"]
    result = {
        "schemaVersion": "corelm-blind-crossmodel-v1-design-check-v1",
        "status": "FAILED_SCHEDULE_DRAFT_DO_NOT_RUN",
        "readyToFreeze": ready_to_freeze,
        "freezeValidatorImplemented": True,
        "structuralValidationPurpose": "HISTORICAL_AUDIT_ONLY",
        "countsTowardScientificVerdict": False,
        "scheduleCloseout": schedule_closeout,
        "freezeAllowed": schedule_closeout["freezeAllowed"],
        "publicationAllowed": schedule_closeout["publicationAllowed"],
        "scientificExecutionAllowed": schedule_closeout[
            "scientificExecutionAllowed"
        ],
        "successorSuiteIdRequired": schedule_closeout[
            "successorSuiteIdRequired"
        ],
        "designRegistrationFileSHA256": sha256_bytes(registration_bytes),
        "canonicalDesignSHA256": sha256_bytes(canonical_json_bytes(registration)),
        "modelAssetManifestFileSHA256": sha256_bytes(asset_manifest_bytes),
        "modelAssetSummary": asset_summary,
        "modelWeightLayoutsFileSHA256": sha256_bytes(weight_layout_bytes),
        "developmentModelAssetManifestFileSHA256": sha256_bytes(
            development_asset_bytes
        ),
        "developmentModelAssetSummary": development_asset_summary,
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
            "NOT FREEZABLE: CHECKPOINT_MISSED_TERMINAL_DRAFT permanently "
            "closed this suite; old blockers cannot be discharged into a V1 "
            "freeze and a new suite ID with a fully rescheduled timeline is "
            "required",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
