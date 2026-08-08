from __future__ import annotations

import argparse
import ast
import inspect
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from blind_v1 import build_frozen_design
from blind_v1 import build_frozen_nist_trust_bundle
from blind_v1 import build_snapshot_registration
from blind_v1 import collect_github_gate_receipt
from blind_v1 import collect_release_receipt
from blind_v1 import collect_snapshot
from blind_v1 import create_asset_receipt
from blind_v1 import fetch_assets
from blind_v1 import freeze_manifest
from blind_v1 import mediawiki_snapshot
from blind_v1 import package_design_release
from blind_v1 import package_development_control_release
from blind_v1 import package_execution_reservation
from blind_v1 import package_snapshot_release
from blind_v1 import run_real_e2e_control


BLIND_V1_ROOT = Path(__file__).resolve().parents[1]


class _GateReached(RuntimeError):
    pass


CREATOR_ENTRYPOINTS = (
    (build_frozen_nist_trust_bundle, "build_frozen_nist_trust_bundle"),
    (freeze_manifest, "build_freeze_manifest"),
    (build_frozen_design, "construct_frozen_design"),
    (build_frozen_design, "build_frozen_design"),
    (collect_github_gate_receipt, "collect_github_gate_receipt"),
    (collect_github_gate_receipt, "collect_github_gate_receipt_to_path"),
    (run_real_e2e_control, "claim_output"),
    (run_real_e2e_control, "build_plan"),
    (run_real_e2e_control, "run_control"),
    (package_development_control_release, "package_development_control_release"),
    (create_asset_receipt, "build_asset_receipt"),
    (package_design_release, "package_design_release"),
    (collect_release_receipt, "collect_release_receipt"),
    (collect_release_receipt, "collect_release_receipt_to_path"),
    (fetch_assets, "fetch_asset"),
    (fetch_assets, "fetch_assets"),
    (fetch_assets, "fetch_development_dataset"),
    (mediawiki_snapshot, "archive_response"),
    (mediawiki_snapshot, "collect_recentchanges_crawl"),
    (mediawiki_snapshot, "fetch_and_inventory_revision"),
    (mediawiki_snapshot, "collect_crawl_stage"),
    (mediawiki_snapshot, "finalize_snapshot"),
    (mediawiki_snapshot, "collect_snapshot"),
    (collect_snapshot, "run_collector_phase"),
    (build_snapshot_registration, "build_snapshot_registration"),
    (build_snapshot_registration, "build_snapshot_registration_to_path"),
    (package_snapshot_release, "package_snapshot_release"),
    (package_execution_reservation, "build_execution_reservation"),
    (package_execution_reservation, "package_execution_reservation"),
)


def _required_arguments(function: object) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, parameter in inspect.signature(function).parameters.items():
        if parameter.kind in {
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        }:
            continue
        if parameter.default is inspect.Parameter.empty:
            result[name] = object()
    return result


class TerminalFreezeEntrypointTests(unittest.TestCase):
    def test_runtime_modules_never_expose_historical_helpers_publicly(self) -> None:
        offenders: list[str] = []
        for path in sorted(BLIND_V1_ROOT.glob("*.py")):
            tree = ast.parse(path.read_bytes(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    for imported in node.names:
                        exposed = imported.asname or imported.name
                        if imported.name.startswith("_historical_") and not exposed.startswith("_"):
                            offenders.append(
                                f"{path.name}:{node.lineno}:{imported.name} as {exposed}"
                            )
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    source_name = None
                    if isinstance(value, ast.Name):
                        source_name = value.id
                    elif isinstance(value, ast.Attribute):
                        source_name = value.attr
                    if not source_name or not source_name.startswith("_historical_"):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and not target.id.startswith("_"):
                            offenders.append(
                                f"{path.name}:{node.lineno}:{target.id} = {source_name}"
                            )
        self.assertEqual(offenders, [])

    def test_every_creator_reaches_terminal_gate_before_inputs(self) -> None:
        for module, name in CREATOR_ENTRYPOINTS:
            function = getattr(module, name)
            with self.subTest(module=module.__name__, entrypoint=name):
                with mock.patch.object(
                    module,
                    "require_scientific_schedule_open",
                    side_effect=_GateReached(name),
                ) as gate:
                    with self.assertRaisesRegex(_GateReached, name):
                        function(**_required_arguments(function))
                gate.assert_called_once()

    def test_creator_only_cli_parses_then_gates_before_creator(self) -> None:
        cases = (
            (
                build_frozen_nist_trust_bundle,
                "parse_arguments",
                "build_frozen_nist_trust_bundle",
                1,
                True,
            ),
            (
                build_frozen_design,
                "parse_arguments",
                "build_frozen_design",
                1,
                True,
            ),
            (
                collect_github_gate_receipt,
                "_parser",
                "collect_github_gate_receipt_to_path",
                2,
                True,
            ),
            (
                run_real_e2e_control,
                "parse_arguments",
                "run_control",
                1,
                False,
            ),
            (
                create_asset_receipt,
                "parse_arguments",
                "build_asset_receipt",
                1,
                False,
            ),
            (
                collect_release_receipt,
                "_argument_parser",
                "collect_release_receipt_to_path",
                2,
                True,
            ),
            (
                fetch_assets,
                "parse_arguments",
                "fetch_assets",
                1,
                False,
            ),
            (
                collect_snapshot,
                "parse_arguments",
                "run_collector_phase",
                1,
                True,
            ),
            (
                build_snapshot_registration,
                "parse_arguments",
                "build_snapshot_registration_to_path",
                1,
                False,
            ),
        )
        for module, parser_name, creator_name, expected_status, accepts_argv in cases:
            with self.subTest(module=module.__name__):
                arguments = argparse.Namespace()
                parser_result: object = arguments
                parse_args = None
                if parser_name.startswith("_"):
                    parse_args = mock.Mock(return_value=arguments)
                    parser_result = SimpleNamespace(parse_args=parse_args)
                with mock.patch.object(
                    module, parser_name, return_value=parser_result
                ) as parser, mock.patch.object(
                    module,
                    "require_scientific_schedule_open",
                    side_effect=ValueError("terminal schedule"),
                ) as gate, mock.patch.object(
                    module,
                    creator_name,
                    side_effect=AssertionError("creator ran after terminal closeout"),
                ) as creator, mock.patch("builtins.print"):
                    observed = module.main([]) if accepts_argv else module.main()
                self.assertEqual(observed, expected_status)
                gate.assert_called_once()
                parser.assert_called_once()
                if parse_args is not None:
                    parse_args.assert_called_once()
                creator.assert_not_called()

    def test_real_terminal_gate_rejects_before_missing_input(self) -> None:
        missing = Path("/definitely-not-opened-by-retired-blind-v1")
        with self.assertRaisesRegex(
            ValueError, "CHECKPOINT_MISSED_TERMINAL_DRAFT"
        ):
            create_asset_receipt.build_asset_receipt(missing, missing)

    def test_post_release_regression_remains_non_scientifically_callable(self) -> None:
        expected = {"status": "NON_SCIENTIFIC_POST_RELEASE_REGRESSION_TEST"}
        arguments = argparse.Namespace()
        with mock.patch.object(
            run_real_e2e_control,
            "require_scientific_schedule_open",
            side_effect=AssertionError("terminal gate must not block regression"),
        ) as gate, mock.patch.object(
            run_real_e2e_control,
            "_historical_run_control",
            return_value=expected,
        ) as historical:
            observed = run_real_e2e_control.run_control(
                arguments, post_release_regression=True
            )
        self.assertEqual(observed, expected)
        gate.assert_not_called()
        historical.assert_called_once_with(
            arguments, post_release_regression=True
        )

    def test_mixed_cli_verification_branches_do_not_call_gate(self) -> None:
        with self.subTest(command="freeze-manifest verify-development-control"):
            with mock.patch.object(
                freeze_manifest,
                "require_scientific_schedule_open",
                side_effect=AssertionError("verification was gated"),
            ) as gate, mock.patch.object(
                freeze_manifest,
                "verify_development_control_report",
                return_value={"artifactCount": 1},
            ), mock.patch("builtins.print"):
                result = freeze_manifest.main(
                    [
                        "verify-development-control",
                        "--report", "report.json",
                        "--artifact-root", "artifacts",
                        "--lab-repository", "lab",
                        "--lab-commit", "0" * 40,
                        "--lab-tree", "1" * 40,
                        "--codec-repository", "codec",
                        "--codec-commit", "2" * 40,
                        "--codec-tree", "3" * 40,
                    ]
                )
            self.assertEqual(result, 0)
            gate.assert_not_called()

    def test_mixed_cli_creator_branches_gate_before_sensitive_work(self) -> None:
        cases = (
            (
                freeze_manifest,
                "build_freeze_manifest",
                SimpleNamespace(command="create"),
                1,
            ),
            (
                package_development_control_release,
                "package_development_control_release",
                SimpleNamespace(command="package"),
                1,
            ),
            (
                package_design_release,
                "package_design_release",
                SimpleNamespace(command="package"),
                1,
            ),
            (
                package_snapshot_release,
                "package_snapshot_release",
                SimpleNamespace(command="package"),
                2,
            ),
        )
        for module, creator_name, arguments, expected_status in cases:
            parser_name = (
                "_parser" if module is package_snapshot_release else "parse_arguments"
            )
            parser_result: object = arguments
            if parser_name == "_parser":
                parser_result = SimpleNamespace(parse_args=lambda _argv: arguments)
            with self.subTest(module=module.__name__):
                with mock.patch.object(
                    module, parser_name, return_value=parser_result
                ), mock.patch.object(
                    module,
                    "require_scientific_schedule_open",
                    side_effect=ValueError("terminal schedule"),
                ) as gate, mock.patch.object(
                    module,
                    creator_name,
                    side_effect=AssertionError("creator ran after terminal closeout"),
                ) as creator, mock.patch("builtins.print"):
                    observed = module.main([])
                self.assertEqual(observed, expected_status)
                gate.assert_called_once()
                creator.assert_not_called()

        with self.subTest(command="development release verify"):
            with mock.patch.object(
                package_development_control_release,
                "require_scientific_schedule_open",
                side_effect=AssertionError("verification was gated"),
            ) as gate, mock.patch.object(
                package_development_control_release,
                "verify_development_control_release_assets",
                return_value={"status": "VERIFIED"},
            ), mock.patch("builtins.print"):
                result = package_development_control_release.main(
                    ["verify", "--asset-root", "assets"]
                )
            self.assertEqual(result, 0)
            gate.assert_not_called()

        with self.subTest(command="design release verify"):
            report = SimpleNamespace(as_dict=lambda: {"status": "VERIFIED"})
            with mock.patch.object(
                package_design_release,
                "require_scientific_schedule_open",
                side_effect=AssertionError("verification was gated"),
            ) as gate, mock.patch.object(
                package_design_release,
                "verify_design_release_package",
                return_value=report,
            ), mock.patch("builtins.print"):
                result = package_design_release.main(
                    [
                        "verify",
                        "--asset-root", "assets",
                        "--signing-public-key", "key.pub",
                    ]
                )
            self.assertEqual(result, 0)
            gate.assert_not_called()

        with self.subTest(command="snapshot release verify"):
            report = SimpleNamespace(as_dict=lambda: {"status": "VERIFIED"})
            stdout = SimpleNamespace(buffer=io.BytesIO())
            with mock.patch.object(
                package_snapshot_release,
                "require_scientific_schedule_open",
                side_effect=AssertionError("verification was gated"),
            ) as gate, mock.patch.object(
                package_snapshot_release,
                "verify_snapshot_release",
                return_value=report,
            ), mock.patch.object(package_snapshot_release.sys, "stdout", stdout):
                result = package_snapshot_release.main(
                    [
                        "verify",
                        "--corpus-root", "corpus",
                        "--snapshot-registration", "snapshot.json",
                        "--design-publication-receipt", "receipt.json",
                        "--asset-root", "assets",
                    ]
                )
            self.assertEqual(result, 0)
            gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
