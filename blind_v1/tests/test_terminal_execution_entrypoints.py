from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from blind_v1 import collect_empty_result_root
from blind_v1 import collect_zenodo_receipt
from blind_v1 import create_zenodo_deposit_manifest
from blind_v1 import experiment_closeout
from blind_v1 import model_worker
from blind_v1 import package_closeout_release
from blind_v1 import package_evidence_assets
from blind_v1 import package_evidence_release
from blind_v1 import runner
from blind_v1 import state_machine
from blind_v1 import zenodo_archive


class TerminalGateReached(RuntimeError):
    pass


class DevelopmentBranchReached(RuntimeError):
    pass


class TerminalExecutionEntrypointTests(unittest.TestCase):
    def assert_gate_precedes_historical_creator(
        self,
        *,
        module: object,
        public_name: str,
        historical_name: str,
        operation: str,
        call: object | None = None,
    ) -> None:
        public = getattr(module, public_name)
        invoke = call if call is not None else public
        with (
            mock.patch.object(
                module,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached(operation),
            ) as gate,
            mock.patch.object(module, historical_name) as historical,
            self.assertRaisesRegex(TerminalGateReached, operation),
        ):
            invoke()  # type: ignore[operator]
        gate.assert_called_once_with(operation=operation)
        historical.assert_not_called()

    def test_every_public_creator_gates_before_historical_inputs_and_outputs(self) -> None:
        generic_cases = (
            (
                runner,
                "prepare_private_snapshot",
                "_historical_prepare_private_snapshot",
                "prepare-private-snapshot",
            ),
            (
                state_machine,
                "create_attempt_marker",
                "_historical_create_attempt_marker",
                "create-attempt-marker",
            ),
            (
                state_machine,
                "create_terminal_outcome",
                "_historical_create_terminal_outcome",
                "create-terminal-outcome",
            ),
            (
                package_evidence_release,
                "package_release",
                "_historical_package_release",
                "package-evidence-release",
            ),
            (
                package_evidence_assets,
                "package_evidence_assets",
                "_historical_package_evidence_assets",
                "package-evidence-assets",
            ),
            (
                experiment_closeout,
                "collect_empty_result_root_observation",
                "_historical_collect_empty_result_root_observation",
                "collect-empty-result-root",
            ),
            (
                experiment_closeout,
                "create_no_attempt_expired",
                "_historical_create_no_attempt_expired",
                "create-no-attempt-closeout",
            ),
            (
                experiment_closeout,
                "create_late_publication_invalid",
                "_historical_create_late_publication_invalid",
                "create-late-publication-closeout",
            ),
            (
                collect_empty_result_root,
                "collect_to_directory",
                "_historical_collect_to_directory",
                "collect-empty-result-root-files",
            ),
            (
                package_closeout_release,
                "package_closeout_release",
                "_historical_package_closeout_release",
                "package-closeout-release",
            ),
            (
                zenodo_archive,
                "build_deposit_manifest",
                "_historical_build_deposit_manifest",
                "build-zenodo-deposit-manifest",
            ),
            (
                zenodo_archive,
                "build_deposit_manifest_to_path",
                "_historical_build_deposit_manifest_to_path",
                "write-zenodo-deposit-manifest",
            ),
            (
                zenodo_archive,
                "build_zenodo_receipt",
                "_historical_build_zenodo_receipt",
                "build-zenodo-receipt",
            ),
            (
                zenodo_archive,
                "write_zenodo_receipt_to_path",
                "_historical_write_zenodo_receipt_to_path",
                "write-zenodo-receipt",
            ),
            (
                collect_zenodo_receipt,
                "collect_zenodo_receipt_to_path",
                "_historical_collect_zenodo_receipt_to_path",
                "collect-zenodo-receipt",
            ),
        )
        for module, public_name, historical_name, operation in generic_cases:
            with self.subTest(public_name=public_name):
                self.assert_gate_precedes_historical_creator(
                    module=module,
                    public_name=public_name,
                    historical_name=historical_name,
                    operation=operation,
                )

        self.assert_gate_precedes_historical_creator(
            module=runner,
            public_name="fetch_exact_pulse_with_total_timeout",
            historical_name="_historical_fetch_exact_pulse_with_total_timeout",
            operation="fetch-exact-nist-pulse",
            call=lambda: runner.fetch_exact_pulse_with_total_timeout(
                lambda _endpoint: (_ for _ in ()).throw(
                    AssertionError("NIST client touched")
                ),
                timeout_seconds=1,
            ),
        )
        self.assert_gate_precedes_historical_creator(
            module=runner,
            public_name="execute_private_one_shot",
            historical_name="_historical_execute_private_one_shot",
            operation="execute-private-one-shot",
            call=lambda: runner.execute_private_one_shot(
                Path("input-must-not-be-touched"),
                Path("output-must-not-be-touched"),
                outer_authorization={},
            ),
        )
        with (
            mock.patch.object(
                runner,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached("outer supervisor blocked"),
            ) as gate,
            mock.patch.object(runner, "verify_private_snapshot") as verify_snapshot,
            mock.patch.object(runner, "load_json_strict") as load_json,
            mock.patch.object(runner, "_spawn_authorized_private_execution") as spawn,
            self.assertRaisesRegex(TerminalGateReached, "outer supervisor blocked"),
        ):
            runner.reexec_private_one_shot(
                private_root=Path("private-root-must-not-be-opened"),
                result_root=Path("result-root-must-not-be-created"),
            )
        gate.assert_called_once_with(operation="reexec-private-one-shot")
        verify_snapshot.assert_not_called()
        load_json.assert_not_called()
        spawn.assert_not_called()

    def test_scientific_model_worker_gates_before_job_model_or_output(self) -> None:
        with (
            mock.patch.object(
                model_worker,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached("scientific worker blocked"),
            ) as gate,
            mock.patch.object(model_worker, "load_json_strict") as load_job,
            mock.patch.object(model_worker, "load_frozen_inputs") as load_inputs,
            mock.patch.object(model_worker, "EvidenceWriter") as writer,
            self.assertRaisesRegex(TerminalGateReached, "scientific worker blocked"),
        ):
            model_worker.run(
                Path("job-must-not-be-opened"),
                Path("model-and-corpus-must-not-be-opened"),
                Path("codec-must-not-be-opened"),
                Path("output-must-not-be-created"),
                authorization_fd=3,
            )
        gate.assert_called_once_with(operation="run-scientific-model-worker")
        load_job.assert_not_called()
        load_inputs.assert_not_called()
        writer.assert_not_called()

    def test_development_model_worker_branch_remains_available(self) -> None:
        development_job = {"schemaVersion": model_worker.DEVELOPMENT_JOB_SCHEMA}
        with (
            mock.patch.object(model_worker, "load_json_strict", return_value=development_job),
            mock.patch.object(model_worker, "validate_job"),
            mock.patch.object(model_worker, "_guard_development_output_root"),
            mock.patch.object(
                model_worker,
                "install_network_denial",
                side_effect=DevelopmentBranchReached("development reached"),
            ),
            mock.patch.object(model_worker, "require_scientific_schedule_open") as gate,
            self.assertRaisesRegex(DevelopmentBranchReached, "development reached"),
        ):
            model_worker.run_development(
                Path("development-job.json"),
                Path("development-snapshot"),
                Path("development-codec"),
                Path("development-output"),
            )
        gate.assert_not_called()

    def test_creator_clis_gate_before_plan_or_secret_input(self) -> None:
        manifest_arguments = SimpleNamespace(
            plan=Path("plan-must-not-be-read"),
            deposit_root=Path("deposit-must-not-be-read"),
            output=Path("output-must-not-be-created"),
            cosign=Path("cosign-must-not-be-opened"),
        )
        with (
            mock.patch.object(
                create_zenodo_deposit_manifest,
                "parse_arguments",
                return_value=manifest_arguments,
            ),
            mock.patch.object(
                create_zenodo_deposit_manifest,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached("manifest cli blocked"),
            ),
            mock.patch.object(create_zenodo_deposit_manifest, "load_json_strict") as load_plan,
            self.assertRaisesRegex(TerminalGateReached, "manifest cli blocked"),
        ):
            create_zenodo_deposit_manifest.main()
        load_plan.assert_not_called()

        receipt_arguments = SimpleNamespace(token_env="TOKEN_MUST_NOT_BE_READ")
        with (
            mock.patch.object(
                collect_zenodo_receipt,
                "parse_arguments",
                return_value=receipt_arguments,
            ),
            mock.patch.object(
                collect_zenodo_receipt,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached("receipt cli blocked"),
            ),
            mock.patch.object(
                collect_zenodo_receipt, "load_token_from_environment"
            ) as load_token,
            self.assertRaisesRegex(TerminalGateReached, "receipt cli blocked"),
        ):
            collect_zenodo_receipt.main()
        load_token.assert_not_called()

        closeout_arguments = SimpleNamespace(command="package")
        with (
            mock.patch.object(
                package_closeout_release,
                "_parser",
                return_value=SimpleNamespace(
                    parse_args=lambda _argv: closeout_arguments
                ),
            ),
            mock.patch.object(
                package_closeout_release,
                "require_scientific_schedule_open",
                side_effect=TerminalGateReached("closeout cli blocked"),
            ),
            mock.patch.object(
                package_closeout_release,
                "PinnedCosignReleaseAttestationVerifier",
            ) as open_cosign,
            self.assertRaisesRegex(TerminalGateReached, "closeout cli blocked"),
        ):
            package_closeout_release.main([])
        open_cosign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
