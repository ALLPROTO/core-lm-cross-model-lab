from __future__ import annotations

import gc
import hashlib
import sys
import tempfile
import types
import unittest
import weakref
from pathlib import Path
from unittest import mock

_NUMPY_SHIM: types.ModuleType | None = None
try:
    import numpy as _numpy  # noqa: F401
except ModuleNotFoundError:
    # The streaming KAT does not execute numeric code.  Permit the system
    # Python used for isolated source tests to import cache_adapter without
    # installing the frozen scientific runtime.
    _NUMPY_SHIM = types.ModuleType("numpy")
    _NUMPY_SHIM.random = types.SimpleNamespace(seed=mock.Mock())
    sys.modules["numpy"] = _NUMPY_SHIM

from blind_v1 import model_worker

if _NUMPY_SHIM is not None:
    sys.modules.pop("numpy", None)


class ModelWorkerStreamingTests(unittest.TestCase):
    def test_frozen_input_load_does_not_open_selected_corpus_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files: dict[str, dict[str, object]] = {}
            for filename, value in {
                "config.json": b"{}",
                "model.safetensors": b"weight-bytes",
                "tokenizer.json": b"{}",
            }.items():
                relative = f"models/model/{filename}"
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
                files[filename] = {
                    "path": relative,
                    "bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            job = {
                "schemaVersion": model_worker.SCIENTIFIC_JOB_SCHEMA,
                "model": {"files": files},
                "selectedCorpora": ["en.wikipedia.org"],
                "pages": {
                    "en.wikipedia.org": [
                        {
                            "recordPath": "records/does-not-exist.bin",
                            "recordBytes": 1,
                            "recordSHA256": "0" * 64,
                        }
                    ]
                },
            }

            model_bytes, development_sentences = model_worker.load_frozen_inputs(
                job, root
            )

            self.assertEqual(set(model_bytes), set(files))
            self.assertIsNone(development_sentences)

    def test_producer_releases_assets_and_previous_record_before_next_read(
        self,
    ) -> None:
        class TrackedRecord:
            pass

        class FakeTokenizer:
            def get_vocab_size(self, *, with_added_tokens: bool) -> int:
                self._with_added_tokens = with_added_tokens
                return 50_277

        class FakeWriter:
            def __init__(self, output_root: Path, **_kwargs: object) -> None:
                self.output_root = output_root
                output_root.mkdir(parents=True)

            def finish(self) -> tuple[Path, Path, Path]:
                paths = tuple(
                    self.output_root / name
                    for name in ("raw.jsonl", "containers.vtl5", "pages.jsonl")
                )
                for path in paths:
                    path.write_bytes(b"evidence")
                return paths

            def close_after_failure(self) -> None:
                return None

        fake_torch = types.ModuleType("torch")
        fake_torch.manual_seed = mock.Mock()
        fake_torch.set_num_threads = mock.Mock()
        fake_torch.set_num_interop_threads = mock.Mock()
        fake_torch.use_deterministic_algorithms = mock.Mock()
        module_overrides: dict[str, types.ModuleType] = {"torch": fake_torch}
        if _NUMPY_SHIM is not None:
            module_overrides["numpy"] = _NUMPY_SHIM
        asset_buffers = {
            "model.safetensors": b"weight-bytes",
            "config.json": b"config-bytes",
            "tokenizer.json": b"tokenizer-bytes",
        }
        record_references: list[weakref.ReferenceType[TrackedRecord]] = []

        def load_model_assets(
            _job: dict[str, object], _root: Path
        ) -> tuple[dict[str, bytes], None]:
            return asset_buffers, None

        def instantiate_model(
            observed_buffers: dict[str, bytes],
        ) -> tuple[object, FakeTokenizer, dict[str, object]]:
            self.assertIs(observed_buffers, asset_buffers)
            del observed_buffers["model.safetensors"]
            return (
                object(),
                FakeTokenizer(),
                {"model_type": "gpt_neox", "vocab_size": 50_277},
            )

        def read_one_record(*_args: object) -> TrackedRecord:
            self.assertEqual(asset_buffers, {})
            gc.collect()
            if record_references:
                self.assertIsNone(record_references[-1]())
            record = TrackedRecord()
            record_references.append(weakref.ref(record))
            return record

        def evaluate_record(_raw: object, **kwargs: object) -> dict[str, object]:
            return {
                "corpus": kwargs["corpus"],
                "pageSelectionIndex": kwargs["page_index"],
            }

        job = {
            "schemaVersion": model_worker.SCIENTIFIC_JOB_SCHEMA,
            "suiteId": model_worker.SCIENTIFIC_SUITE_ID,
            "attemptId": "20260821T180000Z-0123456789abcdef",
            "seed": 0,
            "model": {
                "key": "pythia-160m",
                "vocabSize": 50_277,
                "layers": 1,
            },
            "selectedCorpora": ["en.wikipedia.org"],
            "pages": {
                "en.wikipedia.org": [
                    {"pageSelectionIndex": 0, "pageRevisionId": 1},
                    {"pageSelectionIndex": 1, "pageRevisionId": 2},
                ]
            },
        }

        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            sys.modules, module_overrides
        ), mock.patch.object(
            model_worker, "load_json_strict", return_value=job
        ), mock.patch.object(
            model_worker, "validate_job"
        ), mock.patch.object(
            model_worker, "verify_scientific_authorization"
        ), mock.patch.object(
            model_worker, "install_network_denial"
        ), mock.patch.object(
            model_worker, "load_frozen_inputs", side_effect=load_model_assets
        ), mock.patch.object(
            model_worker, "load_model_and_tokenizer", side_effect=instantiate_model
        ), mock.patch.object(
            model_worker, "load_one_corpus_input", side_effect=read_one_record
        ) as record_loader, mock.patch.object(
            model_worker, "geometry_from_config", return_value={"layers": 1}
        ), mock.patch.object(
            model_worker, "evaluate_page", new=evaluate_record
        ), mock.patch.object(
            model_worker, "EvidenceWriter", FakeWriter
        ):
            output_root = Path(temporary) / "worker"
            summary = model_worker.run(
                Path("job.json"),
                Path("snapshot"),
                Path("codec"),
                output_root,
                authorization_fd=3,
            )
            summary_exists = summary.is_file()

        gc.collect()
        self.assertTrue(summary_exists)
        self.assertEqual(record_loader.call_count, 2)
        self.assertEqual(asset_buffers, {})
        self.assertTrue(record_references)
        self.assertTrue(all(reference() is None for reference in record_references))

    def test_scientific_record_reader_rejects_bound_plus_one_before_open(
        self,
    ) -> None:
        page = {
            "recordPath": "records/oversized.bin",
            "recordBytes": model_worker.MAX_ELIGIBLE_CANONICAL_RECORD_BYTES + 1,
            "recordSHA256": "0" * 64,
            "pageRevisionId": 1,
        }
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            model_worker.WorkerError, "asset commitment"
        ):
            model_worker.load_one_corpus_input(
                {"schemaVersion": model_worker.SCIENTIFIC_JOB_SCHEMA},
                Path(temporary),
                "en.wikipedia.org",
                page,
                None,
            )


if __name__ == "__main__":
    unittest.main()
