from __future__ import annotations

import gc
import hashlib
import inspect
import json
import unittest
import weakref

from blind_v1 import development_model_replay as development
from blind_v1 import independent_model_replay as replay


class DevelopmentReplayBackendContractTests(unittest.TestCase):
    def test_exact_backend_arguments_bind_without_model_payload(self) -> None:
        layer_fields = {
            "gpt_neo": "num_layers",
            "llama": "num_hidden_layers",
            "gpt_bigcode": "n_layer",
        }
        signature = inspect.signature(replay.RealModelReplayBackend)
        for model_key, identity in development.EXPECTED_MODEL_IDENTITIES.items():
            with self.subTest(model=model_key):
                config = {
                    "model_type": identity["modelType"],
                    "vocab_size": identity["vocabSize"],
                    layer_fields[identity["modelType"]]: identity["layers"],
                }
                config_raw = json.dumps(config, sort_keys=True).encode("utf-8")
                tokenizer_raw = b'{"fixture":"no-model-payload"}'
                model_bytes = {
                    "config.json": config_raw,
                    "tokenizer.json": tokenizer_raw,
                }
                files = {
                    filename: {
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                    for filename, raw in model_bytes.items()
                }
                model = {
                    "key": model_key,
                    "layers": identity["layers"],
                    "vocabSize": identity["vocabSize"],
                    "files": files,
                }
                arguments = development._development_backend_arguments(
                    model_key=model_key,
                    model=model,
                    model_bytes=model_bytes,
                )
                self.assertEqual(
                    arguments,
                    {
                        "expected_model_type": identity["modelType"],
                        "expected_model_vocab_size": identity["vocabSize"],
                        "expected_tokenizer_vocab_size": identity[
                            "tokenizerVocabSize"
                        ],
                        "expected_layers": identity["layers"],
                    },
                )
                bound = signature.bind(model_bytes, **arguments)
                self.assertEqual(set(bound.arguments), {"model_bytes", *arguments})

                forged = dict(config)
                forged["vocab_size"] += 1
                forged_raw = json.dumps(forged, sort_keys=True).encode("utf-8")
                forged_bytes = dict(model_bytes)
                forged_bytes["config.json"] = forged_raw
                forged_model = dict(model)
                forged_model["files"] = dict(files)
                forged_model["files"]["config.json"] = {
                    "bytes": len(forged_raw),
                    "sha256": hashlib.sha256(forged_raw).hexdigest(),
                }
                with self.assertRaisesRegex(
                    development.DevelopmentReplayError,
                    "backend config differs",
                ):
                    development._development_backend_arguments(
                        model_key=model_key,
                        model=forged_model,
                        model_bytes=forged_bytes,
                    )

                mismatched_spec = dict(model)
                mismatched_spec["files"] = dict(files)
                mismatched_spec["files"]["tokenizer.json"] = {
                    "bytes": len(tokenizer_raw),
                    "sha256": "0" * 64,
                }
                with self.assertRaisesRegex(
                    development.DevelopmentReplayError,
                    "backend asset differs",
                ):
                    development._development_backend_arguments(
                        model_key=model_key,
                        model=mismatched_spec,
                        model_bytes=model_bytes,
                    )

    def test_backend_order_and_owned_record_release_are_explicit(self) -> None:
        runner_source = inspect.getsource(development.run_development_replay)
        helper_source = inspect.getsource(
            development._consume_owned_development_record
        )
        self.assertLess(
            runner_source.index("backend = replay.RealModelReplayBackend"),
            runner_source.index('raw_relative = f"workers/{model_key}/'),
        )
        self.assertNotIn("record_raw = replay.read_beneath", runner_source)
        self.assertLess(
            runner_source.index("_consume_owned_development_record("),
            runner_source.index("page_summaries.append(page_summary)"),
        )
        self.assertLess(
            helper_source.index("finally:"), helper_source.index("del record_raw")
        )
        self.assertLess(
            helper_source.index("del record_raw"), helper_source.index("gc.collect()")
        )

        class TrackedRecord:
            pass

        references: list[weakref.ReferenceType[TrackedRecord]] = []

        def new_record() -> TrackedRecord:
            gc.collect()
            if references:
                self.assertIsNone(references[-1]())
            record = TrackedRecord()
            references.append(weakref.ref(record))
            return record

        for _index in range(2):
            observed = development._consume_owned_development_record(
                new_record(), lambda record: id(record)
            )
            self.assertIsInstance(observed, int)
        gc.collect()
        self.assertIsNone(references[-1]())


if __name__ == "__main__":
    unittest.main()
