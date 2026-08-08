from __future__ import annotations

import hashlib
import inspect
import json
import math
import sys
import unittest
from pathlib import Path

from blind_v1 import independent_model_replay
from blind_v1 import model_worker
from blind_v1 import verify_model_weight_layouts


BLIND_ROOT = Path(__file__).resolve().parents[1]
LAYOUT_PATH = BLIND_ROOT / "model-weight-layouts.json"
ASSET_MANIFEST_PATH = BLIND_ROOT / "model-assets.draft.json"
ASSET_ROOT = BLIND_ROOT / ".assets"
LAYOUT_BYTES = 83_789
LAYOUT_SHA256 = "cee28426296047d6cccab65866452e747dfdb8ee99ec594f1accd8e792af54a9"
MODEL_KEYS = {
    "distilgpt2-82m",
    "gpt2-124m",
    "pythia-160m",
    "pythia-70m",
    "smollm-135m",
    "smollm-360m",
}


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def key_digest(keys: object) -> str:
    ordered = sorted(str(key) for key in keys)
    return hashlib.sha256(("\n".join(ordered) + "\n").encode("utf-8")).hexdigest()


def exact_header(path: Path, expected_size: int) -> tuple[bytes, bytes, dict[str, object]]:
    """Read the safetensors prefix and JSON header, never tensor payload bytes."""

    if path.stat().st_size != expected_size:
        raise AssertionError(f"unexpected local model size: {path}")
    with path.open("rb") as handle:
        prefix = handle.read(8)
        if len(prefix) != 8:
            raise AssertionError(f"truncated safetensors prefix: {path}")
        header_size = int.from_bytes(prefix, "little")
        if header_size <= 0 or header_size >= expected_size - 8:
            raise AssertionError(f"invalid safetensors header length: {path}")
        raw_header = handle.read(header_size)
        if len(raw_header) != header_size:
            raise AssertionError(f"truncated safetensors header: {path}")
        if handle.tell() != 8 + header_size:
            raise AssertionError("header reader crossed the tensor-payload boundary")
    parsed = json.loads(raw_header.decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict):
        raise AssertionError(f"safetensors header is not an object: {path}")
    return prefix, raw_header, parsed


class ModelWeightLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = LAYOUT_PATH.read_bytes()
        cls.layout = json.loads(cls.raw)
        cls.asset_manifest = json.loads(ASSET_MANIFEST_PATH.read_bytes())

    def test_fixture_is_exact_canonical_and_bound_to_asset_manifest(self) -> None:
        self.assertEqual(len(self.raw), LAYOUT_BYTES)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), LAYOUT_SHA256)
        self.assertEqual(self.raw, canonical_bytes(self.layout))
        self.assertEqual(
            self.layout,
            {
                **self.layout,
                "schemaVersion": "corelm-blind-crossmodel-v1-model-weight-layouts-v1",
                "suiteId": independent_model_replay.SUITE_ID,
                "status": "EXACT_SAFETENSORS_HEADERS_PINNED_NO_TENSOR_PAYLOAD",
                "payloadBytesIncluded": False,
            },
        )
        self.assertEqual(set(self.layout["models"]), MODEL_KEYS)
        self.assertEqual(set(self.asset_manifest["models"]), MODEL_KEYS)
        self.assertEqual(
            sum(item["tensorCount"] for item in self.layout["models"].values()),
            1_082,
        )
        for model_key, record in self.layout["models"].items():
            declared = self.asset_manifest["models"][model_key]["files"][
                "model.safetensors"
            ]
            self.assertEqual(record["modelFileBytes"], declared["bytes"])
            self.assertEqual(record["modelFileSHA256"], declared["sha256"])
            tensors = record["tensors"]
            self.assertEqual(record["tensorCount"], len(tensors))
            self.assertEqual(record["stateKeysSHA256"], key_digest(tensors))
            self.assertEqual(len(record["headerLengthPrefixHex"]), 16)
            self.assertEqual(
                int.from_bytes(bytes.fromhex(record["headerLengthPrefixHex"]), "little"),
                record["headerBytes"],
            )
            for tensor in tensors.values():
                self.assertEqual(set(tensor), {"dtype", "shape"})
                # Pythia's discarded causal-mask buffers are U8; all retained
                # Pythia parameters are F16 and the other four models are F32.
                self.assertIn(tensor["dtype"], {"F16", "F32", "U8"})
                # Safetensors represents scalar masked-bias buffers as [].
                self.assertIsInstance(tensor["shape"], list)
                self.assertTrue(all(type(value) is int and value > 0 for value in tensor["shape"]))

    def test_local_assets_match_exact_headers_without_reading_payloads(self) -> None:
        if not ASSET_ROOT.exists():
            self.assertFalse(ASSET_ROOT.exists())
            return
        self.assertTrue(
            MODEL_KEYS.issubset(
                {path.name for path in ASSET_ROOT.iterdir() if path.is_dir()}
            )
        )
        for model_key, record in self.layout["models"].items():
            prefix, raw_header, parsed = exact_header(
                ASSET_ROOT / model_key / "model.safetensors",
                record["modelFileBytes"],
            )
            self.assertEqual(prefix.hex(), record["headerLengthPrefixHex"])
            self.assertEqual(len(raw_header), record["headerBytes"])
            self.assertEqual(hashlib.sha256(raw_header).hexdigest(), record["headerSHA256"])
            parsed.pop("__metadata__", None)
            observed = {
                key: {"dtype": item["dtype"], "shape": item["shape"]}
                for key, item in parsed.items()
            }
            self.assertEqual(observed, record["tensors"])
        self.assertEqual(
            verify_model_weight_layouts.derive_layout(
                asset_root=ASSET_ROOT,
                manifest_path=ASSET_MANIFEST_PATH,
            ),
            self.layout,
        )

    def test_local_layouts_match_locked_transformers_meta_skeletons(self) -> None:
        if not ASSET_ROOT.exists():
            self.assertFalse(ASSET_ROOT.exists())
            return
        import torch
        from transformers import (
            GPT2Config,
            GPT2LMHeadModel,
            GPTNeoXConfig,
            GPTNeoXForCausalLM,
            LlamaConfig,
            LlamaForCausalLM,
        )

        self.assertEqual(__import__("transformers").__version__, "5.14.1")
        classes = {
            "gpt2": (GPT2Config, GPT2LMHeadModel),
            "gpt_neox": (GPTNeoXConfig, GPTNeoXForCausalLM),
            "llama": (LlamaConfig, LlamaForCausalLM),
        }
        for model_key, record in self.layout["models"].items():
            with self.subTest(model=model_key):
                config_object = json.loads(
                    (ASSET_ROOT / model_key / "config.json").read_bytes()
                )
                config_class, model_class = classes[record["modelType"]]
                config = config_class.from_dict(config_object)
                config._attn_implementation = "eager"
                config.use_cache = True
                with torch.device("meta"):
                    model = model_class(config)
                expected = {
                    key: tuple(tensor.shape)
                    for key, tensor in model.state_dict().items()
                }
                source = {
                    key: (tensor["dtype"], tuple(tensor["shape"]))
                    for key, tensor in record["tensors"].items()
                }
                normalized = model_worker._normalized_state_dict_for_loading(
                    source,
                    model_type=record["modelType"],
                    tie_word_embeddings=record["tieWordEmbeddings"],
                )
                replay = independent_model_replay._prepare_exact_state_for_replay(
                    source,
                    model_type=record["modelType"],
                    tied_word_embeddings=record["tieWordEmbeddings"],
                )
                observed = {key: marker[1] for key, marker in normalized.items()}
                self.assertEqual(observed, expected)
                self.assertEqual(
                    {key: marker[1] for key, marker in replay.items()}, expected
                )
                del model

    def test_both_independent_normalizers_match_all_six_exact_headers(self) -> None:
        for model_key, record in self.layout["models"].items():
            with self.subTest(model=model_key):
                markers = {key: object() for key in record["tensors"]}
                worker = model_worker._normalized_state_dict_for_loading(
                    markers,
                    model_type=record["modelType"],
                    tie_word_embeddings=record["tieWordEmbeddings"],
                )
                replay = independent_model_replay._prepare_exact_state_for_replay(
                    markers,
                    model_type=record["modelType"],
                    tied_word_embeddings=record["tieWordEmbeddings"],
                )
                namespace, input_key, ignored, derived_keys = (
                    verify_model_weight_layouts.normalize_keys(
                        set(record["tensors"]),
                        model_type=record["modelType"],
                        tie_word_embeddings=record["tieWordEmbeddings"],
                    )
                )
                self.assertEqual(set(worker), set(replay))
                self.assertEqual(set(worker), derived_keys)
                self.assertEqual(namespace, record["namespacePolicy"])
                self.assertEqual(input_key, record["inputEmbeddingKey"])
                self.assertEqual(ignored, record["ignoredStateKeys"])
                self.assertEqual(len(worker), record["normalizedStateKeyCount"])
                self.assertEqual(
                    key_digest(worker), record["normalizedStateKeysSHA256"]
                )
                self.assertTrue(all(worker[key] is replay[key] for key in worker))
                self.assertTrue(
                    all(key not in worker for key in record["ignoredStateKeys"])
                )
                input_marker = markers.get(record["inputEmbeddingKey"])
                if input_marker is None and record["namespacePolicy"] == "add-transformer-prefix":
                    input_marker = markers["wte.weight"]
                if record["tieWordEmbeddings"]:
                    self.assertIs(worker["lm_head.weight"], input_marker)
                else:
                    self.assertIs(worker["lm_head.weight"], markers["embed_out.weight"])
                    self.assertIsNot(worker["lm_head.weight"], input_marker)

    def test_exact_six_header_arithmetic_proves_two_copy_load_bound(self) -> None:
        dtype_bytes = {"F16": 2, "F32": 4, "U8": 1}
        rss_limit = 4_294_967_296
        current_peaks: dict[str, int] = {}
        reordered_peaks: dict[str, int] = {}
        for model_key, record in self.layout["models"].items():
            tensors = record["tensors"]
            payload_bytes = sum(
                math.prod(tensor["shape"]) * dtype_bytes[tensor["dtype"]]
                for tensor in tensors.values()
            )
            self.assertEqual(
                record["modelFileBytes"], 8 + record["headerBytes"] + payload_bytes
            )
            ignored = set(record["ignoredStateKeys"])
            fp32_model_bytes = sum(
                math.prod(tensor["shape"]) * 4
                for key, tensor in tensors.items()
                if key not in ignored
            )
            current_peaks[model_key] = (
                record["modelFileBytes"] + payload_bytes + fp32_model_bytes
            )
            reordered_peaks[model_key] = max(
                2 * record["modelFileBytes"],
                record["modelFileBytes"] + payload_bytes,
                payload_bytes + fp32_model_bytes,
            )

        self.assertEqual(current_peaks["smollm-360m"], 4_341_886_040)
        self.assertGreater(current_peaks["smollm-360m"], rss_limit)
        self.assertEqual(reordered_peaks["smollm-360m"], 2_894_634_160)
        self.assertEqual(
            max(reordered_peaks, key=reordered_peaks.get), "smollm-360m"
        )
        self.assertLess(max(reordered_peaks.values()), rss_limit)
        self.assertGreater(
            rss_limit - max(reordered_peaks.values()), 1_400_000_000
        )

    def test_owned_safetensors_decode_does_not_retain_input_bytes(self) -> None:
        import safetensors
        import torch
        from safetensors.torch import load as load_safetensors
        from safetensors.torch import save as save_safetensors

        raw = save_safetensors(
            {"fixture-not-a-model": torch.arange(16, dtype=torch.float32)}
        )
        before = sys.getrefcount(raw)
        deserialized = safetensors.deserialize(raw)
        self.assertEqual(sys.getrefcount(raw), before)
        self.assertEqual(len(deserialized), 1)
        self.assertIsInstance(deserialized[0][1]["data"], bytearray)

        for helper in (
            model_worker._decode_owned_weight_state_and_release_input,
            independent_model_replay._decode_replay_state_and_discard_input,
        ):
            with self.subTest(helper=helper.__module__):
                buffers = {"model.safetensors": raw}
                decoder_events: list[str] = []

                def decoder(value: bytes) -> dict[str, object]:
                    self.assertNotIn("model.safetensors", buffers)
                    self.assertIs(value, raw)
                    decoder_events.append("decoded-after-pop")
                    return load_safetensors(value)

                state = helper(buffers, decoder)
                self.assertEqual(decoder_events, ["decoded-after-pop"])
                self.assertNotIn("model.safetensors", buffers)
                self.assertEqual(
                    state["fixture-not-a-model"].tolist(), list(range(16))
                )

    def test_decode_precedes_model_construction_in_both_implementations(self) -> None:
        producer = inspect.getsource(model_worker.load_model_and_tokenizer)
        replay_backend = inspect.getsource(
            independent_model_replay.RealModelReplayBackend.__init__
        )
        replay_runner = inspect.getsource(
            independent_model_replay.run_independent_model_replay
        )
        self.assertLess(
            producer.index("_decode_owned_weight_state_and_release_input"),
            producer.index("model = model_class"),
        )
        self.assertLess(
            replay_backend.index("_decode_replay_state_and_discard_input"),
            replay_backend.index("model = model_class"),
        )
        self.assertNotIn("load_file", producer)
        self.assertNotIn("safe_open", producer)
        self.assertNotIn("load_file", replay_backend)
        self.assertNotIn("safe_open", replay_backend)
        self.assertLess(
            replay_runner.index("backend = RealModelReplayBackend"),
            replay_runner.index('raw_relative = f"workers/{model_key}/'),
        )

    def test_decode_failure_still_consumes_owned_weight_buffer(self) -> None:
        for helper, error in (
            (
                model_worker._decode_owned_weight_state_and_release_input,
                RuntimeError,
            ),
            (
                independent_model_replay._decode_replay_state_and_discard_input,
                RuntimeError,
            ),
        ):
            with self.subTest(helper=helper.__module__):
                buffers = {"model.safetensors": b"fixture-not-a-model"}

                def fail(_value: bytes) -> dict[str, object]:
                    raise RuntimeError("fixture decoder failure")

                with self.assertRaisesRegex(error, "fixture decoder failure"):
                    helper(buffers, fail)
                self.assertNotIn("model.safetensors", buffers)

    def test_replay_implementation_does_not_import_producer_normalizer(self) -> None:
        source = inspect.getsource(independent_model_replay)
        self.assertNotIn("from blind_v1 import model_worker", source)
        self.assertNotIn("_normalized_state_dict_for_loading", source)

    def test_ambiguous_or_incomplete_layouts_fail_closed(self) -> None:
        for normalizer, error, tied_name in (
            (
                model_worker._normalized_state_dict_for_loading,
                model_worker.WorkerError,
                "tie_word_embeddings",
            ),
            (
                independent_model_replay._prepare_exact_state_for_replay,
                independent_model_replay.IndependentModelReplayError,
                "tied_word_embeddings",
            ),
        ):
            with self.subTest(normalizer=normalizer.__module__):
                with self.assertRaises(error):
                    normalizer(
                        {"wte.weight": object(), "transformer.wpe.weight": object()},
                        model_type="gpt2",
                        **{tied_name: True},
                    )
                with self.assertRaises(error):
                    normalizer(
                        {
                            "gpt_neox.embed_in.weight": object(),
                            "embed_out.weight": object(),
                            "lm_head.weight": object(),
                        },
                        model_type="gpt_neox",
                        **{tied_name: False},
                    )
                with self.assertRaises(error):
                    normalizer(
                        {"gpt_neox.embed_in.weight": object()},
                        model_type="gpt_neox",
                        **{tied_name: False},
                    )
                with self.assertRaises(error):
                    normalizer(
                        {
                            "model.embed_tokens.weight": object(),
                            "lm_head.weight": object(),
                        },
                        model_type="llama",
                        **{tied_name: True},
                    )

    def test_scientific_attempt_id_is_exact_and_wrong_prefix_is_rejected(self) -> None:
        valid = "20260821T180000Z-0123456789abcdef"
        wrong_prefix = "20260926T180000Z-0123456789abcdef"
        wrong_time = "20260821T180001Z-0123456789abcdef"
        for pattern in (model_worker.ATTEMPT_ID, independent_model_replay.ATTEMPT_ID):
            self.assertIsNotNone(pattern.fullmatch(valid))
            self.assertIsNone(pattern.fullmatch(wrong_prefix))
            self.assertIsNone(pattern.fullmatch(wrong_time))


if __name__ == "__main__":
    unittest.main()
