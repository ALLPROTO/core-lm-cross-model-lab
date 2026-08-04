from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path

import numpy as np

from v4 import independent_model_replay as subject


SUITE = subject.SUITE_ID
ATTEMPT = "20260926T180000Z-0123456789abcdef"
MODEL = "fixture-model-not-scientific"
CORPUS = "en.wikipedia.org"
REVISION = 123


def _field(value: str) -> bytes:
    raw = value.encode("utf-8")
    return len(raw).to_bytes(8, "big") + raw


def corpus_record() -> bytes:
    return b"".join(
        (
            subject.RECORD_MAGIC,
            _field(CORPUS),
            (1).to_bytes(8, "big"),
            REVISION.to_bytes(8, "big"),
            (2).to_bytes(8, "big"),
            _field("2026-08-12T12:00:00Z"),
            _field("fixture-user"),
            _field("Fixture title"),
            _field("Fixture content used only by unit tests."),
        )
    )


class FakeBackend:
    """Fast validation seam; production entry point cannot select this backend."""

    vocab_size = 8
    layers = 2
    trajectory_width = 128

    def __init__(self) -> None:
        self.token_ids = [index % self.vocab_size for index in range(512)]

    def tokenize(self, _text: str) -> list[int]:
        return list(self.token_ids)

    def baseline_cache(self, _prefix_ids: list[int]) -> list[np.ndarray]:
        return [
            np.zeros((subject.PREFILL_TOKENS, self.trajectory_width), dtype=np.float32)
            for _ in range(self.layers)
        ]

    def evaluate(
        self,
        _continuation_ids: list[int],
        targets: list[int],
        _baseline_layers: list[np.ndarray],
        _candidate_layers: list[np.ndarray],
    ) -> list[dict[str, object]]:
        return [
            {
                "targetTokenId": target,
                "baselineLossF32Bits": subject.float32_bits(1.0 + index / 1024),
                "candidateLossF32Bits": subject.float32_bits(1.1 + index / 1024),
                "baselineTop1TokenId": index % self.vocab_size,
                "candidateTop1TokenId": (index + 1) % self.vocab_size,
            }
            for index, target in enumerate(targets)
        ]


def fixture() -> dict[str, object]:
    backend = FakeBackend()
    tokens = backend.tokenize("ignored")
    identity = {
        "suiteId": SUITE,
        "attemptId": ATTEMPT,
        "modelKey": MODEL,
        "corpusProject": CORPUS,
        "pageRevisionId": REVISION,
        "pageSelectionIndex": 0,
    }
    page = {
        "schemaVersion": subject.PAGE_TOKEN_SCHEMA,
        **identity,
        "vocabSize": backend.vocab_size,
        "first512TokenIds": tokens,
        "first512StreamSHA256": subject.sha256_bytes(
            subject.token_id_stream(tokens)
        ),
    }
    targets = tokens[subject.PREFILL_TOKENS + 1 :]
    computed = backend.evaluate([], targets, [], [])
    raw = [
        {
            "schemaVersion": subject.RAW_TOKEN_SCHEMA,
            **identity,
            "predictionIndex": index,
            **metrics,
        }
        for index, metrics in enumerate(computed)
    ]
    container_payloads: dict[str, bytes] = {}
    containers = []
    for layer_index in range(backend.layers):
        relative = (
            f"containers/{MODEL}/{CORPUS}/revision-{REVISION}/"
            f"layer-{layer_index:02d}.vtl5"
        )
        payload = f"fixture-container-{layer_index}".encode("ascii")
        container_payloads[relative] = payload
        containers.append(
            {
                "schemaVersion": subject.CONTAINER_SCHEMA,
                **identity,
                "layerIndex": layer_index,
                "denseBF16Bytes": (
                    subject.PREFILL_TOKENS * backend.trajectory_width * 2
                ),
                "containerBytes": len(payload),
                "containerSHA256": subject.sha256_bytes(payload),
                "relativePath": relative,
                "structuralReplay": True,
            }
        )

    def reader(record: dict[str, object]) -> bytes:
        return container_payloads[str(record["relativePath"])]

    def decoder(_raw: bytes, **expected: object):
        array = np.zeros(
            (
                int(expected["expected_rows"]),
                int(expected["expected_columns"]),
            ),
            dtype=np.float32,
        )
        return array, {
            "inputSha256": expected["expected_input_sha256"],
            "reconstructionSha256": subject._float32_sha256(array),
        }

    return {
        "backend": backend,
        "suite_id": SUITE,
        "attempt_id": ATTEMPT,
        "model_key": MODEL,
        "corpus": CORPUS,
        "page_index": 0,
        "revision": REVISION,
        "record_raw": corpus_record(),
        "page_evidence": page,
        "raw_evidence": raw,
        "container_evidence": containers,
        "candidate": {
            "backend": "voidtoken-v5",
            "groupSize": 128,
            "transformBlockSize": 128,
            "codeCompression": "zlib-9",
            "scaleCompression": "zlib-9",
            "signMode": "none",
        },
        "bits_by_layer": [8, 9],
        "container_reader": reader,
        "container_decoder": decoder,
    }


def zero_vtl5_container(*, input_sha256: str) -> bytes:
    rows = 3
    columns = 128
    bits = 8
    scale_raw = np.zeros((rows, 1), dtype=np.dtype("<f2")).tobytes()
    code_raw = bytes(rows * columns)
    stored_scales = zlib.compress(scale_raw, level=9)
    stored_codes = zlib.compress(code_raw, level=9)
    payload = stored_scales + stored_codes
    reconstruction = np.zeros((rows, columns), dtype=np.float32)
    metadata = {
        "bits": bits,
        "codeCompression": "zlib-9",
        "codeCount": rows * columns,
        "codeMapping": "zigzag-symmetric-v1",
        "dtype": "float32",
        "format": "voidtoken-rotated-entropy-v5",
        "groupSize": 128,
        "groupsPerRow": 1,
        "inputSha256": input_sha256,
        "layerIndex": 0,
        "packedBytes": len(code_raw),
        "packing": "lsb-first-v1",
        "payloadBytes": len(payload),
        "payloadSha256": subject.sha256_bytes(payload),
        "quantization": "symmetric-max-abs-v1",
        "reconstructionSha256": subject._float32_sha256(reconstruction),
        "scaleBytes": len(scale_raw),
        "scaleCompression": "zlib-9",
        "scaleCount": rows,
        "scaleDtype": "float16-le",
        "shape": [rows, columns],
        "signDerivation": "shake256-layer-column-v1",
        "signMode": "none",
        "storedCodeBytes": len(stored_codes),
        "storedScaleBytes": len(stored_scales),
        "transform": "normalized-walsh-hadamard-v1",
        "transformBlockSize": 128,
    }
    metadata_raw = subject.canonical_json_bytes(metadata)
    return b"VTL5" + len(metadata_raw).to_bytes(4, "little") + metadata_raw + payload


class IndependentModelReplayTests(unittest.TestCase):
    def test_fake_page_seam_exactly_accepts_consistent_fixture(self) -> None:
        result = subject.replay_page(**fixture())
        self.assertEqual(result["predictions"], 128)
        self.assertEqual(result["containers"], 2)

    def test_forged_loss_or_top1_is_rejected(self) -> None:
        for field, value in (
            ("baselineLossF32Bits", subject.float32_bits(99.0)),
            ("candidateTop1TokenId", 7),
        ):
            with self.subTest(field=field):
                values = fixture()
                forged = copy.deepcopy(values["raw_evidence"])
                forged[0][field] = value
                values["raw_evidence"] = forged
                with self.assertRaisesRegex(
                    subject.IndependentModelReplayError,
                    f"prediction 0/{field}",
                ):
                    subject.replay_page(**values)

    def test_forged_retokenization_is_rejected(self) -> None:
        values = fixture()
        page = copy.deepcopy(values["page_evidence"])
        page["first512TokenIds"][0] = 7
        page["first512StreamSHA256"] = subject.sha256_bytes(
            subject.token_id_stream(page["first512TokenIds"])
        )
        values["page_evidence"] = page
        with self.assertRaisesRegex(
            subject.IndependentModelReplayError, "retokenized IDs"
        ):
            subject.replay_page(**values)

    def test_forged_container_mapping_is_rejected(self) -> None:
        values = fixture()
        containers = copy.deepcopy(values["container_evidence"])
        containers[0]["relativePath"] = containers[1]["relativePath"]
        values["container_evidence"] = containers
        with self.assertRaisesRegex(
            subject.IndependentModelReplayError, "container-to-page/layer mapping"
        ):
            subject.replay_page(**values)

    def test_forged_weight_bytes_are_rejected_before_backend_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "models" / "fixture" / "model.safetensors"
            path.parent.mkdir(parents=True)
            original = b"frozen-weight-bytes"
            path.write_bytes(original)
            committed = hashlib.sha256(original).hexdigest()
            path.write_bytes(b"forged-weight-bytes")
            with self.assertRaisesRegex(
                subject.IndependentModelReplayError, "SHA-256 differs"
            ):
                subject.read_beneath(
                    root,
                    "models/fixture/model.safetensors",
                    maximum_bytes=1024,
                    expected_bytes=len(b"forged-weight-bytes"),
                    expected_sha256=committed,
                )

    def test_independent_vtl5_decoder_binds_container_to_baseline(self) -> None:
        baseline = np.zeros((3, 128), dtype=np.float32)
        digest = subject._float32_sha256(baseline)
        raw = zero_vtl5_container(input_sha256=digest)
        decoded, _metadata = subject.decode_vtl5_container(
            raw,
            expected_layer=0,
            expected_bits=8,
            expected_rows=3,
            expected_columns=128,
            expected_group_size=128,
            expected_transform_block_size=128,
            expected_sign_mode="none",
            expected_input_sha256=digest,
        )
        self.assertTrue(np.array_equal(decoded, baseline))
        with self.assertRaisesRegex(
            subject.IndependentModelReplayError, "container-to-cache mapping"
        ):
            subject.decode_vtl5_container(
                raw,
                expected_layer=0,
                expected_bits=8,
                expected_rows=3,
                expected_columns=128,
                expected_group_size=128,
                expected_transform_block_size=128,
                expected_sign_mode="none",
                expected_input_sha256="f" * 64,
            )


if __name__ == "__main__":
    unittest.main()
