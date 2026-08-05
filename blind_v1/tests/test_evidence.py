from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from blind_v1.evidence import (
    CONTAINER_SCHEMA,
    PAGE_TOKEN_SCHEMA,
    RAW_TOKEN_SCHEMA,
    EvidenceError,
    build_sha256_manifest,
    evaluate_raw_evidence,
    float32_from_bits,
    float32_to_bits,
    read_evidence_file,
    require_manifest_paths,
    selected_ledger_token_commitments,
    token_id_stream,
    verify_page_token_evidence,
    verify_sha256_manifest,
)
from blind_v1.protocol import canonical_json_bytes


SUITE = "corelm-blind-crossmodel-v1"
ATTEMPT = "attempt-fixture-only"
MODELS = ["model-a", "model-b", "model-c"]
CORPORA = ["de.wikipedia.org", "fr.wikipedia.org"]
LAYERS = {"model-a": 2, "model-b": 3, "model-c": 4}
BITS = {model: [8] * layers for model, layers in LAYERS.items()}


def page_token_fixture():
    models = ["model-a"]
    corpora = ["de.wikipedia.org", "fr.wikipedia.org"]
    vocabulary_sizes = {"model-a": 1024}
    selected_revisions = {
        corpus: [1000 * (corpus_index + 1) + page for page in range(16)]
        for corpus_index, corpus in enumerate(corpora)
    }
    page_tokens = []
    raw_tokens = []
    ledger = {}
    for corpus in corpora:
        for page_index, revision in enumerate(selected_revisions[corpus]):
            token_ids = [
                (page_index * 17 + token_index) % vocabulary_sizes["model-a"]
                for token_index in range(512)
            ]
            digest = hashlib.sha256(token_id_stream(token_ids)).hexdigest()
            page_tokens.append(
                {
                    "schemaVersion": PAGE_TOKEN_SCHEMA,
                    "suiteId": SUITE,
                    "attemptId": ATTEMPT,
                    "modelKey": "model-a",
                    "corpusProject": corpus,
                    "pageRevisionId": revision,
                    "pageSelectionIndex": page_index,
                    "vocabSize": vocabulary_sizes["model-a"],
                    "first512TokenIds": token_ids,
                    "first512StreamSHA256": digest,
                }
            )
            ledger[(corpus, revision, "model-a")] = {
                "vocabSize": vocabulary_sizes["model-a"],
                "first512StreamSHA256": digest,
            }
            for prediction_index in range(128):
                raw_tokens.append(
                    {
                        "schemaVersion": RAW_TOKEN_SCHEMA,
                        "suiteId": SUITE,
                        "attemptId": ATTEMPT,
                        "modelKey": "model-a",
                        "corpusProject": corpus,
                        "pageRevisionId": revision,
                        "pageSelectionIndex": page_index,
                        "predictionIndex": prediction_index,
                        "targetTokenId": token_ids[384 + prediction_index],
                        "baselineLossF32Bits": float32_to_bits(1.0),
                        "candidateLossF32Bits": float32_to_bits(1.0),
                        "baselineTop1TokenId": 1,
                        "candidateTop1TokenId": 1,
                    }
                )
    return (
        page_tokens,
        raw_tokens,
        models,
        corpora,
        vocabulary_sizes,
        selected_revisions,
        ledger,
    )


def six_model_selected_page_fixture():
    """Six frozen tokenizers validated before binding three selected models."""

    base_pages, base_raw, _models, corpora, _vocabs, revisions, _ledger = (
        page_token_fixture()
    )
    pool_models = [
        "distilgpt2-82m",
        "gpt2-124m",
        "pythia-70m",
        "pythia-160m",
        "smollm-135m",
        "smollm-360m",
    ]
    selected_models = ["smollm-135m", "pythia-70m", "gpt2-124m"]
    tokenizer_vocabs = {
        model: 50277 if model.startswith("pythia-") else 50257
        for model in pool_models
    }
    model_vocabs = {
        model: 50304 if model.startswith("pythia-") else tokenizer_vocabs[model]
        for model in selected_models
    }
    pages = []
    raw = []
    for model in selected_models:
        for item in base_pages:
            pages.append(
                dict(
                    item,
                    modelKey=model,
                    vocabSize=tokenizer_vocabs[model],
                )
            )
        for item in base_raw:
            prediction = dict(item, modelKey=model)
            if model.startswith("pythia-"):
                prediction["baselineTop1TokenId"] = 50303
                prediction["candidateTop1TokenId"] = 50303
            raw.append(prediction)
    full_ledgers = {}
    page_by_identity = {
        (item["corpusProject"], item["pageRevisionId"]): item for item in base_pages
    }
    for corpus in corpora:
        full_ledgers[corpus] = []
        for revision in revisions[corpus]:
            page = page_by_identity[(corpus, revision)]
            tokenizers = {}
            for model in pool_models:
                tokenizers[model] = {
                    "tokenCount": 512,
                    "vocabSize": tokenizer_vocabs[model],
                    "completeStreamSHA256": "a" * 64,
                    "first512StreamSHA256": page["first512StreamSHA256"],
                }
            full_ledgers[corpus].append(
                {"project": corpus, "revid": revision, "tokenizers": tokenizers}
            )
    return (
        pages,
        raw,
        pool_models,
        selected_models,
        corpora,
        tokenizer_vocabs,
        model_vocabs,
        revisions,
        full_ledgers,
    )


def evidence_fixture(*, mismatches_in_first_cell: int = 0):
    raw_tokens = []
    containers = []
    mismatch_budget = mismatches_in_first_cell
    for model_index, model in enumerate(MODELS):
        for corpus_index, corpus in enumerate(CORPORA):
            for page in range(16):
                revision = 100000 + model_index * 10000 + corpus_index * 1000 + page
                for prediction in range(128):
                    mismatch = (
                        model_index == 0
                        and corpus_index == 0
                        and mismatch_budget > 0
                    )
                    if mismatch:
                        mismatch_budget -= 1
                    raw_tokens.append(
                        {
                            "schemaVersion": RAW_TOKEN_SCHEMA,
                            "suiteId": SUITE,
                            "attemptId": ATTEMPT,
                            "modelKey": model,
                            "corpusProject": corpus,
                            "pageRevisionId": revision,
                            "pageSelectionIndex": page,
                            "predictionIndex": prediction,
                            "targetTokenId": 7,
                            "baselineLossF32Bits": float32_to_bits(1.0),
                            "candidateLossF32Bits": float32_to_bits(1.0001),
                            "baselineTop1TokenId": 11,
                            "candidateTop1TokenId": 12 if mismatch else 11,
                        }
                    )
                for layer in range(LAYERS[model]):
                    relative = f"containers/{model}/{corpus}/{page:02d}/{layer:02d}.vtl5"
                    containers.append(
                        {
                            "schemaVersion": CONTAINER_SCHEMA,
                            "suiteId": SUITE,
                            "attemptId": ATTEMPT,
                            "modelKey": model,
                            "corpusProject": corpus,
                            "pageRevisionId": revision,
                            "pageSelectionIndex": page,
                            "layerIndex": layer,
                            "denseBF16Bytes": 2500,
                            "containerBytes": 1000,
                            "containerSHA256": f"{len(containers) + 1:064x}",
                            "relativePath": relative,
                            "structuralReplay": True,
                        }
                    )
    return raw_tokens, containers


class EvidenceTests(unittest.TestCase):
    def evaluate(self, raw_tokens, containers):
        return evaluate_raw_evidence(
            raw_tokens,
            containers,
            suite_id=SUITE,
            attempt_id=ATTEMPT,
            models=MODELS,
            corpora=CORPORA,
            layer_counts=LAYERS,
            bits_by_model=BITS,
        )

    def test_exact_float32_bit_round_trip(self) -> None:
        encoded = float32_to_bits(1.25)
        self.assertEqual(encoded, "3fa00000")
        self.assertEqual(float32_from_bits(encoded, "subject"), 1.25)
        with self.assertRaises(EvidenceError):
            float32_from_bits("7f800000", "infinity")

    def verify_page_tokens(self, page_tokens, raw_tokens, fixture) -> dict:
        _, _, models, corpora, vocabularies, revisions, ledger = fixture
        return verify_page_token_evidence(
            page_tokens,
            raw_tokens,
            suite_id=SUITE,
            attempt_id=ATTEMPT,
            models=models,
            corpora=corpora,
            tokenizer_vocabulary_sizes=vocabularies,
            model_vocabulary_sizes=vocabularies,
            selected_revisions=revisions,
            ledger_token_commitments=ledger,
        )

    def test_page_tokens_bind_exact_stream_ledger_and_raw_targets(self) -> None:
        fixture = page_token_fixture()
        result = self.verify_page_tokens(fixture[0], fixture[1], fixture)
        self.assertEqual(result["pages"], 32)
        self.assertEqual(result["tokensPerPage"], 512)

    def test_shifted_page_stream_is_rejected_against_the_frozen_ledger(self) -> None:
        fixture = page_token_fixture()
        page_tokens = [dict(item) for item in fixture[0]]
        shifted = list(page_tokens[0]["first512TokenIds"])
        shifted = shifted[1:] + shifted[:1]
        page_tokens[0]["first512TokenIds"] = shifted
        page_tokens[0]["first512StreamSHA256"] = hashlib.sha256(
            token_id_stream(shifted)
        ).hexdigest()
        with self.assertRaisesRegex(EvidenceError, "exact full ledger"):
            self.verify_page_tokens(page_tokens, fixture[1], fixture)

    def test_page_token_id_equal_to_vocab_size_is_rejected(self) -> None:
        fixture = page_token_fixture()
        page_tokens = [dict(item) for item in fixture[0]]
        token_ids = list(page_tokens[0]["first512TokenIds"])
        token_ids[0] = fixture[4]["model-a"]
        page_tokens[0]["first512TokenIds"] = token_ids
        page_tokens[0]["first512StreamSHA256"] = hashlib.sha256(
            token_id_stream(token_ids)
        ).hexdigest()
        with self.assertRaisesRegex(EvidenceError, "outside the registered vocabulary"):
            self.verify_page_tokens(page_tokens, fixture[1], fixture)

    def test_raw_prediction_id_equal_to_vocab_size_is_rejected(self) -> None:
        fixture = page_token_fixture()
        for field in (
            "targetTokenId",
            "baselineTop1TokenId",
            "candidateTop1TokenId",
        ):
            with self.subTest(field=field):
                raw_tokens = [dict(item) for item in fixture[1]]
                raw_tokens[0][field] = fixture[4]["model-a"]
                with self.assertRaisesRegex(
                    EvidenceError, r"outside the registered .* vocabulary"
                ):
                    self.verify_page_tokens(fixture[0], raw_tokens, fixture)

    def test_tokenizer_and_model_vocabulary_domains_are_distinct(self) -> None:
        fixture = page_token_fixture()
        original_pages, raw_tokens, models, corpora, _vocabs, revisions, original_ledger = fixture
        tokenizer_vocabulary_sizes = {"model-a": 50277}
        model_vocabulary_sizes = {"model-a": 50304}
        page_tokens = [dict(item, vocabSize=50277) for item in original_pages]
        ledger = {
            identity: dict(commitment, vocabSize=50277)
            for identity, commitment in original_ledger.items()
        }

        valid_top1 = [dict(item) for item in raw_tokens]
        valid_top1[0]["baselineTop1TokenId"] = 50303
        valid_top1[0]["candidateTop1TokenId"] = 50303
        verify_page_token_evidence(
            page_tokens,
            valid_top1,
            suite_id=SUITE,
            attempt_id=ATTEMPT,
            models=models,
            corpora=corpora,
            tokenizer_vocabulary_sizes=tokenizer_vocabulary_sizes,
            model_vocabulary_sizes=model_vocabulary_sizes,
            selected_revisions=revisions,
            ledger_token_commitments=ledger,
        )

        invalid_target = [dict(item) for item in raw_tokens]
        invalid_target[0]["targetTokenId"] = 50277
        with self.assertRaisesRegex(EvidenceError, "tokenizer vocabulary"):
            verify_page_token_evidence(
                page_tokens,
                invalid_target,
                suite_id=SUITE,
                attempt_id=ATTEMPT,
                models=models,
                corpora=corpora,
                tokenizer_vocabulary_sizes=tokenizer_vocabulary_sizes,
                model_vocabulary_sizes=model_vocabulary_sizes,
                selected_revisions=revisions,
                ledger_token_commitments=ledger,
        )

        invalid_top1 = [dict(item) for item in raw_tokens]
        invalid_top1[0]["baselineTop1TokenId"] = 50304
        with self.assertRaisesRegex(EvidenceError, "model vocabulary"):
            verify_page_token_evidence(
                page_tokens,
                invalid_top1,
                suite_id=SUITE,
                attempt_id=ATTEMPT,
                models=models,
                corpora=corpora,
                tokenizer_vocabulary_sizes=tokenizer_vocabulary_sizes,
                model_vocabulary_sizes=model_vocabulary_sizes,
                selected_revisions=revisions,
                ledger_token_commitments=ledger,
            )

    def test_raw_target_must_equal_positions_384_through_511(self) -> None:
        fixture = page_token_fixture()
        raw_tokens = [dict(item) for item in fixture[1]]
        raw_tokens[0]["targetTokenId"] = (
            raw_tokens[0]["targetTokenId"] + 1
        ) % fixture[4]["model-a"]
        with self.assertRaisesRegex(EvidenceError, r"positions 384\.\.511"):
            self.verify_page_tokens(fixture[0], raw_tokens, fixture)

    def test_full_ledgers_are_validated_before_selected_commitments_are_used(self) -> None:
        fixture = page_token_fixture()
        _, _, models, corpora, vocabularies, revisions, expected = fixture
        ledgers = {}
        for corpus in corpora:
            ledgers[corpus] = []
            for revision in revisions[corpus]:
                commitment = expected[(corpus, revision, "model-a")]
                ledgers[corpus].append(
                    {
                        "project": corpus,
                        "revid": revision,
                        "tokenizers": {
                            "model-a": {
                                "tokenCount": 512,
                                "vocabSize": commitment["vocabSize"],
                                "completeStreamSHA256": "a" * 64,
                                "first512StreamSHA256": commitment[
                                    "first512StreamSHA256"
                                ],
                            }
                        },
                    }
                )
        observed = selected_ledger_token_commitments(
            ledgers,
            models=models,
            selected_models=models,
            vocabulary_sizes=vocabularies,
            selected_revisions=revisions,
        )
        self.assertEqual(observed, expected)
        ledgers[corpora[0]][0]["tokenizers"]["model-a"]["vocabSize"] = 1025
        with self.assertRaisesRegex(EvidenceError, "token count/vocabSize"):
            selected_ledger_token_commitments(
                ledgers,
                models=models,
                selected_models=models,
                vocabulary_sizes=vocabularies,
                selected_revisions=revisions,
            )

    def test_six_model_ledger_is_validated_then_three_models_are_bound(self) -> None:
        (
            pages,
            raw,
            pool_models,
            selected_models,
            corpora,
            pool_tokenizer_vocabs,
            selected_model_vocabs,
            revisions,
            full_ledgers,
        ) = six_model_selected_page_fixture()
        commitments = selected_ledger_token_commitments(
            full_ledgers,
            models=pool_models,
            selected_models=selected_models,
            vocabulary_sizes=pool_tokenizer_vocabs,
            selected_revisions=revisions,
        )
        self.assertEqual({identity[2] for identity in commitments}, set(selected_models))
        observed = verify_page_token_evidence(
            pages,
            raw,
            suite_id=SUITE,
            attempt_id=ATTEMPT,
            models=selected_models,
            corpora=corpora,
            tokenizer_vocabulary_sizes={
                model: pool_tokenizer_vocabs[model] for model in selected_models
            },
            model_vocabulary_sizes=selected_model_vocabs,
            selected_revisions=revisions,
            ledger_token_commitments=commitments,
        )
        self.assertEqual(observed["pages"], 96)

    def test_all_six_cells_and_models_pass(self) -> None:
        raw_tokens, containers = evidence_fixture()
        result = self.evaluate(raw_tokens, containers)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(len(result["cells"]), 6)
        self.assertEqual(len(result["modelAggregates"]), 3)
        self.assertTrue(all(cell["compressionRatioVsBF16"] == 2.5 for cell in result["cells"]))

    def test_one_failing_cell_cannot_be_averaged_away(self) -> None:
        raw_tokens, containers = evidence_fixture(mismatches_in_first_cell=22)
        result = self.evaluate(raw_tokens, containers)
        self.assertEqual(result["verdict"], "FAIL_GATES")
        failures = [cell for cell in result["cells"] if not cell["pass"]]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["modelKey"], "model-a")

    def test_missing_token_is_rejected(self) -> None:
        raw_tokens, containers = evidence_fixture()
        raw_tokens.pop()
        with self.assertRaisesRegex(EvidenceError, "2,048"):
            self.evaluate(raw_tokens, containers)

    def test_duplicate_container_is_rejected(self) -> None:
        raw_tokens, containers = evidence_fixture()
        containers.append(dict(containers[0]))
        with self.assertRaisesRegex(EvidenceError, "duplicate container"):
            self.evaluate(raw_tokens, containers)

    def test_revision_binding_crosses_token_and_container_evidence(self) -> None:
        raw_tokens, containers = evidence_fixture()
        containers[0]["pageRevisionId"] += 1
        with self.assertRaisesRegex(EvidenceError, "revision differs"):
            self.evaluate(raw_tokens, containers)

    def test_manifest_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"evidence")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(EvidenceError):
                build_sha256_manifest(root, ["link"])

    def test_manifest_coverage_is_explicit_and_safe_reads_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "raw.jsonl").write_bytes(b"{}\n")
            manifest = build_sha256_manifest(root, ["raw.jsonl"])
            require_manifest_paths(manifest, ["raw.jsonl"])
            with self.assertRaisesRegex(EvidenceError, "omits required"):
                require_manifest_paths(manifest, ["raw.jsonl", "missing.vtl5"])
            self.assertEqual(
                read_evidence_file(root, "raw.jsonl", maximum_bytes=3), b"{}\n"
            )
            with self.assertRaisesRegex(EvidenceError, "outside its bound"):
                read_evidence_file(root, "raw.jsonl", maximum_bytes=2)

    def test_manifest_itself_must_be_beneath_the_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            evidence_root = parent / "evidence"
            evidence_root.mkdir()
            (evidence_root / "raw.jsonl").write_bytes(b"{}\n")
            manifest = build_sha256_manifest(evidence_root, ["raw.jsonl"])
            manifest_path = evidence_root / "evidence-manifest.json"
            manifest_path.write_bytes(
                canonical_json_bytes(manifest) + b"\n"
            )
            observed, _ = verify_sha256_manifest(evidence_root, manifest_path)
            self.assertEqual(observed, manifest)
            outside = parent / "outside.json"
            outside.write_bytes(manifest_path.read_bytes())
            with self.assertRaisesRegex(EvidenceError, "escapes"):
                verify_sha256_manifest(evidence_root, outside)


if __name__ == "__main__":
    unittest.main()
