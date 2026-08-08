from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from blind_v1 import development_corpus as subject


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _block(sent_id: str, text: str, word: str) -> bytes:
    return (
        f"# sent_id = {sent_id}\n"
        f"# text = {text}\n"
        f"1\t{word}\t{word.lower()}\tNOUN\tNN\t_\t0\troot\t0:root\t"
        "SpaceAfter=No\n"
        "2\t.\t.\tPUNCT\t.\t_\t1\tpunct\t1:punct\t_"
    ).encode("utf-8")


@contextmanager
def _fixture_identity(raw: bytes, texts: list[str]):
    joined = "\n\n".join(texts).encode("utf-8")
    with mock.patch.multiple(
        subject,
        SOURCE_BYTES=len(raw),
        SOURCE_SHA256=hashlib.sha256(raw).hexdigest(),
        SENTENCE_COUNT=len(texts),
        JOINED_TEXT_BYTES=len(joined),
        JOINED_TEXT_SHA256=hashlib.sha256(joined).hexdigest(),
    ):
        yield


class DevelopmentCorpusTests(unittest.TestCase):
    def test_exact_upstream_constants_and_tracked_rights_bytes(self) -> None:
        self.assertEqual(subject.RELEASE_TAG, "r2.18")
        self.assertEqual(
            subject.REVISION, "e173a1be1b442faf34e7d5a502189ad5d9d1e197"
        )
        self.assertEqual(subject.TREE, "50f2ebe00ff016d2dca93f9bf6ee51c5f8493fde")
        self.assertEqual(subject.SPLIT, "test")
        self.assertEqual(subject.SENTENCE_COUNT, 1_000)
        self.assertEqual(subject.SOURCE_BYTES, 1_386_858)
        self.assertEqual(
            subject.SOURCE_SHA256,
            "c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa",
        )
        self.assertEqual(subject.JOINED_TEXT_BYTES, 112_419)
        self.assertEqual(
            subject.JOINED_TEXT_SHA256,
            "69dd039b37979f91b165981e92ae578067ecdf0db69bbee0a431c9f337c0f8ea",
        )

        draft = json.loads(
            (PROJECT_ROOT / "blind_v1/development-corpus.draft.json").read_bytes()
        )
        self.assertEqual(draft["datasetId"], subject.DATASET_ID)
        self.assertEqual(draft["repository"], subject.REPOSITORY)
        self.assertEqual(draft["revision"], subject.REVISION)
        self.assertEqual(draft["queriedAtUTC"], "2026-08-03T23:02:05Z")
        self.assertEqual(draft["releaseTag"], subject.RELEASE_TAG)
        self.assertEqual(draft["split"], subject.SPLIT)
        self.assertEqual(draft["file"], subject.FILE)
        self.assertEqual(draft["bytes"], subject.SOURCE_BYTES)
        self.assertEqual(draft["sha256"], subject.SOURCE_SHA256)
        self.assertEqual(draft["rows"], subject.SENTENCE_COUNT)
        self.assertEqual(draft["joinedTextBytes"], subject.JOINED_TEXT_BYTES)
        self.assertEqual(draft["joinedTextSHA256"], subject.JOINED_TEXT_SHA256)
        self.assertIs(draft["contentSynthetic"], False)

        readme = (
            PROJECT_ROOT / "LICENSES" / subject.README_ARCHIVED_PATH
        ).read_bytes()
        license_raw = (
            PROJECT_ROOT / "LICENSES" / subject.LICENSE_ARCHIVED_PATH
        ).read_bytes()
        attribution = (
            PROJECT_ROOT / "LICENSES" / subject.ATTRIBUTION_ARCHIVED_PATH
        ).read_bytes()
        for raw, size, digest in (
            (readme, subject.README_BYTES, subject.README_SHA256),
            (license_raw, subject.LICENSE_BYTES, subject.LICENSE_SHA256),
            (attribution, subject.ATTRIBUTION_BYTES, subject.ATTRIBUTION_SHA256),
        ):
            self.assertEqual(len(raw), size)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_rights_verifier_binds_exact_entries_and_raw_notices(self) -> None:
        entries = list(subject.expected_source_evidence_entries())
        evidence = {
            "schemaVersion": subject.SOURCE_EVIDENCE_SCHEMA,
            "status": subject.SOURCE_EVIDENCE_STATUS,
            "retrievedAt": "2026-08-04T00:00:00Z",
            "sources": entries,
        }
        readme = (
            PROJECT_ROOT / "LICENSES" / subject.README_ARCHIVED_PATH
        ).read_bytes()
        license_raw = (
            PROJECT_ROOT / "LICENSES" / subject.LICENSE_ARCHIVED_PATH
        ).read_bytes()
        attribution = (
            PROJECT_ROOT / "LICENSES" / subject.ATTRIBUTION_ARCHIVED_PATH
        ).read_bytes()
        self.assertEqual(
            subject.verify_rights_evidence(
                evidence, readme, license_raw, attribution
            ),
            subject.RIGHTS_STATUS,
        )
        self.assertIn("NO_OWNERSHIP", subject.RIGHTS_SCOPE)

        changed = json.loads(json.dumps(evidence))
        changed["sources"][0]["bytes"] += 1
        with self.assertRaises(subject.DevelopmentCorpusError):
            subject.verify_rights_evidence(
                changed, readme, license_raw, attribution
            )
        with self.assertRaises(subject.DevelopmentCorpusError):
            subject.verify_rights_evidence(
                evidence, readme + b"x", license_raw, attribution
            )
        with self.assertRaises(subject.DevelopmentCorpusError):
            subject.verify_rights_evidence(
                evidence, readme, license_raw, attribution + b"x"
            )

    def test_strict_conllu_parser_and_two_lf_join(self) -> None:
        texts = ["Alpha.", "Béta."]
        raw = (
            _block("pud-a", texts[0], "Alpha")
            + b"\n\n"
            + _block("pud-b", texts[1], "Béta")
            + b"\n\n"
        )
        with _fixture_identity(raw, texts):
            records = subject.parse_corpus(raw)
        self.assertEqual([record.index for record in records], [0, 1])
        self.assertEqual([record.sent_id for record in records], ["pud-a", "pud-b"])
        self.assertEqual([record.text for record in records], texts)
        self.assertEqual(subject.joined_text(records), "Alpha.\n\nBéta.".encode())

        malformed = raw.replace(b"# text = B", b"# text = copy\n# text = B")
        with _fixture_identity(malformed, texts):
            with self.assertRaises(subject.DevelopmentCorpusError):
                subject.parse_corpus(malformed)
        no_terminal = raw[:-1]
        with _fixture_identity(no_terminal, texts):
            with self.assertRaisesRegex(
                subject.DevelopmentCorpusError, "exactly two LF"
            ):
                subject.parse_corpus(no_terminal)
        three_terminal = raw + b"\n"
        with _fixture_identity(three_terminal, texts):
            with self.assertRaisesRegex(
                subject.DevelopmentCorpusError, "exactly two LF"
            ):
                subject.parse_corpus(three_terminal)
        malformed_row = raw.replace(b"\t0\troot", b" 0 root", 1)
        with _fixture_identity(malformed_row, texts):
            with self.assertRaisesRegex(
                subject.DevelopmentCorpusError, "malformed CoNLL-U row"
            ):
                subject.parse_corpus(malformed_row)

    def test_partition_bounds_and_record_round_trip(self) -> None:
        bounds = subject.partition_bounds()
        self.assertEqual(len(bounds), 32)
        self.assertEqual(bounds[0], (0, 31))
        self.assertEqual(bounds[-1], (968, 1000))
        self.assertEqual({end - start for start, end in bounds}, {31, 32})
        self.assertEqual(
            [start for start, _ in bounds[1:]],
            [end for _, end in bounds[:-1]],
        )

        content = "Alpha.\n\nBéta."
        raw = subject.serialize_record(
            sentence_start=0, sentence_end=2, content=content
        )
        self.assertEqual(
            subject.parse_record(raw),
            {
                "datasetId": subject.DATASET_ID,
                "repository": subject.REPOSITORY,
                "releaseTag": subject.RELEASE_TAG,
                "revision": subject.REVISION,
                "tree": subject.TREE,
                "split": subject.SPLIT,
                "file": subject.FILE,
                "sourceSHA256": subject.SOURCE_SHA256,
                "joinedTextSHA256": subject.JOINED_TEXT_SHA256,
                "sentenceStart": 0,
                "sentenceEnd": 2,
                "content": content,
            },
        )
        with self.assertRaises(subject.DevelopmentCorpusError):
            subject.parse_record(raw + b"x")
        with self.assertRaises(subject.DevelopmentCorpusError):
            subject.serialize_record(
                sentence_start=999, sentence_end=1001, content="out of range"
            )


if __name__ == "__main__":
    unittest.main()
