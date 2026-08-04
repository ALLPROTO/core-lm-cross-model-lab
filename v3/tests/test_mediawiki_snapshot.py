from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from v3 import mediawiki_snapshot as subject


SERVER_DATE = "Mon, 31 Aug 2026 06:00:01 GMT"


def response(uri: str, body_value: object, *, date: str = SERVER_DATE) -> subject.ArchivedHTTPResponse:
    body = subject.canonical_json_bytes(body_value)
    headers = (
        "HTTP/1.1 200 OK\r\n"
        f"Date: {date}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return subject.ArchivedHTTPResponse(uri, 200, headers, body)


def change(project_index: int, index: int) -> dict[str, object]:
    revid = (project_index + 1) * 1_000_000 + index + 1
    title = f"Fixture page {project_index}-{index}"
    content = f"fixture {project_index} {index} " + "x" * 640
    return {
        "type": "new",
        "ns": 0,
        "title": title,
        "pageid": (project_index + 1) * 100_000 + index + 1,
        "revid": revid,
        "old_revid": 0,
        "rcid": (project_index + 1) * 10_000_000 + index + 1,
        "user": f"Fixture author {index}",
        "userid": index + 1,
        "timestamp": f"2026-08-16T00:{index // 60:02d}:{index % 60:02d}Z",
        "redirect": False,
        "sha1": hashlib.sha1(content.encode("utf-8")).hexdigest(),
        "_content": content,
    }


def public_change(value: dict[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


def revision_response(value: dict[str, object]) -> dict[str, object]:
    return {
        "batchcomplete": True,
        "query": {
            "pages": [
                {
                    "pageid": value["pageid"],
                    "ns": 0,
                    "title": value["title"],
                    "revisions": [
                        {
                            "revid": value["revid"],
                            "parentid": 0,
                            "timestamp": value["timestamp"],
                            "user": value["user"],
                            "userid": value["userid"],
                            "sha1": value["sha1"],
                            "slots": {
                                "main": {
                                    "sha1": value["sha1"],
                                    "contentmodel": "wikitext",
                                    "contentformat": "text/x-wiki",
                                    "content": value["_content"],
                                }
                            },
                        }
                    ],
                }
            ]
        },
    }


class FixtureTokenizer:
    vocab_size = 1024

    def __init__(self, count: int = 512) -> None:
        self.count = count
        self.calls: list[tuple[str, bool]] = []

    def encode(self, text: str, *, add_special_tokens: bool) -> list[int]:
        self.calls.append((text, add_special_tokens))
        return [index % self.vocab_size for index in range(self.count)]


class SmartTransport:
    def __init__(self, records: dict[str, list[dict[str, object]]]) -> None:
        self.records = records
        self.by_revision = {
            int(item["revid"]): item
            for values in records.values()
            for item in values
        }
        self.uris: list[str] = []

    def __call__(self, uri: str) -> subject.ArchivedHTTPResponse:
        self.uris.append(uri)
        parsed = urlsplit(uri)
        query = parse_qs(parsed.query, strict_parsing=True)
        if query.get("list") == ["recentchanges"]:
            value = {
                "batchcomplete": True,
                "query": {
                    "recentchanges": [
                        public_change(item) for item in self.records[parsed.hostname]
                    ]
                },
            }
        elif query.get("prop") == ["revisions"]:
            revid = int(query["revids"][0])
            value = revision_response(self.by_revision[revid])
        else:
            raise AssertionError(f"unexpected URI: {uri}")
        return response(uri, value)


class MediaWikiSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    @staticmethod
    def clock() -> datetime:
        return datetime(2026, 8, 31, 6, 0, 2, tzinfo=timezone.utc)

    def collect_two_stages(
        self,
        transport: subject.Transport,
    ) -> None:
        subject.collect_crawl_stage(
            root=self.root,
            crawl_index=0,
            transport=transport,
            clock=lambda: datetime(2026, 8, 30, 6, 0, 2, tzinfo=timezone.utc),
        )
        subject.collect_crawl_stage(
            root=self.root,
            crawl_index=1,
            transport=transport,
            clock=self.clock,
        )

    def test_record_serialization_round_trip_is_exact_and_strict(self) -> None:
        value = subject.serialize_record(
            project="en.wikipedia.org",
            pageid=1,
            revid=2,
            userid=0,
            timestamp="2026-08-16T00:00:00Z",
            username="192.0.2.1",
            title="Title é",
            content="raw\n{{wikitext}}",
        )
        self.assertTrue(value.startswith(subject.RECORD_MAGIC))
        self.assertEqual(
            subject.parse_record(value),
            {
                "project": "en.wikipedia.org",
                "pageid": 1,
                "revid": 2,
                "userid": 0,
                "timestamp": "2026-08-16T00:00:00Z",
                "username": "192.0.2.1",
                "title": "Title é",
                "content": "raw\n{{wikitext}}",
            },
        )
        with self.assertRaisesRegex(subject.SnapshotError, "trailing"):
            subject.parse_record(value + b"x")
        with self.assertRaises(subject.SnapshotError):
            subject.serialize_record(
                project="en.wikipedia.org",
                pageid=1,
                revid=2,
                userid=0,
                timestamp="2026-08-16T00:00:00Z",
                username="user",
                title="\ud800",
                content="x",
            )

    def test_token_commitment_uses_little_endian_count_and_ids(self) -> None:
        tokenizer = FixtureTokenizer(count=513)
        observed = subject.token_commitment(tokenizer, "text")
        ids = [index % 1024 for index in range(513)]
        complete = len(ids).to_bytes(8, "little") + b"".join(
            item.to_bytes(4, "little") for item in ids
        )
        first = (512).to_bytes(8, "little") + b"".join(
            item.to_bytes(4, "little") for item in ids[:512]
        )
        self.assertEqual(observed["completeStreamSHA256"], hashlib.sha256(complete).hexdigest())
        self.assertEqual(observed["first512StreamSHA256"], hashlib.sha256(first).hexdigest())
        self.assertEqual(tokenizer.calls, [("text", False)])

    def test_recentchanges_continuation_is_copied_exactly_and_archived(self) -> None:
        first_record = change(1, 0)
        second_record = change(1, 1)
        calls: list[str] = []

        def transport(uri: str) -> subject.ArchivedHTTPResponse:
            calls.append(uri)
            if len(calls) == 1:
                value = {
                    "continue": {"rccontinue": "token|1", "continue": "-||"},
                    "query": {"recentchanges": [public_change(first_record)]},
                }
            else:
                query = parse_qs(urlsplit(uri).query)
                self.assertEqual(query["continue"], ["-||"])
                self.assertEqual(query["rccontinue"], ["token|1"])
                value = {
                    "batchcomplete": True,
                    "query": {"recentchanges": [public_change(second_record)]},
                }
            return response(uri, value)

        crawl = subject.collect_recentchanges_crawl(
            project="en.wikipedia.org",
            crawl_index=1,
            root=self.root,
            transport=transport,
            clock=self.clock,
        )
        self.assertEqual([item["revid"] for item in crawl["records"]], [first_record["revid"], second_record["revid"]])
        self.assertEqual(len(crawl["pages"]), 2)
        for page in crawl["pages"]:
            for field in ("requestURIFile", "responseHeaders", "responseBody"):
                path = self.root / page[field]["relativePath"]
                self.assertTrue(path.is_file())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), page[field]["sha256"])

    def test_crawl_fails_on_old_date_duplicate_and_continuation_cycle(self) -> None:
        record = public_change(change(1, 0))

        def old_date(uri: str) -> subject.ArchivedHTTPResponse:
            return response(
                uri,
                {"batchcomplete": True, "query": {"recentchanges": [record]}},
                date="Mon, 24 Aug 2026 05:59:59 GMT",
            )

        with self.assertRaisesRegex(subject.SnapshotError, "Date precedes"):
            subject.collect_recentchanges_crawl(
                project="en.wikipedia.org",
                crawl_index=0,
                root=self.root / "old-date",
                transport=old_date,
                clock=self.clock,
            )

        duplicate_root = self.root / "duplicate"
        duplicate_calls = 0

        def duplicate(uri: str) -> subject.ArchivedHTTPResponse:
            nonlocal duplicate_calls
            duplicate_calls += 1
            value: dict[str, object] = {
                "query": {"recentchanges": [record]},
            }
            if duplicate_calls == 1:
                value["continue"] = {"continue": "-||", "rccontinue": "next"}
            else:
                value["batchcomplete"] = True
            return response(uri, value)

        with self.assertRaisesRegex(subject.SnapshotError, "duplicate revision"):
            subject.collect_recentchanges_crawl(
                project="en.wikipedia.org",
                crawl_index=1,
                root=duplicate_root,
                transport=duplicate,
                clock=self.clock,
            )

        cycle_root = self.root / "cycle"

        def cycle(uri: str) -> subject.ArchivedHTTPResponse:
            return response(
                uri,
                {
                    "continue": {"continue": "-||", "rccontinue": "same"},
                    "query": {"recentchanges": []},
                },
            )

        with self.assertRaisesRegex(subject.SnapshotError, "cycle"):
            subject.collect_recentchanges_crawl(
                project="en.wikipedia.org",
                crawl_index=1,
                root=cycle_root,
                transport=cycle,
                clock=self.clock,
            )

    def test_union_rejects_conflicting_duplicate(self) -> None:
        item = public_change(change(0, 0))
        first = {"project": "de.wikipedia.org", "crawlIndex": 1, "records": [item]}
        changed = copy.deepcopy(item)
        changed["title"] = "different"
        second = {"project": "de.wikipedia.org", "crawlIndex": 2, "records": [changed]}
        with self.assertRaisesRegex(subject.SnapshotError, "disagree"):
            subject.union_crawls(first, second)

    def test_full_fixture_snapshot_and_manifest_record_loader(self) -> None:
        records = {
            project: [change(project_index, index) for index in range(64)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        transport = SmartTransport(records)
        tokenizers = {key: FixtureTokenizer() for key in subject.MODEL_KEYS}
        manifest = subject.collect_snapshot(
            root=self.root,
            transport=transport,
            tokenizers=tokenizers,
            clock=self.clock,
        )
        self.assertEqual(manifest["status"], "SNAPSHOT_READY_FOR_FREEZE")
        self.assertFalse(manifest["countsTowardScientificVerdict"])
        verification = subject.verify_corpus_snapshot(self.root)
        self.assertTrue(verification["readyForFreeze"])
        self.assertEqual(verification["eligibleRecords"], 192)
        self.assertFalse(verification["tokenCommitmentsRecomputed"])
        verification_with_tokenizers = subject.verify_corpus_snapshot(
            self.root, tokenizers=tokenizers
        )
        self.assertTrue(verification_with_tokenizers["tokenCommitmentsRecomputed"])

        selected = records["fr.wikipedia.org"][7]
        record_bytes = subject.load_record_bytes(
            manifest, "fr.wikipedia.org", int(selected["revid"]), self.root
        )
        parsed = subject.parse_record(record_bytes)
        self.assertEqual(parsed["title"], selected["title"])
        self.assertEqual(parsed["content"], selected["_content"])

        item = manifest["projects"]["fr.wikipedia.org"]["inventory"][7]
        target = self.root / item["record"]["relativePath"]
        original = target.read_bytes()
        target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(subject.SnapshotError, "SHA-256"):
            subject.load_record_bytes(
                manifest, "fr.wikipedia.org", int(selected["revid"]), self.root
            )

    def test_verifier_replays_request_uri_instead_of_trusting_manifest(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        manifest = subject.collect_snapshot(
            root=self.root,
            transport=SmartTransport(records),
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            clock=self.clock,
        )
        page = manifest["projects"]["en.wikipedia.org"]["crawls"][0]["pages"][0]
        forged_uri = subject.recentchanges_uri(
            "en.wikipedia.org",
            {"continue": "-||", "rccontinue": "forged-continuation"},
        )
        forged_request = forged_uri.encode("ascii") + b"\n"
        request_path = self.root / page["requestURIFile"]["relativePath"]
        request_path.write_bytes(forged_request)
        page["requestURI"] = forged_uri
        page["requestURIFile"]["bytes"] = len(forged_request)
        page["requestURIFile"]["sha256"] = hashlib.sha256(forged_request).hexdigest()
        (self.root / "corpus-manifest.json").write_bytes(
            subject.canonical_json_bytes(manifest)
        )
        with self.assertRaisesRegex(
            subject.SnapshotError,
            "differs from replay|committed file byte count differs",
        ):
            subject.verify_corpus_snapshot(self.root)

    def test_moved_page_uses_creation_title_and_records_current_title_only_in_inventory(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        moved = records["en.wikipedia.org"][0]

        class MovedTransport(SmartTransport):
            def __call__(self, uri: str) -> subject.ArchivedHTTPResponse:
                parsed = urlsplit(uri)
                query = parse_qs(parsed.query, strict_parsing=True)
                if query.get("prop") != ["revisions"]:
                    return super().__call__(uri)
                self.uris.append(uri)
                revid = int(query["revids"][0])
                value = revision_response(self.by_revision[revid])
                if revid == int(moved["revid"]):
                    value["query"]["pages"][0]["title"] = "Current moved title"
                return response(uri, value)

        transport = MovedTransport(records)
        manifest = subject.collect_snapshot(
            root=self.root,
            transport=transport,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            clock=self.clock,
        )
        item = manifest["projects"]["en.wikipedia.org"]["inventory"][0]
        self.assertEqual(item["title"], moved["title"])
        self.assertEqual(item["revisionAPICurrentTitle"], "Current moved title")
        self.assertEqual(
            item["historyURL"],
            f"https://en.wikipedia.org/w/index.php?curid={moved['pageid']}&action=history",
        )
        ledger = json.loads(
            (
                self.root
                / manifest["projects"]["en.wikipedia.org"]["ledger"]["relativePath"]
            ).read_text()
        )
        self.assertNotIn("revisionAPICurrentTitle", ledger[0])
        parsed = subject.parse_record(
            subject.load_record_bytes(
                manifest,
                "en.wikipedia.org",
                int(moved["revid"]),
                self.root,
            )
        )
        self.assertEqual(parsed["title"], moved["title"])
        subject.verify_corpus_snapshot(
            self.root,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )

    def test_moved_ineligible_revision_records_current_api_title(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        moved = records["de.wikipedia.org"][0]

        class MovedHiddenTransport(SmartTransport):
            def __call__(self, uri: str) -> subject.ArchivedHTTPResponse:
                parsed = urlsplit(uri)
                query = parse_qs(parsed.query, strict_parsing=True)
                if query.get("prop") != ["revisions"]:
                    return super().__call__(uri)
                self.uris.append(uri)
                revid = int(query["revids"][0])
                value = revision_response(self.by_revision[revid])
                if revid == int(moved["revid"]):
                    page = value["query"]["pages"][0]
                    page["title"] = "Current title after move"
                    revision = page["revisions"][0]
                    revision.pop("user")
                    revision.pop("userid")
                    revision["userhidden"] = True
                return response(uri, value)

        manifest = subject.collect_snapshot(
            root=self.root,
            transport=MovedHiddenTransport(records),
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            clock=self.clock,
        )
        item = manifest["projects"]["de.wikipedia.org"]["inventory"][0]
        self.assertFalse(item["eligible"])
        self.assertEqual(item["title"], moved["title"])
        self.assertEqual(item["revisionAPICurrentTitle"], "Current title after move")
        self.assertIn("revision-user-hidden", item["ineligibilityReasons"])
        self.assertEqual(
            json.loads((self.root / "ledgers/de.wikipedia.org.json").read_text()),
            [],
        )
        subject.verify_corpus_snapshot(
            self.root,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )

    def test_complete_pending_bundle_is_promoted_without_refetching(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        self.collect_two_stages(SmartTransport(records))
        selected = records["de.wikipedia.org"][0]
        revid = int(selected["revid"])
        uri = subject.revision_uri("de.wikipedia.org", revid)
        archived = response(uri, revision_response(selected))
        pending = (
            self.root
            / "archive"
            / "revisions"
            / "de.wikipedia.org"
            / f".{revid}.partial"
        )
        pending.mkdir(parents=True)
        (pending / "request-uri.txt").write_bytes(uri.encode("ascii") + b"\n")
        (pending / "response-headers.bin").write_bytes(archived.header_bytes)
        (pending / "response-body.bin").write_bytes(archived.body)

        transport = SmartTransport(records)
        subject.finalize_snapshot(
            root=self.root,
            transport=transport,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )
        requested = {
            int(parse_qs(urlsplit(value).query)["revids"][0])
            for value in transport.uris
        }
        self.assertNotIn(revid, requested)
        self.assertFalse(pending.exists())
        self.assertTrue((pending.parent / str(revid)).is_dir())

    def test_incomplete_pending_bundle_fails_before_network(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        self.collect_two_stages(SmartTransport(records))
        selected = records["de.wikipedia.org"][0]
        revid = int(selected["revid"])
        uri = subject.revision_uri("de.wikipedia.org", revid)
        pending = (
            self.root
            / "archive"
            / "revisions"
            / "de.wikipedia.org"
            / f".{revid}.partial"
        )
        pending.mkdir(parents=True)
        (pending / "request-uri.txt").write_bytes(uri.encode("ascii") + b"\n")
        calls: list[str] = []

        def forbidden_transport(value: str) -> subject.ArchivedHTTPResponse:
            calls.append(value)
            raise AssertionError("network must not run over a partial bundle")

        with self.assertRaisesRegex(subject.SnapshotError, "pending response bundle is incomplete"):
            subject.finalize_snapshot(
                root=self.root,
                transport=forbidden_transport,
                tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            )
        self.assertEqual(calls, [])
        self.assertTrue(pending.is_dir())

    def test_finalize_resumes_without_refetching_committed_revision_bundles(self) -> None:
        records = {
            project: [change(project_index, index) for index in range(2)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        crawl_transport = SmartTransport(records)
        self.collect_two_stages(crawl_transport)
        tokenizers = {key: FixtureTokenizer() for key in subject.MODEL_KEYS}
        first = SmartTransport(records)
        revision_calls = 0

        def fail_after_three(uri: str) -> subject.ArchivedHTTPResponse:
            nonlocal revision_calls
            query = parse_qs(urlsplit(uri).query, strict_parsing=True)
            if query.get("prop") == ["revisions"]:
                revision_calls += 1
                if revision_calls == 4:
                    raise RuntimeError("injected transport interruption")
            return first(uri)

        with self.assertRaisesRegex(RuntimeError, "injected"):
            subject.finalize_snapshot(
                root=self.root,
                transport=fail_after_three,
                tokenizers=tokenizers,
            )
        committed = {
            int(path.name)
            for project in subject.PROJECTS
            for path in (self.root / "archive" / "revisions" / project).glob("[0-9]*")
        }
        self.assertEqual(len(committed), 3)

        resumed = SmartTransport(records)
        manifest = subject.finalize_snapshot(
            root=self.root,
            transport=resumed,
            tokenizers=tokenizers,
        )
        resumed_revisions = {
            int(parse_qs(urlsplit(uri).query)["revids"][0])
            for uri in resumed.uris
        }
        self.assertTrue(committed.isdisjoint(resumed_revisions))
        self.assertEqual(len(resumed_revisions), 3)

        def forbidden_transport(_uri: str) -> subject.ArchivedHTTPResponse:
            raise AssertionError("complete corpus replay must not use the network")

        replayed = subject.finalize_snapshot(
            root=self.root,
            transport=forbidden_transport,
            tokenizers=tokenizers,
        )
        self.assertEqual(replayed, manifest)

        manifest_path = self.root / "corpus-manifest.json"
        pending_manifest = self.root / ".corpus-manifest.json.pending"
        os.link(manifest_path, pending_manifest)
        replayed_after_manifest_crash = subject.finalize_snapshot(
            root=self.root,
            transport=forbidden_transport,
            tokenizers=tokenizers,
        )
        self.assertEqual(replayed_after_manifest_crash, manifest)
        self.assertFalse(pending_manifest.exists())

    def test_verifier_binds_corpus_crawl_views_to_stage_manifests(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        manifest = subject.collect_snapshot(
            root=self.root,
            transport=SmartTransport(records),
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            clock=self.clock,
        )
        manifest["projects"]["en.wikipedia.org"]["crawls"][0]["notBefore"] = (
            "2026-08-30T06:00:01Z"
        )
        (self.root / "corpus-manifest.json").write_bytes(
            subject.canonical_json_bytes(manifest)
        )
        with self.assertRaisesRegex(subject.SnapshotError, "differ from stage manifests"):
            subject.verify_corpus_snapshot(self.root)

    def test_bundle_committed_before_record_failure_is_reused_and_extras_fail_closed(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        self.collect_two_stages(SmartTransport(records))
        transport = SmartTransport(records)
        original = subject._write_or_reuse_exact
        failed = False

        def fail_first_record(root: Path, relative: str, value: bytes) -> dict[str, object]:
            nonlocal failed
            if relative.startswith("records/") and not failed:
                failed = True
                raise RuntimeError("injected record publication failure")
            return original(root, relative, value)

        with mock.patch.object(subject, "_write_or_reuse_exact", fail_first_record):
            with self.assertRaisesRegex(RuntimeError, "record publication"):
                subject.finalize_snapshot(
                    root=self.root,
                    transport=transport,
                    tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
                )
        first_revid = int(records["de.wikipedia.org"][0]["revid"])
        calls_before = len(transport.uris)
        resumed = SmartTransport(records)
        subject.finalize_snapshot(
            root=self.root,
            transport=resumed,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )
        resumed_ids = {
            int(parse_qs(urlsplit(uri).query)["revids"][0]) for uri in resumed.uris
        }
        self.assertNotIn(first_revid, resumed_ids)
        self.assertEqual(calls_before, 1)

        bundle = (
            self.root
            / "archive"
            / "revisions"
            / "de.wikipedia.org"
            / str(first_revid)
        )
        (bundle / "unexpected.bin").write_bytes(b"not evidence")
        with self.assertRaisesRegex(subject.SnapshotError, "inventory differs"):
            subject.finalize_snapshot(
                root=self.root,
                transport=lambda uri: (_ for _ in ()).throw(
                    AssertionError(f"unexpected network call: {uri}")
                ),
                tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            )

    def test_two_durable_crawl_stages_can_run_on_separate_days(self) -> None:
        records = {
            project: [change(project_index, 0)]
            for project_index, project in enumerate(subject.PROJECTS)
        }
        transport = SmartTransport(records)
        first_day = lambda: datetime(
            2026, 8, 30, 6, 0, 2, tzinfo=timezone.utc
        )
        subject.collect_crawl_stage(
            root=self.root,
            crawl_index=0,
            transport=transport,
            clock=first_day,
        )
        replayed_first = subject.load_crawl_stage(self.root, 0)
        self.assertEqual(
            replayed_first["de.wikipedia.org"]["records"][0]["revid"],
            records["de.wikipedia.org"][0]["revid"],
        )
        with self.assertRaisesRegex(subject.SnapshotError, "before"):
            subject.collect_crawl_stage(
                root=self.root,
                crawl_index=1,
                transport=transport,
                clock=first_day,
            )
        subject.collect_crawl_stage(
            root=self.root,
            crawl_index=1,
            transport=transport,
            clock=self.clock,
        )
        manifest = subject.finalize_snapshot(
            root=self.root,
            transport=transport,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )
        self.assertEqual(manifest["status"], "INSUFFICIENT_ELIGIBLE_REVISIONS")
        self.assertFalse(subject.verify_corpus_snapshot(self.root)["readyForFreeze"])

    def test_hidden_and_deleted_revision_is_archived_as_ineligible(self) -> None:
        originals = {
            project: change(project_index, 0)
            for project_index, project in enumerate(subject.PROJECTS)
        }
        public = {
            project: public_change(value) for project, value in originals.items()
        }
        hidden = public["de.wikipedia.org"]
        for field in ("user", "userid", "sha1"):
            hidden.pop(field)
        hidden["userhidden"] = True
        hidden["sha1hidden"] = True
        by_revision = {
            int(value["revid"]): value for value in originals.values()
        }

        def transport(uri: str) -> subject.ArchivedHTTPResponse:
            parsed = urlsplit(uri)
            query = parse_qs(parsed.query, strict_parsing=True)
            if query.get("list") == ["recentchanges"]:
                value = {
                    "batchcomplete": True,
                    "query": {"recentchanges": [public[parsed.hostname]]},
                }
            else:
                revid = int(query["revids"][0])
                if revid == int(originals["de.wikipedia.org"]["revid"]):
                    value = {
                        "batchcomplete": True,
                        "query": {
                            "badrevids": {
                                str(revid): {"revid": revid, "missing": True}
                            }
                        },
                    }
                else:
                    value = revision_response(by_revision[revid])
            return response(uri, value)

        manifest = subject.collect_snapshot(
            root=self.root,
            transport=transport,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
            clock=self.clock,
        )
        excluded = manifest["projects"]["de.wikipedia.org"]["inventory"][0]
        self.assertFalse(excluded["eligible"])
        self.assertEqual(
            excluded["ineligibilityReasons"],
            [
                "recentchanges-user-hidden",
                "recentchanges-sha1-hidden",
                "revision-unavailable-or-deleted",
            ],
        )
        self.assertNotIn("record", excluded)
        self.assertNotIn("tokenizers", excluded)
        verification = subject.verify_corpus_snapshot(
            self.root,
            tokenizers={key: FixtureTokenizer() for key in subject.MODEL_KEYS},
        )
        self.assertEqual(verification["eligibleRecords"], 2)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_record_loader_rejects_symlink_leaf(self) -> None:
        value = subject.serialize_record(
            project="en.wikipedia.org",
            pageid=1,
            revid=2,
            userid=3,
            timestamp="2026-08-16T00:00:00Z",
            username="author",
            title="title",
            content="content",
        )
        real = self.root / "real.bin"
        real.write_bytes(value)
        linked = self.root / "linked.bin"
        linked.symlink_to(real)
        commitment = {
            "relativePath": "linked.bin",
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
        manifest = {
            "schemaVersion": subject.MANIFEST_SCHEMA,
            "projects": {
                "en.wikipedia.org": {
                    "inventory": [
                        {
                            "revid": 2,
                            "eligible": True,
                            "record": commitment,
                            "titleSHA256": hashlib.sha256(b"title").hexdigest(),
                            "contentSHA256": hashlib.sha256(b"content").hexdigest(),
                            "inputSHA256": hashlib.sha256(b"title\n\ncontent").hexdigest(),
                        }
                    ]
                }
            },
        }
        with self.assertRaisesRegex(subject.SnapshotError, "symlink"):
            subject.load_record_bytes(manifest, "en.wikipedia.org", 2, self.root)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_snapshot_parent_symlink_is_rejected_component_by_component(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        snapshot = real_parent / "snapshot"
        snapshot.mkdir()
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)

        with self.assertRaisesRegex(subject.SnapshotError, "symlink"):
            subject._write_exclusive(
                linked_parent / "snapshot",
                "archive/value.bin",
                b"must not be written through a linked parent",
            )
        self.assertFalse((snapshot / "archive").exists())

    def test_committed_read_detects_leaf_swap_after_fd_open(self) -> None:
        original = b"a" * (1024 * 1024 + 17)
        target = self.root / "record.bin"
        target.write_bytes(original)
        commitment = {
            "relativePath": "record.bin",
            "bytes": len(original),
            "sha256": hashlib.sha256(original).hexdigest(),
        }
        saved = self.root / "opened-record.bin"
        real_read = os.read
        swapped = False

        def swap_then_read(descriptor: int, count: int) -> bytes:
            nonlocal swapped
            if not swapped:
                target.replace(saved)
                target.write_bytes(b"concurrent replacement")
                swapped = True
            return real_read(descriptor, count)

        with mock.patch.object(subject.os, "read", side_effect=swap_then_read):
            with self.assertRaisesRegex(subject.SnapshotError, "changed while being read"):
                subject._read_committed(self.root, commitment)
        self.assertEqual(saved.read_bytes(), original)
        self.assertEqual(target.read_bytes(), b"concurrent replacement")

    def test_concurrent_empty_response_target_is_never_overwritten_or_complete(self) -> None:
        uri = subject.revision_uri("de.wikipedia.org", 42)
        archived = response(uri, {"batchcomplete": True, "query": {"pages": []}})
        target = self.root / "archive/revisions/de.wikipedia.org/42"
        pending = target.parent / ".42.partial"
        real_mkdir = os.mkdir
        raced = False

        def create_empty_target_then_conflict(
            path: object,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal raced
            if path == "42" and dir_fd is not None and not raced:
                raced = True
                real_mkdir(path, mode, dir_fd=dir_fd)
                raise FileExistsError("injected concurrent empty target")
            real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(subject.os, "mkdir", side_effect=create_empty_target_then_conflict):
            with self.assertRaisesRegex(subject.SnapshotError, "inventory differs"):
                subject._publish_response_bundle(
                    self.root,
                    "archive/revisions/de.wikipedia.org/42",
                    archived,
                )

        self.assertTrue(raced)
        self.assertTrue(target.is_dir())
        self.assertEqual(list(target.iterdir()), [])
        self.assertTrue(pending.is_dir())
        self.assertEqual(
            {item.name for item in pending.iterdir()},
            set(subject._RESPONSE_BUNDLE_FILES.values()),
        )
        with self.assertRaisesRegex(subject.SnapshotError, "inventory differs"):
            subject._load_existing_response_bundle(
                self.root,
                "archive/revisions/de.wikipedia.org/42",
                expected_uri=uri,
            )

    def test_concurrent_identical_response_target_is_replayed_exclusively(self) -> None:
        uri = subject.revision_uri("de.wikipedia.org", 43)
        archived = response(uri, {"batchcomplete": True, "query": {"pages": []}})
        payloads = {
            "request-uri.txt": uri.encode("ascii") + b"\n",
            "response-headers.bin": archived.header_bytes,
            "response-body.bin": archived.body,
        }
        target = self.root / "archive/revisions/de.wikipedia.org/43"
        pending = target.parent / ".43.partial"
        real_mkdir = os.mkdir
        raced_inode: int | None = None

        def publish_identical_target_then_conflict(
            path: object,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal raced_inode
            if path == "43" and dir_fd is not None and raced_inode is None:
                real_mkdir(path, mode, dir_fd=dir_fd)
                target_descriptor = os.open(
                    path,
                    subject._directory_flags(),
                    dir_fd=dir_fd,
                )
                try:
                    raced_inode = os.fstat(target_descriptor).st_ino
                    for filename, value in payloads.items():
                        descriptor = os.open(
                            filename,
                            subject._write_new_flags(),
                            0o600,
                            dir_fd=target_descriptor,
                        )
                        try:
                            view = memoryview(value)
                            while view:
                                written = os.write(descriptor, view)
                                view = view[written:]
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                    os.fsync(target_descriptor)
                finally:
                    os.close(target_descriptor)
                raise FileExistsError("injected concurrent identical target")
            real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(
            subject.os,
            "mkdir",
            side_effect=publish_identical_target_then_conflict,
        ):
            archive, replayed = subject._publish_response_bundle(
                self.root,
                "archive/revisions/de.wikipedia.org/43",
                archived,
            )

        self.assertEqual(replayed, archived)
        self.assertEqual(os.stat(target, follow_symlinks=False).st_ino, raced_inode)
        self.assertFalse(pending.exists())
        for role, filename in subject._RESPONSE_BUNDLE_FILES.items():
            self.assertEqual(
                hashlib.sha256((target / filename).read_bytes()).hexdigest(),
                archive[role]["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
