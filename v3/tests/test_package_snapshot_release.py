from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from v3.package_snapshot_release import (
    ASSET_NAMES,
    ASSET_ROLES,
    SnapshotReleaseError,
    canonical_json_bytes,
    package_snapshot_release,
    sha256_bytes,
    verify_snapshot_release,
)


SUITE_ID = "corelm-voidtoken-crossmodel-livewiki-v3-author-verified"
PROJECTS = (
    "de.wikipedia.org",
    "en.wikipedia.org",
    "fr.wikipedia.org",
)
MODELS = (
    "gpt-neo-125m",
    "smollm2-360m",
    "tiny-starcoder-py",
)


def canonical_line(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


class SnapshotReleasePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.corpus_root = self.root / "corpus-source"
        self.corpus_root.mkdir()
        self.design_receipt_path = self.root / "design-publication-receipt.json"
        self.snapshot_path = self.root / "snapshot-registration.json"
        self._build_sources()

    def tearDown(self) -> None:
        for directory, child_directories, filenames in os.walk(
            self.root,
            topdown=False,
            followlinks=False,
        ):
            for filename in filenames:
                path = Path(directory) / filename
                if not path.is_symlink():
                    try:
                        os.chmod(path, 0o600)
                    except FileNotFoundError:
                        pass
            for child in child_directories:
                path = Path(directory) / child
                if not path.is_symlink():
                    try:
                        os.chmod(path, 0o700)
                    except FileNotFoundError:
                        pass
            try:
                os.chmod(directory, 0o700)
            except FileNotFoundError:
                pass
        self.temporary.cleanup()

    def _write_corpus(self, relative: str, raw: bytes) -> dict[str, object]:
        path = self.corpus_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {
            "relativePath": relative,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        }

    def _build_sources(self) -> None:
        projects: dict[str, object] = {}
        for project_index, project in enumerate(PROJECTS):
            crawls: list[dict[str, object]] = []
            for crawl_index in (1, 2):
                prefix = (
                    f"archive/crawl-{crawl_index}/{project}/page-000000"
                )
                request_uri = (
                    f"https://{project}/w/api.php?fixture={crawl_index}\n"
                ).encode("ascii")
                headers = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n"
                body = canonical_json_bytes(
                    {
                        "project": project,
                        "crawlIndex": crawl_index,
                        "fixture": True,
                    }
                )
                crawls.append(
                    {
                        "crawlIndex": crawl_index,
                        "project": project,
                        "notBefore": (
                            "2026-08-30T06:00:00Z"
                            if crawl_index == 1
                            else "2026-08-31T06:00:00Z"
                        ),
                        "pages": [
                            {
                                "requestURI": request_uri[:-1].decode("ascii"),
                                "serverDate": (
                                    "2026-08-30T06:00:01Z"
                                    if crawl_index == 1
                                    else "2026-08-31T06:00:01Z"
                                ),
                                "requestURIFile": self._write_corpus(
                                    f"{prefix}/request-uri.txt", request_uri
                                ),
                                "responseHeaders": self._write_corpus(
                                    f"{prefix}/response-headers.bin", headers
                                ),
                                "responseBody": self._write_corpus(
                                    f"{prefix}/response-body.json", body
                                ),
                                "records": 1,
                            }
                        ],
                    }
                )

            revid = 1000 + project_index
            revision_prefix = f"archive/revisions/{project}/{revid}"
            revision_uri = f"https://{project}/w/api.php?revid={revid}"
            revision_archive = {
                "requestURI": revision_uri,
                "serverDate": "2026-08-31T06:00:01Z",
                "requestURIFile": self._write_corpus(
                    f"{revision_prefix}/request-uri.txt",
                    revision_uri.encode("ascii") + b"\n",
                ),
                "responseHeaders": self._write_corpus(
                    f"{revision_prefix}/response-headers.bin",
                    b"HTTP/1.1 200 OK\r\n\r\n",
                ),
                "responseBody": self._write_corpus(
                    f"{revision_prefix}/response-body.json",
                    canonical_json_bytes({"revision": revid}),
                ),
            }
            title = f"Fixture {project}"
            content = f"exact corpus bytes for {project}\n".encode("utf-8")
            record = self._write_corpus(
                f"records/{project}/{revid}.bin",
                content,
            )
            attribution = {
                "username": f"Author-{project_index}",
                "userid": 500 + project_index,
                "spdxLike": "SOURCE-MANIFEST-ONLY",
                "licenseURL": f"https://{project}/source-license",
                "projectTermsURL": f"https://{project}/source-terms",
                "project": project,
            }
            inventory = [
                {
                    "project": project,
                    "pageid": 2000 + project_index,
                    "revid": revid,
                    "userid": 500 + project_index,
                    "timestamp": f"2026-08-16T00:00:0{project_index}Z",
                    "username": f"Author-{project_index}",
                    "title": title,
                    "mediaWikiSHA1": hashlib.sha1(content).hexdigest(),
                    "titleSHA256": sha256_bytes(title.encode("utf-8")),
                    "contentSHA256": sha256_bytes(content),
                    "inputSHA256": sha256_bytes(
                        title.encode("utf-8") + b"\n\n" + content
                    ),
                    "tokenizers": {},
                    "revisionURL": (
                        f"https://{project}/w/index.php?oldid={revid}"
                    ),
                    "historyURL": (
                        f"https://{project}/w/index.php?title=Fixture&action=history"
                    ),
                    "attribution": attribution,
                    "revisionArchive": revision_archive,
                    "eligible": True,
                    "ineligibilityReasons": [],
                    "record": record,
                }
            ]
            ledger_raw = canonical_json_bytes(inventory)
            ledger = self._write_corpus(
                f"ledgers/{project}.json",
                ledger_raw,
            )
            projects[project] = {
                "crawls": crawls,
                "unionRevisionCount": 1,
                "inventory": inventory,
                "eligibleRevisionCount": 1,
                "ledger": ledger,
            }

        corpus_manifest = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-corpus-manifest-v1",
            "suiteId": SUITE_ID,
            "status": "SNAPSHOT_READY_FOR_FREEZE",
            "countsTowardScientificVerdict": False,
            "projects": projects,
        }
        self.corpus_manifest_raw = canonical_json_bytes(corpus_manifest)
        (self.corpus_root / "corpus-manifest.json").write_bytes(
            self.corpus_manifest_raw
        )
        for crawl_index in (1, 2):
            (self.corpus_root / f"crawl-{crawl_index}-manifest.json").write_bytes(
                canonical_json_bytes(
                    {
                        "schemaVersion": "fixture-crawl-stage-v1",
                        "crawlIndex": crawl_index,
                        "countsTowardScientificVerdict": False,
                    }
                )
            )

        receipt_unsigned = {
            "schemaVersion": "corelm-github-release-receipt-v2",
            "suiteId": SUITE_ID,
            "kind": "design",
            "tag": "corelm-crossmodel-livewiki-v3-design",
            "fixtureBoundary": "unit structure; not signature evidence",
        }
        receipt = dict(receipt_unsigned)
        receipt["contentSHA256"] = sha256_bytes(
            canonical_json_bytes(receipt_unsigned)
        )
        self.design_receipt_raw = canonical_line(receipt)
        self.design_receipt_path.write_bytes(self.design_receipt_raw)

        snapshot = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-snapshot-registration-v1",
            "suiteId": SUITE_ID,
            "status": "SNAPSHOT_FROZEN_READY_FOR_PUBLICATION",
            "designPublicationReceiptSHA256": sha256_bytes(
                self.design_receipt_raw
            ),
            "snapshotReleasePlan": {
                "tag": "corelm-crossmodel-livewiki-v3-snapshot",
                "publishNoLaterThan": "2026-09-01T18:00:00Z",
                "serverTimestampRequired": True,
                "immutableReleaseRequired": True,
                "signedAnnotatedTagRequired": True,
            },
            "projects": list(PROJECTS),
            "models": list(MODELS),
            "ledgers": {project: "4" * 64 for project in PROJECTS},
            "modelAssetSourceManifestSHA256": "5" * 64,
            "fullAssetReceiptSHA256": "6" * 64,
            "corpusManifestSHA256": sha256_bytes(self.corpus_manifest_raw),
            "createdAt": "2026-08-31T06:30:00Z",
        }
        self.snapshot_raw = canonical_line(snapshot)
        self.snapshot_path.write_bytes(self.snapshot_raw)

    def _package(self, name: str = "snapshot-release"):
        return package_snapshot_release(
            corpus_root=self.corpus_root,
            snapshot_registration_path=self.snapshot_path,
            design_publication_receipt_path=self.design_receipt_path,
            output_root=self.root / name,
        )

    def _verify(self, name: str = "snapshot-release"):
        return verify_snapshot_release(
            corpus_root=self.corpus_root,
            snapshot_registration_path=self.snapshot_path,
            design_publication_receipt_path=self.design_receipt_path,
            asset_root=self.root / name,
        )

    def test_package_is_exact_deterministic_read_only_and_self_verifying(self) -> None:
        first = self._package("release-one")
        second = self._package("release-two")
        self.assertEqual(tuple(asset.role for asset in first.assets), ASSET_ROLES)
        self.assertEqual(
            [(asset.name, asset.bytes, asset.sha256) for asset in first.assets],
            [(asset.name, asset.bytes, asset.sha256) for asset in second.assets],
        )
        self.assertEqual(first.attribution_records, 3)
        self.assertFalse(stat.S_IMODE((self.root / "release-one").stat().st_mode) & 0o222)
        for asset in first.assets:
            path = self.root / "release-one" / asset.name
            self.assertTrue(path.is_file())
            self.assertFalse(stat.S_IMODE(path.stat().st_mode) & 0o222)

        source_files = {
            path.relative_to(self.corpus_root).as_posix(): path.read_bytes()
            for path in self.corpus_root.rglob("*")
            if path.is_file()
        }
        with zipfile.ZipFile(
            self.root / "release-one" / ASSET_NAMES["corpus-bytes"]
        ) as archive:
            self.assertEqual(archive.namelist(), sorted(source_files))
            for relative, raw in source_files.items():
                self.assertEqual(archive.read(relative), raw)

        attribution = json.loads(
            (self.root / "release-one" / ASSET_NAMES["attribution"]).read_bytes()
        )
        observed = attribution["records"][0]["attribution"]
        source_project = attribution["records"][0]["project"]
        source_item = self._manifest()["projects"][source_project]["inventory"][0]
        self.assertEqual(observed, source_item["attribution"])
        self.assertNotIn("license", observed)

        sha_manifest = json.loads(
            (
                self.root
                / "release-one"
                / ASSET_NAMES["sha256-manifest"]
            ).read_bytes()
        )
        self.assertIs(sha_manifest["selfDigestExcluded"], True)
        self.assertNotIn(
            "sha256-manifest",
            [item["role"] for item in sha_manifest["assets"]],
        )
        self.assertEqual(self._verify("release-one").assets, first.assets)

    def _manifest(self) -> dict[str, object]:
        return json.loads((self.corpus_root / "corpus-manifest.json").read_bytes())

    def test_no_overwrite_and_exact_five_file_inventory(self) -> None:
        occupied = self.root / "occupied"
        occupied.mkdir()
        sentinel = occupied / "sentinel"
        sentinel.write_bytes(b"do not overwrite")
        with self.assertRaisesRegex(SnapshotReleaseError, "already exists"):
            self._package("occupied")
        self.assertEqual(sentinel.read_bytes(), b"do not overwrite")

        self._package()
        before = {
            path.name: path.read_bytes()
            for path in (self.root / "snapshot-release").iterdir()
        }
        with self.assertRaisesRegex(SnapshotReleaseError, "already exists"):
            self._package()
        after = {
            path.name: path.read_bytes()
            for path in (self.root / "snapshot-release").iterdir()
        }
        self.assertEqual(before, after)

        os.chmod(self.root / "snapshot-release", 0o755)
        (self.root / "snapshot-release" / "extra.bin").write_bytes(b"extra")
        os.chmod(self.root / "snapshot-release", 0o555)
        with self.assertRaisesRegex(SnapshotReleaseError, "exactly five"):
            self._verify()

    def test_source_symlink_special_file_empty_directory_and_extra_are_rejected(self) -> None:
        extra = self.corpus_root / "extra.bin"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(SnapshotReleaseError, "inventory differs"):
            self._package("extra-release")
        extra.unlink()

        symlink = self.corpus_root / "linked.bin"
        symlink.symlink_to(self.corpus_root / "corpus-manifest.json")
        with self.assertRaisesRegex(SnapshotReleaseError, "symlink"):
            self._package("symlink-release")
        symlink.unlink()

        fifo = self.corpus_root / "named-pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(SnapshotReleaseError, "special file"):
            self._package("fifo-release")
        fifo.unlink()

        empty = self.corpus_root / "unexpected-empty-directory"
        empty.mkdir()
        with self.assertRaisesRegex(SnapshotReleaseError, "directory inventory"):
            self._package("directory-release")

    def test_path_escape_and_noncanonical_snapshot_are_rejected(self) -> None:
        manifest = self._manifest()
        manifest["projects"][PROJECTS[0]]["ledger"]["relativePath"] = "../escape"
        raw = canonical_json_bytes(manifest)
        (self.corpus_root / "corpus-manifest.json").write_bytes(raw)
        snapshot = json.loads(self.snapshot_raw)
        snapshot["corpusManifestSHA256"] = sha256_bytes(raw)
        self.snapshot_path.write_bytes(canonical_line(snapshot))
        with self.assertRaisesRegex(SnapshotReleaseError, "escapes"):
            self._package("escape-release")

        self._build_sources()
        self.snapshot_path.write_bytes(self.snapshot_raw.replace(b'"suiteId"', b' "suiteId"'))
        with self.assertRaisesRegex(SnapshotReleaseError, "canonical JSON"):
            self._package("noncanonical-release")

    def test_snapshot_must_bind_exact_corpus_and_design_receipt_bytes(self) -> None:
        snapshot = json.loads(self.snapshot_raw)
        snapshot["corpusManifestSHA256"] = "0" * 64
        self.snapshot_path.write_bytes(canonical_line(snapshot))
        with self.assertRaisesRegex(SnapshotReleaseError, "different corpus"):
            self._package("wrong-corpus")

        self.snapshot_path.write_bytes(self.snapshot_raw)
        receipt = json.loads(self.design_receipt_raw)
        receipt["fixtureBoundary"] = "changed exact receipt bytes"
        unsigned = dict(receipt)
        unsigned.pop("contentSHA256")
        receipt["contentSHA256"] = sha256_bytes(canonical_json_bytes(unsigned))
        self.design_receipt_path.write_bytes(canonical_line(receipt))
        with self.assertRaisesRegex(SnapshotReleaseError, "different design"):
            self._package("wrong-design")

    def test_tampering_and_source_mutation_fail_closed(self) -> None:
        self._package("tampered-release")
        release = self.root / "tampered-release"
        archive_path = release / ASSET_NAMES["corpus-bytes"]
        os.chmod(release, 0o755)
        os.chmod(archive_path, 0o600)
        raw = bytearray(archive_path.read_bytes())
        raw[-1] ^= 1
        archive_path.write_bytes(raw)
        os.chmod(archive_path, 0o444)
        os.chmod(release, 0o555)
        with self.assertRaisesRegex(SnapshotReleaseError, "manifest differs"):
            verify_snapshot_release(
                corpus_root=self.corpus_root,
                snapshot_registration_path=self.snapshot_path,
                design_publication_receipt_path=self.design_receipt_path,
                asset_root=release,
            )

        self._package("source-change-release")
        manifest = self._manifest()
        record_path = self.corpus_root / manifest["projects"][PROJECTS[0]][
            "inventory"
        ][0]["record"]["relativePath"]
        record_path.write_bytes(record_path.read_bytes() + b"mutation")
        with self.assertRaisesRegex(SnapshotReleaseError, "commitment differs"):
            verify_snapshot_release(
                corpus_root=self.corpus_root,
                snapshot_registration_path=self.snapshot_path,
                design_publication_receipt_path=self.design_receipt_path,
                asset_root=self.root / "source-change-release",
            )

    def test_cli_verify_emits_canonical_structured_report(self) -> None:
        self._package("cli-release")
        project_root = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "v3.package_snapshot_release",
                "verify",
                "--corpus-root",
                str(self.corpus_root),
                "--snapshot-registration",
                str(self.snapshot_path),
                "--design-publication-receipt",
                str(self.design_receipt_path),
                "--asset-root",
                str(self.root / "cli-release"),
            ],
            cwd=project_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "VERIFIED_SNAPSHOT_RELEASE_ASSETS")
        self.assertEqual(len(report["assets"]), 5)
        self.assertEqual(completed.stdout, canonical_line(report))


if __name__ == "__main__":
    unittest.main()
