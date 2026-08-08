from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from blind_v1 import package_evidence_assets as subject
from blind_v1.release_receipt import REQUIRED_ASSET_ROLES


def canonical_line(value: object) -> bytes:
    return subject.canonical_json_bytes(value) + b"\n"


def content_bound(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["contentSHA256"] = subject.sha256_bytes(
        subject.canonical_json_bytes(result)
    )
    return result


def make_read_only(root: Path) -> None:
    directories: list[Path] = []
    for directory, child_directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        current = Path(directory)
        directories.append(current)
        for filename in filenames:
            path = current / filename
            if not path.is_symlink():
                os.chmod(path, 0o444, follow_symlinks=False)
        for child in child_directories:
            path = current / child
            if not path.is_symlink():
                directories.append(path)
    for directory in sorted(set(directories), key=lambda path: len(path.parts), reverse=True):
        os.chmod(directory, 0o555, follow_symlinks=False)


class EvidenceAssetPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._cleanup, temporary)
        self.root = Path(temporary.name)
        self.evidence = self.root / "sealed-evidence"
        self.report = self.root / "external-verifier-report.json"
        self._build_source()

    @staticmethod
    def _cleanup(temporary: tempfile.TemporaryDirectory[str]) -> None:
        root = Path(temporary.name)
        for directory, child_directories, filenames in os.walk(
            root, topdown=False, followlinks=False
        ):
            current = Path(directory)
            for filename in filenames:
                path = current / filename
                if not path.is_symlink():
                    try:
                        os.chmod(path, 0o600, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
            for child in child_directories:
                path = current / child
                if not path.is_symlink():
                    try:
                        os.chmod(path, 0o700, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
            try:
                os.chmod(current, 0o700, follow_symlinks=False)
            except FileNotFoundError:
                pass
        temporary.cleanup()

    def _build_source(self) -> None:
        payloads = {
            "payload/attempt/attempt-reservation.json": b'{"reserved":true}\n',
            "payload/attempt/raw/nist-response.bin": b"real archived bytes\x00\xff",
            "payload/corpus/corpus-manifest.json": b'{"corpus":"bound"}\n',
        }
        entries: list[dict[str, object]] = []
        for relative, raw in payloads.items():
            path = self.evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            role = "public-corpus" if relative.startswith("payload/corpus/") else "attempt-evidence"
            entries.append(
                {
                    "path": relative,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "role": role,
                }
            )
        entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
        manifest = content_bound(
            {
                "schemaVersion": subject.INNER_MANIFEST_SCHEMA,
                "suiteId": subject.SUITE_ID,
                "attemptId": "20260821T180000Z-0123456789abcdef",
                "createdAt": "2026-08-22T18:05:00Z",
                "packageStatus": "PARTIAL_CONSUMED_INCOMPLETE",
                "recoveryClassification": "CONSUMED_INCOMPLETE",
                "terminalState": None,
                "attemptCountsTowardScientificVerdict": False,
                "artifactPresence": {"attemptReservation": True},
                "forensicArtifacts": [],
                "missingArtifacts": ["payload/attempt/terminal-outcome.json"],
                "groups": {"attempt": {}, "corpus": {}},
                "entries": entries,
                "entryCount": len(entries),
                "totalBytes": sum(int(item["bytes"]) for item in entries),
                "entriesSHA256": subject.sha256_bytes(
                    subject.canonical_json_bytes(entries)
                ),
            }
        )
        manifest_raw = canonical_line(manifest)
        (self.evidence / subject.INNER_MANIFEST_NAME).write_bytes(manifest_raw)
        report = content_bound(
            {
                "schemaVersion": subject.INNER_REPORT_SCHEMA,
                "status": "VERIFIED_PARTIAL_CONSUMED_INCOMPLETE",
                "suiteId": manifest["suiteId"],
                "attemptId": manifest["attemptId"],
                "recoveryClassification": manifest["recoveryClassification"],
                "terminalState": manifest["terminalState"],
                "attemptCountsTowardScientificVerdict": manifest[
                    "attemptCountsTowardScientificVerdict"
                ],
                "entryCount": manifest["entryCount"],
                "totalBytes": manifest["totalBytes"],
                "manifestFileSHA256": subject.sha256_bytes(manifest_raw),
                "manifestContentSHA256": manifest["contentSHA256"],
                "missingArtifacts": manifest["missingArtifacts"],
                "forensicArtifacts": manifest["forensicArtifacts"],
            }
        )
        self.report.write_bytes(canonical_line(report))
        os.chmod(self.report, 0o444)
        make_read_only(self.evidence)

    def _package(self, name: str) -> Path:
        output = self.root / name
        result = subject._historical_package_evidence_assets(
            evidence_root=self.evidence,
            verifier_report=self.report,
            output_directory=output,
        )
        self.assertEqual(
            result["status"], "VERIFIED_CANONICAL_EVIDENCE_RELEASE_ASSETS"
        )
        return output

    def _rewrite_sha_manifest_for_archive(self, output: Path) -> None:
        path = output / subject.ASSET_NAMES["sha256-manifest"]
        value = json.loads(path.read_bytes())
        archive_path = output / subject.ASSET_NAMES["evidence-package"]
        archive_raw = archive_path.read_bytes()
        for item in value["assets"]:
            if item["role"] == "evidence-package":
                item["bytes"] = len(archive_raw)
                item["sha256"] = hashlib.sha256(archive_raw).hexdigest()
        os.chmod(path, 0o600)
        path.write_bytes(canonical_line(value))
        os.chmod(path, 0o444)

    def test_deterministic_four_role_assets_verify_and_extract(self) -> None:
        self.assertEqual(subject.ASSET_ROLES, REQUIRED_ASSET_ROLES["evidence"])
        first = self._package("release-assets-one")
        second = self._package("release-assets-two")
        self.assertEqual(
            {path.name for path in first.iterdir()},
            set(subject.ASSET_NAMES.values()),
        )
        for name in subject.ASSET_NAMES.values():
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        result = subject.verify_evidence_assets(first)
        self.assertEqual(result["archiveFormat"], "POSIX-USTAR-UNCOMPRESSED")
        self.assertEqual(result["archiveMemberCount"], 4)

        extracted = self.root / "extracted-evidence"
        subject.extract_evidence_package(asset_root=first, output_directory=extracted)
        for relative in (
            subject.INNER_MANIFEST_NAME,
            "payload/attempt/attempt-reservation.json",
            "payload/attempt/raw/nist-response.bin",
            "payload/corpus/corpus-manifest.json",
        ):
            self.assertEqual(
                (extracted / relative).read_bytes(),
                (self.evidence / relative).read_bytes(),
            )
        self.assertEqual(stat.S_IMODE(extracted.stat().st_mode), 0o555)

    def test_cross_binding_rejects_fabricated_report_before_output(self) -> None:
        report = json.loads(self.report.read_bytes())
        report["manifestFileSHA256"] = "f" * 64
        report.pop("contentSHA256")
        report = content_bound(report)
        os.chmod(self.report, 0o600)
        self.report.write_bytes(canonical_line(report))
        os.chmod(self.report, 0o444)
        output = self.root / "must-not-exist"
        with self.assertRaisesRegex(subject.EvidenceAssetError, "does not bind"):
            subject._historical_package_evidence_assets(
                evidence_root=self.evidence,
                verifier_report=self.report,
                output_directory=output,
            )
        self.assertFalse(output.exists())

    def test_inner_manifest_rejects_nonpublic_attempt_prefix(self) -> None:
        manifest = json.loads(
            (self.evidence / subject.INNER_MANIFEST_NAME).read_bytes()
        )
        manifest["attemptId"] = "20260926T180000Z-0123456789abcdef"
        with self.assertRaisesRegex(subject.EvidenceAssetError, "identity differs"):
            subject._validate_inner_manifest(manifest)

    def test_sealed_source_rejects_extra_symlink_hardlink_and_writable_file(self) -> None:
        cases = ("extra", "symlink", "hardlink", "writable")
        for case in cases:
            with self.subTest(case=case):
                temporary = tempfile.TemporaryDirectory(dir=self.root)
                self.addCleanup(self._cleanup, temporary)
                evidence = Path(temporary.name) / "evidence"
                report = Path(temporary.name) / "report.json"
                os.mkdir(evidence)
                source_files = {}
                for directory, _children, filenames in os.walk(self.evidence):
                    for filename in filenames:
                        source = Path(directory) / filename
                        relative = source.relative_to(self.evidence)
                        destination = evidence / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(source.read_bytes())
                        source_files[relative.as_posix()] = destination
                report.write_bytes(self.report.read_bytes())
                os.chmod(report, 0o444)
                target = source_files["payload/attempt/raw/nist-response.bin"]
                if case == "extra":
                    (evidence / "extra.bin").write_bytes(b"extra")
                elif case == "symlink":
                    target.unlink()
                    target.symlink_to(evidence / subject.INNER_MANIFEST_NAME)
                elif case == "hardlink":
                    os.link(target, evidence / "alias.bin")
                else:
                    os.chmod(target, 0o644)
                make_read_only(evidence)
                if case == "writable":
                    os.chmod(target, 0o644)
                with self.assertRaises(subject.EvidenceAssetError):
                    subject._historical_package_evidence_assets(
                        evidence_root=evidence,
                        verifier_report=report,
                        output_directory=Path(temporary.name) / "output",
                    )

    def test_rehashed_noncanonical_tar_header_fails_before_extraction(self) -> None:
        output = self._package("malicious-container")
        archive = output / subject.ASSET_NAMES["evidence-package"]
        raw = bytearray(archive.read_bytes())
        raw[156] = ord("2")
        os.chmod(archive, 0o600)
        archive.write_bytes(raw)
        os.chmod(archive, 0o444)
        self._rewrite_sha_manifest_for_archive(output)
        destination = self.root / "must-not-extract"
        with self.assertRaisesRegex(subject.EvidenceAssetError, "USTAR header"):
            subject.extract_evidence_package(
                asset_root=output,
                output_directory=destination,
            )
        self.assertFalse(destination.exists())

    def test_tamper_extra_and_symlink_release_assets_fail_closed(self) -> None:
        tampered = self._package("tampered-assets")
        archive = tampered / subject.ASSET_NAMES["evidence-package"]
        raw = archive.read_bytes()
        os.chmod(archive, 0o600)
        archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        os.chmod(archive, 0o444)
        with self.assertRaisesRegex(subject.EvidenceAssetError, "commitment differs"):
            subject.verify_evidence_assets(tampered)

        extra = self._package("extra-assets")
        os.chmod(extra, 0o755)
        (extra / "unexpected.bin").write_bytes(b"extra")
        os.chmod(extra / "unexpected.bin", 0o444)
        os.chmod(extra, 0o555)
        with self.assertRaisesRegex(subject.EvidenceAssetError, "inventory differs"):
            subject.verify_evidence_assets(extra)

        linked = self._package("linked-assets")
        manifest = linked / subject.ASSET_NAMES["evidence-release-manifest"]
        os.chmod(linked, 0o755)
        manifest.unlink()
        manifest.symlink_to(linked / subject.ASSET_NAMES["evidence-package-verifier-report"])
        os.chmod(linked, 0o555)
        with self.assertRaisesRegex(subject.EvidenceAssetError, "unsafe"):
            subject.verify_evidence_assets(linked)

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaisesRegex(subject.EvidenceAssetError, "already exists"):
            subject._historical_package_evidence_assets(
                evidence_root=self.evidence,
                verifier_report=self.report,
                output_directory=output,
            )
        self.assertEqual(sentinel.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
