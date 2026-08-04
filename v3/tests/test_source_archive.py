from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import stat
from pathlib import Path
from unittest import mock

from v3.source_archive import (
    MANIFEST_MEMBER,
    SOURCE_PREFIX,
    SourceArchiveError,
    create_source_archive,
    verify_source_archive,
)


def _git(repository: Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Source Archive Test",
            "GIT_AUTHOR_EMAIL": "source-archive@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-03T00:00:00Z",
            "GIT_COMMITTER_NAME": "Source Archive Test",
            "GIT_COMMITTER_EMAIL": "source-archive@example.invalid",
            "GIT_COMMITTER_DATE": "2026-08-03T00:00:00Z",
            "LC_ALL": "C",
        }
    )
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout.decode("ascii").strip()


def _info(
    name: str,
    data: bytes,
    *,
    mode: int = 0o644,
    member_type: bytes = tarfile.REGTYPE,
    linkname: str = "",
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.size = len(data) if member_type == tarfile.REGTYPE else 0
    info.mtime = 0
    info.type = member_type
    info.linkname = linkname
    info.uname = ""
    info.gname = ""
    info.devmajor = 0
    info.devminor = 0
    return info


def _records(path: Path) -> list[tuple[str, int, bytes]]:
    result: list[tuple[str, int, bytes]] = []
    with tarfile.open(path, "r:", encoding="utf-8", errors="strict") as archive:
        for member in archive:
            stream = archive.extractfile(member)
            if stream is None:
                raise AssertionError("fixture archive unexpectedly contains a non-file")
            result.append((member.name, member.mode, stream.read()))
    return result


def _write_variant(
    path: Path,
    records: list[tuple[str, int, bytes]],
    *,
    first_source_type: bytes | None = None,
    unsafe_extra: bool = False,
    safe_extra: bool = False,
) -> None:
    source_replaced = False
    with tarfile.open(
        path,
        "w:",
        format=tarfile.USTAR_FORMAT,
        encoding="utf-8",
        errors="strict",
    ) as archive:
        for name, mode, data in records:
            if (
                first_source_type is not None
                and name.startswith(SOURCE_PREFIX)
                and not source_replaced
            ):
                linkname = "../../outside" if first_source_type in {
                    tarfile.SYMTYPE,
                    tarfile.LNKTYPE,
                } else ""
                archive.addfile(
                    _info(
                        name,
                        b"",
                        mode=mode,
                        member_type=first_source_type,
                        linkname=linkname,
                    )
                )
                source_replaced = True
            else:
                archive.addfile(_info(name, data, mode=mode), io.BytesIO(data))
        if unsafe_extra:
            data = b"escape\n"
            archive.addfile(_info("../escape", data), io.BytesIO(data))
        if safe_extra:
            data = b"extra\n"
            archive.addfile(_info("source/extra.txt", data), io.BytesIO(data))


class SourceArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        _git(self.repository, "init", "-q")
        (self.repository / "plain.txt").write_bytes(b"committed plain bytes\n")
        (self.repository / "nested").mkdir()
        executable = self.repository / "nested" / "run.sh"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        (self.repository / "unicode-é.txt").write_bytes(b"strict utf-8 path\n")
        _git(self.repository, "add", "plain.txt", "nested/run.sh", "unicode-é.txt")
        _git(self.repository, "commit", "-q", "-m", "archived source")
        self.commit = _git(self.repository, "rev-parse", "HEAD")
        self.tree = _git(self.repository, "rev-parse", "HEAD^{tree}")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, name: str = "source.tar") -> Path:
        destination = self.root / name
        create_source_archive(
            self.repository,
            destination,
            expected_commit=self.commit,
            expected_tree=self.tree,
        )
        return destination

    def test_repeated_builds_are_byte_identical_canonical_ustar(self) -> None:
        first = self.create("first.tar")
        second = self.create("second.tar")
        first_raw = first.read_bytes()
        self.assertEqual(first_raw, second.read_bytes())
        self.assertEqual(len(first_raw) % tarfile.RECORDSIZE, 0)

        records = _records(first)
        self.assertEqual(records[0][0], MANIFEST_MEMBER)
        self.assertEqual(
            [name for name, _mode, _data in records[1:]],
            sorted(
                [name for name, _mode, _data in records[1:]],
                key=lambda value: value[len(SOURCE_PREFIX) :].encode("utf-8"),
            ),
        )
        report = verify_source_archive(
            first,
            expected_commit=self.commit,
            expected_tree=self.tree,
        )
        self.assertEqual(report.archive_sha256, hashlib.sha256(first_raw).hexdigest())
        self.assertEqual(report.file_count, 3)

    def test_exact_verification_is_gitless_and_wrong_identity_is_rejected(self) -> None:
        archive = self.create()
        (self.repository / "plain.txt").write_bytes(b"dirty worktree replacement\n")
        with mock.patch(
            "v3.git_source.subprocess.run",
            side_effect=AssertionError("archive verifier invoked Git"),
        ):
            report = verify_source_archive(
                archive,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )
        self.assertEqual(report.commit, self.commit)
        self.assertEqual(report.tree, self.tree)
        with self.assertRaisesRegex(SourceArchiveError, "commit differs"):
            verify_source_archive(
                archive,
                expected_commit="0" * 40,
                expected_tree=self.tree,
            )
        with self.assertRaisesRegex(SourceArchiveError, "tree differs"):
            verify_source_archive(
                archive,
                expected_commit=self.commit,
                expected_tree="0" * 40,
            )

    def test_tampered_payload_and_extra_member_are_rejected(self) -> None:
        archive = self.create()
        tampered = self.root / "tampered.tar"
        raw = archive.read_bytes()
        needle = b"committed plain bytes\n"
        offset = raw.find(needle)
        self.assertGreaterEqual(offset, 0)
        tampered.write_bytes(raw[:offset] + b"T" + raw[offset + 1 :])
        with self.assertRaisesRegex(SourceArchiveError, "bytes differ"):
            verify_source_archive(
                tampered,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

        extra = self.root / "extra.tar"
        _write_variant(extra, _records(archive), safe_extra=True)
        with self.assertRaisesRegex(SourceArchiveError, "extra member"):
            verify_source_archive(
                extra,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_unsafe_paths_links_and_special_entries_are_rejected(self) -> None:
        archive = self.create()
        records = _records(archive)
        cases = (
            (tarfile.SYMTYPE, "symbolic"),
            (tarfile.LNKTYPE, "hardlink"),
            (tarfile.FIFOTYPE, "fifo"),
        )
        for index, (member_type, label) in enumerate(cases):
            with self.subTest(label=label):
                unsafe = self.root / f"unsafe-{index}.tar"
                _write_variant(unsafe, records, first_source_type=member_type)
                with self.assertRaisesRegex(SourceArchiveError, "not a regular file"):
                    verify_source_archive(
                        unsafe,
                        expected_commit=self.commit,
                        expected_tree=self.tree,
                    )

        traversal = self.root / "traversal.tar"
        _write_variant(traversal, records, unsafe_extra=True)
        with self.assertRaisesRegex(SourceArchiveError, "unsafe path component"):
            verify_source_archive(
                traversal,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_external_ancestor_symlinks_are_rejected_and_output_dir_is_synced(self) -> None:
        archive = self.create("canonical.tar")
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(SourceArchiveError):
            verify_source_archive(
                linked_parent / archive.name,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )
        linked_repository = self.root / "linked-repository"
        linked_repository.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaises(SourceArchiveError):
            create_source_archive(
                linked_repository,
                self.root / "bad-repository.tar",
                expected_commit=self.commit,
                expected_tree=self.tree,
            )
        with self.assertRaises(SourceArchiveError):
            create_source_archive(
                self.repository,
                linked_parent / "bad-output.tar",
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

        directory_syncs = 0
        real_fsync = os.fsync

        def recording_fsync(descriptor: int) -> None:
            nonlocal directory_syncs
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directory_syncs += 1
            real_fsync(descriptor)

        with mock.patch("v3.source_archive.os.fsync", side_effect=recording_fsync):
            self.create("durable.tar")
        self.assertGreaterEqual(directory_syncs, 2)

    def test_cli_create_and_verify(self) -> None:
        archive = self.root / "cli.tar"
        create = subprocess.run(
            [
                sys.executable,
                "-m",
                "v3.source_archive",
                "create",
                "--repository",
                os.fspath(self.repository),
                "--output",
                os.fspath(archive),
                "--commit",
                self.commit,
                "--tree",
                self.tree,
            ],
            cwd=Path(__file__).resolve().parents[2],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(create.returncode, 0, create.stderr.decode("utf-8", "replace"))
        created = json.loads(create.stdout)
        self.assertEqual(created["status"], "SOURCE_ARCHIVE_VERIFIED")

        verify = subprocess.run(
            [
                sys.executable,
                "-m",
                "v3.source_archive",
                "verify",
                "--archive",
                os.fspath(archive),
                "--expected-commit",
                self.commit,
                "--expected-tree",
                self.tree,
            ],
            cwd=Path(__file__).resolve().parents[2],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr.decode("utf-8", "replace"))
        self.assertEqual(json.loads(verify.stdout), created)


if __name__ == "__main__":
    unittest.main()
