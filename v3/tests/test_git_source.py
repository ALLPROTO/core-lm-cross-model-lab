from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from v3.git_source import (
    GitSourceError,
    build_source_manifest,
    canonical_json_bytes,
    iter_commit_files,
    load_source_manifest_bytes,
    seal_git_source,
    source_manifest_bytes,
    verify_copied_source,
)


def _git(
    repository: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> bytes:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Source Seal Test",
            "GIT_AUTHOR_EMAIL": "source-seal@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-03T00:00:00Z",
            "GIT_COMMITTER_NAME": "Source Seal Test",
            "GIT_COMMITTER_EMAIL": "source-seal@example.invalid",
            "GIT_COMMITTER_DATE": "2026-08-03T00:00:00Z",
            "LC_ALL": "C",
        }
    )
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout.rstrip(b"\n")


def _rehash_manifest(value: dict[str, object]) -> None:
    unsigned = dict(value)
    unsigned.pop("contentSHA256", None)
    value["contentSHA256"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


class GitSourceContractTests(unittest.TestCase):
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
        _git(self.repository, "commit", "-q", "-m", "sealed source")
        self.commit = _git(self.repository, "rev-parse", "HEAD").decode("ascii")
        self.tree = _git(self.repository, "rev-parse", "HEAD^{tree}").decode("ascii")
        self.seal = seal_git_source(
            self.repository,
            expected_commit=self.commit,
            expected_tree=self.tree,
        )
        self.manifest = build_source_manifest(self.seal)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def export(self, name: str = "export") -> Path:
        destination = self.root / name
        destination.mkdir()
        for entry in self.seal:
            path = destination / entry.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(entry.data)
            path.chmod(0o755 if entry.mode == "100755" else 0o644)
        return destination

    def test_seal_reads_commit_objects_not_dirty_worktree(self) -> None:
        (self.repository / "plain.txt").write_bytes(b"dirty replacement\n")
        (self.repository / "untracked.txt").write_bytes(b"not source\n")
        entries = tuple(
            iter_commit_files(
                self.repository,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )
        )
        observed = {path: (mode, data, oid) for path, mode, data, oid in entries}
        self.assertEqual(observed["plain.txt"][1], b"committed plain bytes\n")
        self.assertNotIn("untracked.txt", observed)
        self.assertEqual(observed["nested/run.sh"][0], "100755")
        self.assertEqual(len(observed["plain.txt"][2]), 40)

    def test_manifest_round_trip_and_gitless_export_verification(self) -> None:
        raw = source_manifest_bytes(self.manifest)
        self.assertEqual(load_source_manifest_bytes(raw), self.manifest)
        exported = self.export()
        with mock.patch(
            "v3.git_source.subprocess.run",
            side_effect=AssertionError("independent verifier invoked Git"),
        ):
            verified = verify_copied_source(
                exported,
                raw,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )
        self.assertEqual(verified, self.seal.files)
        self.assertFalse((exported / ".git").exists())

    def test_wrong_commit_tree_pair_is_rejected(self) -> None:
        with self.assertRaisesRegex(GitSourceError, "does not point"):
            seal_git_source(
                self.repository,
                expected_commit=self.commit,
                expected_tree="0" * 40,
            )
        with self.assertRaisesRegex(GitSourceError, "expected commit"):
            verify_copied_source(
                self.export(),
                self.manifest,
                expected_commit="1" * 40,
                expected_tree=self.tree,
            )

    def test_manifest_binds_exact_commit_object(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        commit_record = mutated["commitObject"]
        self.assertIsInstance(commit_record, dict)
        commit_record["dataBase64"] = "AA=="
        commit_record["bytes"] = 1
        _rehash_manifest(mutated)
        with self.assertRaisesRegex(GitSourceError, "commit object hash"):
            verify_copied_source(
                self.export(),
                mutated,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_manifest_reconstructs_the_complete_git_tree(self) -> None:
        mutated = copy.deepcopy(self.manifest)
        mutated["files"][0]["mode"] = (
            "100644" if mutated["files"][0]["mode"] == "100755" else "100755"
        )
        _rehash_manifest(mutated)
        with self.assertRaisesRegex(GitSourceError, "reconstruct"):
            verify_copied_source(
                self.export(),
                mutated,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_tampered_extra_and_missing_files_are_rejected(self) -> None:
        tampered = self.export("tampered")
        (tampered / "plain.txt").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(GitSourceError, "bytes differ"):
            verify_copied_source(
                tampered,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

        extra = self.export("extra")
        (extra / "extra.txt").write_bytes(b"extra\n")
        with self.assertRaisesRegex(GitSourceError, "inventory differs"):
            verify_copied_source(
                extra,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

        missing = self.export("missing")
        (missing / "plain.txt").unlink()
        with self.assertRaisesRegex(GitSourceError, "inventory differs"):
            verify_copied_source(
                missing,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_physical_executable_mode_is_verified(self) -> None:
        exported = self.export()
        (exported / "nested" / "run.sh").chmod(0o644)
        with self.assertRaisesRegex(GitSourceError, "executable mode differs"):
            verify_copied_source(
                exported,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_symlink_is_rejected_from_git_not_followed(self) -> None:
        os.symlink("plain.txt", self.repository / "alias")
        _git(self.repository, "add", "alias")
        _git(self.repository, "commit", "-q", "-m", "symlink")
        commit = _git(self.repository, "rev-parse", "HEAD").decode("ascii")
        tree = _git(self.repository, "rev-parse", "HEAD^{tree}").decode("ascii")
        with self.assertRaisesRegex(GitSourceError, "symbolic links"):
            seal_git_source(
                self.repository,
                expected_commit=commit,
                expected_tree=tree,
            )

    def test_submodule_mode_is_rejected(self) -> None:
        _git(
            self.repository,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.commit},vendor",
        )
        tree = _git(self.repository, "write-tree").decode("ascii")
        commit = _git(self.repository, "commit-tree", tree, input_bytes=b"gitlink\n").decode(
            "ascii"
        )
        with self.assertRaisesRegex(GitSourceError, "submodules"):
            seal_git_source(
                self.repository,
                expected_commit=commit,
                expected_tree=tree,
            )

    def test_unsafe_and_noncanonical_raw_trees_are_rejected(self) -> None:
        blob = _git(
            self.repository,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b"payload",
        ).decode("ascii")
        cases = (
            (b"100644 ..\0" + bytes.fromhex(blob), "unsafe dot"),
            (
                b"100644 z\0"
                + bytes.fromhex(blob)
                + b"100644 a\0"
                + bytes.fromhex(blob),
                "canonical Git order",
            ),
            (
                b"100644 A\0"
                + bytes.fromhex(blob)
                + b"100644 a\0"
                + bytes.fromhex(blob),
                "case-folding",
            ),
        )
        for index, (tree_object, message) in enumerate(cases):
            with self.subTest(index=index):
                tree = _git(
                    self.repository,
                    "hash-object",
                    "--literally",
                    "-t",
                    "tree",
                    "-w",
                    "--stdin",
                    input_bytes=tree_object,
                ).decode("ascii")
                commit = _git(
                    self.repository,
                    "commit-tree",
                    tree,
                    input_bytes=f"raw {index}\n".encode(),
                ).decode("ascii")
                with self.assertRaisesRegex(GitSourceError, message):
                    seal_git_source(
                        self.repository,
                        expected_commit=commit,
                        expected_tree=tree,
                    )

    def test_export_rejects_symlink_and_empty_directory(self) -> None:
        exported = self.export("symlink-export")
        (exported / "plain.txt").unlink()
        os.symlink(self.repository / "plain.txt", exported / "plain.txt")
        with self.assertRaisesRegex(GitSourceError, "symbolic link"):
            verify_copied_source(
                exported,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

        exported = self.export("empty-directory-export")
        (exported / "empty").mkdir()
        with self.assertRaisesRegex(GitSourceError, "inventory differs"):
            verify_copied_source(
                exported,
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
            )

    def test_noncanonical_or_duplicate_json_is_rejected(self) -> None:
        pretty = canonical_json_bytes(self.manifest).replace(b"{", b"{ ", 1) + b"\n"
        with self.assertRaisesRegex(GitSourceError, "not canonical"):
            load_source_manifest_bytes(pretty)
        with self.assertRaisesRegex(GitSourceError, "duplicate"):
            load_source_manifest_bytes(b'{"x":1,"x":2}\n')

    def test_fixed_bounds_are_enforced_on_both_sides(self) -> None:
        with self.assertRaisesRegex(GitSourceError, "byte bound"):
            seal_git_source(
                self.repository,
                expected_commit=self.commit,
                expected_tree=self.tree,
                maximum_file_bytes=4,
            )
        with self.assertRaisesRegex(GitSourceError, "byte bound"):
            verify_copied_source(
                self.export(),
                self.manifest,
                expected_commit=self.commit,
                expected_tree=self.tree,
                maximum_file_bytes=4,
            )


if __name__ == "__main__":
    unittest.main()
