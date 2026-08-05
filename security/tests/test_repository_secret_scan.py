from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security.scan_repository_secrets import (
    MAX_REPORTED_FINDINGS,
    RepositoryScanError,
    matching_secret,
    scan_index,
    scan_reachable_history,
    scan_ref_names,
    scan_repository,
    scan_worktree,
)


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _git_text(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ("git", *arguments),
        cwd=root,
        text=True,
    ).strip()


def _initialize_repository(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Unit Test")
    _git(root, "config", "user.email", "unit@example.invalid")


def _github_token() -> bytes:
    return b"gh" + b"p_" + b"A" * 30


class RepositorySecretScanTests(unittest.TestCase):
    def test_high_confidence_private_material_is_detected(self) -> None:
        cases = (
            ("private key", b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----"),
            ("private key", b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"),
            ("private key", b"AGE-" + b"SECRET-KEY-1" + b"A" * 20),
            ("GitHub token", _github_token()),
            ("AWS access key", b"AK" + b"IA" + b"A" * 16),
            ("OpenAI key", b"s" + b"k-proj-" + b"A" * 24),
            ("Hugging Face token", b"h" + b"f_" + b"A" * 30),
            ("Slack token", b"xox" + b"b-" + b"A" * 20),
            ("Google API key", b"AI" + b"za" + b"A" * 30),
        )
        for expected, value in cases:
            with self.subTest(expected=expected):
                self.assertEqual(matching_secret(value), expected)

    def test_registered_public_signing_material_is_allowed(self) -> None:
        public_key = (ROOT / "v4/signing/corelm-crossmodel-v4-signing.pub").read_bytes()
        allowed_signers = (ROOT / "v4/signing/allowed_signers").read_bytes()
        self.assertIsNone(matching_secret(public_key))
        self.assertIsNone(matching_secret(allowed_signers))
        self.assertEqual(
            public_key,
            b"ssh-ed25519 "
            b"AAAAC3NzaC1lZDI1NTE5AAAAIKpsQwHhryVsgGIgNON9uTJzu4/Il5pj1vTFK7LCZuaB "
            b"Ivan Tyshchenko core-lm-cross-model-v4 signing\n",
        )

    def test_annotated_tag_is_not_misread_as_a_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            _git(root, "tag", "-a", "fixture-tag", "-m", "annotated fixture")
            self.assertEqual(scan_reachable_history(root), [])

    def test_removed_secret_remains_detectable_in_head_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "removed.txt").write_bytes(_github_token() + b"\n")
            _git(root, "add", "removed.txt")
            _git(root, "commit", "-q", "-m", "historical fixture")
            (root / "removed.txt").unlink()
            _git(root, "add", "-u")
            _git(root, "commit", "-q", "-m", "remove historical fixture")
            branch = _git_text(root, "branch", "--show-current")
            _git(root, "checkout", "--detach", "-q")
            _git(root, "branch", "-D", branch)
            findings = scan_reachable_history(root)
            self.assertEqual(len(findings), 1)
            self.assertIn("possible GitHub token", findings[0])

    def test_untracked_worktree_secret_is_detected_without_path_or_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            sensitive_name = "private-token-name.txt"
            token = _github_token()
            (root / sensitive_name).write_bytes(token + b"\n")
            findings = scan_worktree(root)
            self.assertEqual(len(findings), 1)
            self.assertIn("path-sha256:", findings[0])
            self.assertNotIn(sensitive_name, findings[0])
            self.assertNotIn(token.decode("ascii"), findings[0])

    def test_secret_shaped_path_and_ref_names_are_detected_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            token = _github_token().decode("ascii")
            secret_path = root / f"{token}.txt"
            secret_path.write_text("public contents\n", encoding="utf-8")
            worktree_findings = scan_worktree(root)
            self.assertEqual(len(worktree_findings), 1)
            self.assertIn("worktree-name:path-sha256:", worktree_findings[0])
            self.assertNotIn(token, worktree_findings[0])
            _git(root, "branch", token)
            ref_findings = scan_ref_names(root)
            self.assertEqual(len(ref_findings), 1)
            self.assertIn("ref:path-sha256:", ref_findings[0])
            self.assertNotIn(token, ref_findings[0])

    def test_staged_secret_is_detected_after_clean_worktree_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            path = root / "staged.txt"
            path.write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "staged.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            path.write_bytes(_github_token() + b"\n")
            _git(root, "add", "staged.txt")
            path.write_text("public worktree replacement\n", encoding="utf-8")
            self.assertEqual(scan_worktree(root), [])
            findings = scan_index(root)
            self.assertEqual(len(findings), 1)
            self.assertIn("possible GitHub token", findings[0])

    def test_commit_and_tag_messages_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            commit_message = (_github_token() + b" commit message").decode("ascii")
            _git(root, "commit", "--allow-empty", "-q", "-m", commit_message)
            tag_message = (_github_token() + b" tag message").decode("ascii")
            _git(root, "tag", "-a", "message-fixture", "-m", tag_message)
            findings = scan_reachable_history(root)
            self.assertEqual(len(findings), 2)
            self.assertTrue(any("(commit)" in finding for finding in findings))
            self.assertTrue(any("(tag)" in finding for finding in findings))

    def test_shallow_clone_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / "source"
            clone = parent / "clone"
            source.mkdir()
            _initialize_repository(source)
            (source / "public.txt").write_text("one\n", encoding="utf-8")
            _git(source, "add", "public.txt")
            _git(source, "commit", "-q", "-m", "one")
            (source / "public.txt").write_text("two\n", encoding="utf-8")
            _git(source, "commit", "-q", "-am", "two")
            subprocess.run(
                ("git", "clone", "-q", "--depth=1", source.as_uri(), str(clone)),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            with self.assertRaisesRegex(RepositoryScanError, "shallow"):
                scan_repository(clone)

    def test_promisor_configuration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            _git(root, "config", "remote.origin.promisor", "true")
            with self.assertRaisesRegex(RepositoryScanError, "partial/promisor"):
                scan_repository(root)

    def test_replace_refs_and_grafts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            path = root / "public.txt"
            path.write_text("one\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "one")
            path.write_text("two\n", encoding="utf-8")
            _git(root, "commit", "-q", "-am", "two")
            _git(root, "replace", "HEAD", "HEAD^")
            with self.assertRaisesRegex(RepositoryScanError, "replacement"):
                scan_repository(root)
            _git(root, "replace", "-d", "HEAD")
            git_dir = Path(_git_text(root, "rev-parse", "--git-dir"))
            if not git_dir.is_absolute():
                git_dir = root / git_dir
            grafts = git_dir / "info" / "grafts"
            grafts.parent.mkdir(parents=True, exist_ok=True)
            grafts.write_text(_git_text(root, "rev-parse", "HEAD") + "\n")
            with self.assertRaisesRegex(RepositoryScanError, "grafts"):
                scan_repository(root)

    def test_git_errors_never_expose_a_secret_shaped_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            token = _github_token().decode("ascii")
            bad_ref = root / ".git" / "refs" / "heads" / token
            bad_ref.write_text("not-an-object\n", encoding="ascii")
            with self.assertRaises(RepositoryScanError) as caught:
                scan_repository(root)
            self.assertNotIn(token, str(caught.exception))

    def test_unreadable_repository_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(RepositoryScanError):
                scan_repository(Path(temporary))

    def test_missing_secret_shaped_repository_path_is_redacted_by_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token = _github_token().decode("ascii")
            missing = Path(temporary) / token
            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    str(ROOT / "security/scan_repository_secrets.py"),
                    "--repository",
                    str(missing),
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn(token, completed.stdout)
            self.assertNotIn(token, completed.stderr)

    def test_gitlinks_fail_closed_in_worktree_and_index_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            head = _git_text(root, "rev-parse", "HEAD")
            _git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{head},vendor/submodule",
            )
            with self.assertRaisesRegex(RepositoryScanError, "submodules"):
                scan_worktree(root)
            with self.assertRaisesRegex(RepositoryScanError, "submodules"):
                scan_index(root)

    def test_reported_findings_are_deterministically_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            (root / "public.txt").write_text("public fixture\n", encoding="utf-8")
            _git(root, "add", "public.txt")
            _git(root, "commit", "-q", "-m", "fixture")
            token = _github_token().decode("ascii")
            for index in range(MAX_REPORTED_FINDINGS + 5):
                (root / f"{token}-{index}.txt").write_text(
                    "public fixture\n", encoding="utf-8"
                )
            findings = scan_worktree(root)
            self.assertEqual(len(findings), MAX_REPORTED_FINDINGS + 1)
            self.assertEqual(
                findings[-1],
                "additional findings omitted after deterministic report cap",
            )

    def test_workflow_fetches_and_checkout_are_quiet(self) -> None:
        workflow = (
            ROOT / ".github/workflows/repository-secret-scan.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("uses: actions/checkout@", workflow)
        self.assertIn("fetch --quiet --no-tags --depth=1", workflow)
        self.assertIn("checkout --quiet --detach", workflow)
        self.assertIn("--unshallow", workflow)
        self.assertEqual(workflow.count("fetch --quiet"), 4)
        self.assertEqual(workflow.count("2>/dev/null"), 7)


if __name__ == "__main__":
    unittest.main()
