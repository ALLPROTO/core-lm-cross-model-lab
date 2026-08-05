#!/usr/bin/env python3
"""Run the real-data V4 engine only as a post-release development regression.

This entrypoint is deliberately incompatible with the canonical development
control and the scientific attempt. It verifies the signed frozen development
tag, permits execution after the old development cutoff, and emits only
post-release regression marker/report names.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath


V4_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V4_ROOT.parent
FROZEN_TAG = "corelm-crossmodel-livewiki-v4-development-control"
FROZEN_TAG_OBJECT = "767e114baacf864fbeb195b42e9df2be22e6133d"
FROZEN_COMMIT = "f46a5365a585e18f0c198235729fc8259b55abcc"
FROZEN_TREE = "1e15fb82aee21b51cd21e6d8a5f5ff21b35ff658"
POST_RELEASE_TAG = "corelm-crossmodel-v4-post-release-regression-v1"
PUBLIC_KEY_SHA256 = (
    "9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274"
)
ALLOWED_SIGNERS_SHA256 = (
    "36fb4a170eee7664be32f2a5d562db209fa4f6f1f24667cf6a3ef0166d155c16"
)
ALLOWED_CHANGES = frozenset(
    {
        ".github/workflows/repository-secret-scan.yml",
        "README.md",
        "REPRODUCE.md",
        "security/__init__.py",
        "security/scan_repository_secrets.py",
        "security/tests/__init__.py",
        "security/tests/test_repository_secret_scan.py",
        "v4/bootstrap_runtime.sh",
        "v4/run_post_release_regression.py",
        "v4/run_real_e2e_control.py",
        "v4/tests/test_real_e2e_control.py",
    }
)
MAX_GIT_OUTPUT = 16 * 1024 * 1024


def _fail(message: str) -> "NoReturn":
    raise SystemExit(f"POST-RELEASE REGRESSION FAIL: {message}")


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git(
    arguments: tuple[str, ...],
    *,
    allow_missing_config: bool = False,
    maximum_bytes: int = MAX_GIT_OUTPUT,
) -> bytes:
    try:
        completed = subprocess.run(
            (
                "/usr/bin/git",
                "-C",
                str(PROJECT_ROOT),
                "-c",
                f"core.worktree={PROJECT_ROOT}",
                "-c",
                "core.bare=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.ignoreStat=false",
                "-c",
                "core.untrackedCache=false",
                *arguments,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("pre-import Git verification could not run")
    if (
        allow_missing_config
        and completed.returncode == 1
        and not completed.stderr
    ):
        return b""
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > maximum_bytes
    ):
        _fail("pre-import Git verification failed closed")
    return completed.stdout


def _git_text(arguments: tuple[str, ...]) -> str:
    try:
        value = _git(arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        _fail("pre-import Git identity is not UTF-8")
    if "\x00" in value:
        _fail("pre-import Git identity contains NUL")
    return value


def _read_regular(
    path: Path,
    *,
    maximum_bytes: int,
    expected_executable: bool | None = None,
) -> bytes:
    try:
        metadata = path.lstat()
    except OSError:
        _fail("pre-import source file is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > maximum_bytes
    ):
        _fail("pre-import source file has an unsafe type or size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            data = bytearray()
            while len(data) <= maximum_bytes:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, maximum_bytes + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        _fail("pre-import source file cannot be read")
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after) or len(data) != before.st_size:
        _fail("pre-import source file changed while verified")
    if (
        expected_executable is not None
        and bool(before.st_mode & stat.S_IXUSR) != expected_executable
    ):
        _fail("pre-import tracked file mode differs from HEAD")
    return bytes(data)


def _verify_signature(tag: str, allowed_signers: Path) -> None:
    try:
        completed = subprocess.run(
            (
                "/usr/bin/git",
                "-C",
                str(PROJECT_ROOT),
                "-c",
                f"core.worktree={PROJECT_ROOT}",
                "-c",
                "core.bare=false",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed_signers}",
                "-c",
                "gpg.ssh.program=/usr/bin/ssh-keygen",
                "verify-tag",
                tag,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("pre-import signature verification could not run")
    if (
        completed.returncode != 0
        or len(completed.stdout) > 4096
        or len(completed.stderr) > 4096
    ):
        _fail("pre-import signed source tag cannot be verified")


def _verify_repository_layout() -> None:
    try:
        root = PROJECT_ROOT.resolve(strict=True)
        dot_git = (root / ".git").resolve(strict=True)
        dot_git_metadata = (root / ".git").lstat()
    except OSError:
        _fail("pre-import repository layout is unavailable")
    local_config = _git(("config", "--local", "--name-only", "--list", "-z"))
    if local_config and not local_config.endswith(b"\x00"):
        _fail("pre-import local Git configuration is invalid")
    try:
        local_names = {
            name.decode("utf-8", errors="strict").casefold()
            for name in local_config[:-1].split(b"\x00")
            if name
        }
    except UnicodeDecodeError:
        _fail("pre-import local Git configuration is invalid")
    forbidden_names = {
        "core.attributesfile",
        "core.excludesfile",
        "core.worktree",
        "extensions.worktreeconfig",
    }
    if local_names & forbidden_names or any(
        name.startswith("filter.") for name in local_names
    ):
        _fail("pre-import local Git path or filter configuration is forbidden")
    try:
        top = Path(_git_text(("rev-parse", "--show-toplevel"))).resolve(strict=True)
        git_dir = Path(
            _git_text(("rev-parse", "--absolute-git-dir"))
        ).resolve(strict=True)
        common_dir = Path(
            _git_text(
                ("rev-parse", "--path-format=absolute", "--git-common-dir")
            )
        ).resolve(strict=True)
    except OSError:
        _fail("pre-import repository layout is unavailable")
    if (
        root != PROJECT_ROOT
        or not stat.S_ISDIR(dot_git_metadata.st_mode)
        or stat.S_ISLNK(dot_git_metadata.st_mode)
        or top != root
        or git_dir != dot_git
        or common_dir != dot_git
    ):
        _fail("pre-import repository layout differs from a standalone clone")
    exclude_path = dot_git / "info" / "exclude"
    if exclude_path.exists() or exclude_path.is_symlink():
        raw = _read_regular(exclude_path, maximum_bytes=64 * 1024)
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            _fail("pre-import Git exclude policy is invalid")
        if any(line.strip() and not line.lstrip().startswith("#") for line in lines):
            _fail("pre-import local Git exclude patterns are forbidden")
    attributes_path = dot_git / "info" / "attributes"
    if attributes_path.exists() or attributes_path.is_symlink():
        _fail("pre-import local Git attributes are forbidden")


def _verify_clean_tracked_source() -> None:
    if _git(("for-each-ref", "--format=%(refname)", "refs/replace")):
        _fail("pre-import replacement refs are forbidden")
    graft_path = Path(
        _git_text(
            ("rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
        )
    )
    if graft_path.exists() or graft_path.is_symlink():
        _fail("pre-import grafts are forbidden")
    index = _git(("ls-files", "-v", "-z"))
    if index and (
        not index.endswith(b"\x00")
        or any(
            len(entry) < 3 or entry[:2] != b"H "
            for entry in index[:-1].split(b"\x00")
        )
    ):
        _fail("pre-import index has non-canonical flags")
    if _git(
        (
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
    ):
        _fail("pre-import worktree is not clean")
    if _git(("ls-files", "--others", "--ignored", "--exclude-standard", "-z")):
        _fail("pre-import ignored untracked paths are forbidden")


def _verify_live_tracked_files() -> None:
    inventory = _git(("ls-tree", "-r", "-z", "HEAD"))
    for raw_entry in inventory.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            header, raw_path = raw_entry.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = header.split(b" ", 2)
        except ValueError:
            _fail("pre-import tracked-file inventory is invalid")
        if (
            raw_mode not in {b"100644", b"100755"}
            or raw_type != b"blob"
            or len(raw_object_id) != 40
            or any(byte not in b"0123456789abcdef" for byte in raw_object_id)
        ):
            _fail("pre-import tracked entry is not a regular Git blob")
        try:
            relative = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _fail("pre-import tracked path is not UTF-8")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            _fail("pre-import tracked path is unsafe")
        live = _read_regular(
            PROJECT_ROOT / relative,
            maximum_bytes=16 * 1024 * 1024,
            expected_executable=raw_mode == b"100755",
        )
        committed = _git(
            ("cat-file", "blob", raw_object_id.decode("ascii")),
            maximum_bytes=16 * 1024 * 1024,
        )
        if live != committed:
            _fail("pre-import live tracked file differs from HEAD")


def _preimport_source_gate() -> None:
    _verify_repository_layout()
    _verify_clean_tracked_source()
    public_key = V4_ROOT / "signing" / "corelm-crossmodel-v4-signing.pub"
    allowed_signers = V4_ROOT / "signing" / "allowed_signers"
    if hashlib.sha256(_read_regular(public_key, maximum_bytes=4096)).hexdigest() != (
        PUBLIC_KEY_SHA256
    ):
        _fail("pre-import public signing key differs")
    if hashlib.sha256(_read_regular(allowed_signers, maximum_bytes=4096)).hexdigest() != (
        ALLOWED_SIGNERS_SHA256
    ):
        _fail("pre-import allowed-signers policy differs")
    if (
        _git_text(("cat-file", "-t", FROZEN_TAG)) != "tag"
        or _git_text(("rev-parse", FROZEN_TAG)) != FROZEN_TAG_OBJECT
        or _git_text(("rev-list", "-n", "1", FROZEN_TAG)) != FROZEN_COMMIT
        or _git_text(("rev-parse", f"{FROZEN_TAG}^{{tree}}")) != FROZEN_TREE
    ):
        _fail("pre-import frozen source identity differs")
    _verify_signature(FROZEN_TAG, allowed_signers)
    if _git_text(("cat-file", "-t", POST_RELEASE_TAG)) != "tag":
        _fail("pre-import post-release tag is not annotated")
    post_commit = _git_text(("rev-list", "-n", "1", POST_RELEASE_TAG))
    post_tree = _git_text(("rev-parse", f"{POST_RELEASE_TAG}^{{tree}}"))
    if (
        post_commit != _git_text(("rev-parse", "HEAD"))
        or post_tree != _git_text(("rev-parse", "HEAD^{tree}"))
    ):
        _fail("pre-import post-release tag does not target HEAD")
    _verify_signature(POST_RELEASE_TAG, allowed_signers)
    if _git_text(("merge-base", "--is-ancestor", FROZEN_COMMIT, "HEAD")):
        _fail("pre-import frozen source ancestry check differs")
    changed = {
        path
        for path in _git_text(
            ("diff", "--name-only", FROZEN_COMMIT, "HEAD", "--")
        ).splitlines()
        if path
    }
    if changed != ALLOWED_CHANGES:
        _fail("pre-import post-release delta differs")
    remote = _git_text(("remote", "get-url", "origin"))
    if remote.rstrip("/").removesuffix(".git") != (
        "https://github.com/ALLPROTO/core-lm-cross-model-lab"
    ):
        _fail("pre-import repository origin differs")
    _verify_live_tracked_files()


def _require_empty_external_pycache_prefix() -> None:
    """Reject source-adjacent ignored bytecode before importing lab code."""

    raw = sys.pycache_prefix
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise SystemExit(
            "POST-RELEASE REGRESSION FAIL: launch with an explicit empty "
            "-X pycache_prefix outside the repository"
        )
    candidate = Path(raw)
    if (
        not candidate.is_absolute()
        or str(candidate) != raw
        or candidate == PROJECT_ROOT
        or PROJECT_ROOT in candidate.parents
        or candidate.is_symlink()
        or not candidate.is_dir()
    ):
        raise SystemExit(
            "POST-RELEASE REGRESSION FAIL: pycache prefix is not a safe "
            "external directory"
        )
    try:
        if any(candidate.iterdir()):
            raise SystemExit(
                "POST-RELEASE REGRESSION FAIL: pycache prefix is not empty"
            )
    except OSError as error:
        raise SystemExit(
            "POST-RELEASE REGRESSION FAIL: pycache prefix cannot be inspected"
        ) from error


_require_empty_external_pycache_prefix()
_preimport_source_gate()
if __name__ == "__main__" and sys.argv[1:] == ["--verify-source-only"]:
    print("POST-RELEASE REGRESSION SOURCE GATE PASS")
    raise SystemExit(0)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v4.run_real_e2e_control import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(post_release_regression=True))
