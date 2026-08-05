#!/usr/bin/env python3
"""Fail closed when the worktree or reachable Git history contains a secret.

The scanner intentionally uses only the Python standard library and Git.  It
looks for high-confidence private-key and service-token shapes, never prints a
matched value, and treats an unreadable Git object as a verification failure.
Public SSH keys and ``allowed_signers`` files do not match these patterns.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO


ROOT = Path(__file__).resolve().parents[1]
MAX_SCANNED_BYTES = 8 * 1024 * 1024
MAX_GIT_LIST_BYTES = 64 * 1024 * 1024
MAX_REPORTED_FINDINGS = 100
HEX_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}\Z")


class RepositoryScanError(RuntimeError):
    """Raised when the repository cannot be inspected completely."""


def secret_patterns() -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    """Return deliberately high-confidence secret patterns.

    Prefixes are split across byte literals so this source and its unit tests
    cannot become their own positive fixtures.
    """

    return (
        (
            "private key",
            re.compile(
                rb"(?:-{5}BEGIN "
                + rb"(?:[A-Z0-9 ]+ )?PRIVATE KEY-{5}|"
                + rb"-{5}BEGIN PGP PRIVATE KEY BLOCK-{5}|"
                + rb"AGE-SECRET-KEY-1[0-9A-Z]{20,})"
            ),
        ),
        (
            "GitHub token",
            re.compile(
                rb"(?:gh"
                + rb"[pousr]_[A-Za-z0-9]{30,}|github"
                + rb"_pat_[A-Za-z0-9_]{30,})"
            ),
        ),
        (
            "AWS access key",
            re.compile(rb"(?:AK" + rb"IA|AS" + rb"IA)[A-Z0-9]{16}"),
        ),
        (
            "OpenAI key",
            re.compile(rb"s" + rb"k-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
        ),
        (
            "Hugging Face token",
            re.compile(rb"h" + rb"f_[A-Za-z0-9]{30,}"),
        ),
        (
            "Slack token",
            re.compile(rb"xox" + rb"[baprs]-[A-Za-z0-9-]{20,}"),
        ),
        (
            "Google API key",
            re.compile(rb"AI" + rb"za[0-9A-Za-z_-]{30,}"),
        ),
    )


def matching_secret(data: bytes) -> str | None:
    """Return only the secret class, never the matched bytes."""

    for label, pattern in secret_patterns():
        if pattern.search(data):
            return label
    return None


def _closed_git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    return environment


def _path_label(value: str | bytes) -> str:
    raw = (
        value.encode("utf-8", errors="surrogateescape")
        if isinstance(value, str)
        else value
    )
    return "path-sha256:" + hashlib.sha256(raw).hexdigest()


def _run_git_bounded(
    repository: Path,
    *arguments: str,
    return_one_is_empty: bool = False,
) -> bytes:
    try:
        process = subprocess.Popen(
            ("git", *arguments),
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_closed_git_environment(),
        )
    except OSError as error:
        raise RepositoryScanError("Git inspection could not start") from error
    if process.stdout is None:
        process.kill()
        process.wait()
        raise RepositoryScanError("Git inspection output is unavailable")
    try:
        output = process.stdout.read(MAX_GIT_LIST_BYTES + 1)
        if len(output) > MAX_GIT_LIST_BYTES:
            process.kill()
            process.wait()
            raise RepositoryScanError("Git inspection output exceeds the scan bound")
        return_code = process.wait()
    except OSError as error:
        process.kill()
        process.wait()
        raise RepositoryScanError("Git inspection failed closed") from error
    finally:
        process.stdout.close()
    if return_one_is_empty and return_code == 1:
        return b""
    if return_code != 0:
        raise RepositoryScanError(
            f"Git inspection failed closed with exit {return_code}"
        )
    return output


def _git(repository: Path, *arguments: str) -> bytes:
    return _run_git_bounded(repository, *arguments)


def _git_optional(repository: Path, *arguments: str) -> bytes:
    return _run_git_bounded(
        repository,
        *arguments,
        return_one_is_empty=True,
    )


def _canonical_root(repository: Path) -> Path:
    try:
        requested = repository.resolve(strict=True)
        raw = _git(requested, "rev-parse", "--show-toplevel")
        text = raw.decode("utf-8", errors="strict").strip()
        root = Path(text).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise RepositoryScanError("repository root is unavailable") from error
    if requested != root:
        raise RepositoryScanError("scan root must be the Git top level")
    return root


def _record_finding(findings: list[str], finding: str) -> None:
    if len(findings) < MAX_REPORTED_FINDINGS:
        findings.append(finding)
    elif len(findings) == MAX_REPORTED_FINDINGS:
        findings.append("additional findings omitted after deterministic report cap")


def _gitlink_paths(root: Path) -> set[bytes]:
    raw = _git(root, "ls-files", "--stage", "-z")
    paths: set[bytes] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, separator, path = record.partition(b"\t")
        fields = header.split()
        if not separator or len(fields) != 3:
            raise RepositoryScanError("Git index record is malformed")
        if fields[0] == b"160000":
            paths.add(path)
    return paths


def verify_complete_repository(root: Path) -> None:
    try:
        shallow = _git(root, "rev-parse", "--is-shallow-repository").decode(
            "ascii", errors="strict"
        ).strip()
    except UnicodeDecodeError as error:
        raise RepositoryScanError("shallow-clone status is not ASCII") from error
    if shallow != "false":
        raise RepositoryScanError("shallow repository history is incomplete")
    partial_clone = _git_optional(
        root, "config", "--local", "--get", "extensions.partialClone"
    ).strip()
    promisor = _git_optional(
        root, "config", "--local", "--get-regexp", r"^remote\..*\.promisor$"
    ).strip()
    filters = _git_optional(
        root,
        "config",
        "--local",
        "--get-regexp",
        r"^remote\..*\.partialclonefilter$",
    ).strip()
    if partial_clone or promisor or filters:
        raise RepositoryScanError("partial/promisor repository history is incomplete")
    if _git(root, "for-each-ref", "--format=%(refname)", "refs/replace"):
        raise RepositoryScanError("Git replacement refs are forbidden")
    try:
        raw_graft_path = _git(
            root,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/grafts",
        )
        graft_path = Path(
            raw_graft_path.decode("utf-8", errors="strict").strip()
        )
    except UnicodeDecodeError as error:
        raise RepositoryScanError("Git graft path is not UTF-8") from error
    if graft_path.exists() or graft_path.is_symlink():
        raise RepositoryScanError("Git grafts are forbidden")


def scan_ref_names(root: Path) -> list[str]:
    """Scan local ref names without ever printing a raw ref."""

    raw = _git(root, "for-each-ref", "--format=%(refname)")
    findings: list[str] = []
    for ref in raw.splitlines():
        label = matching_secret(ref)
        if label is not None:
            _record_finding(findings, f"ref:{_path_label(ref)}: possible {label}")
    return findings


def _read_worktree_path(root: Path, relative: str) -> bytes:
    path = root / relative
    display = _path_label(relative)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RepositoryScanError(f"cannot inspect worktree path {display}") from error
    if stat.S_ISLNK(metadata.st_mode):
        try:
            return os.fsencode(os.readlink(path))
        except OSError as error:
            raise RepositoryScanError(
                f"cannot inspect worktree symlink {display}"
            ) from error
    if not stat.S_ISREG(metadata.st_mode):
        raise RepositoryScanError(f"worktree path is not a regular file: {display}")
    if metadata.st_size > MAX_SCANNED_BYTES:
        raise RepositoryScanError(
            f"worktree file exceeds {MAX_SCANNED_BYTES} byte scan bound: {display}"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RepositoryScanError(f"cannot open worktree file {display}") from error
    try:
        before = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_SCANNED_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_SCANNED_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise RepositoryScanError(f"cannot read worktree file {display}") from error
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise RepositoryScanError(f"worktree file changed while scanned: {display}")
    return bytes(data)


def scan_worktree(root: Path) -> list[str]:
    """Scan tracked and non-ignored untracked files without following links."""

    gitlinks = _gitlink_paths(root)
    if gitlinks:
        raise RepositoryScanError("Git submodules are unsupported by this scan policy")
    raw = _git(root, "ls-files", "-co", "--exclude-standard", "-z")
    findings: list[str] = []
    for relative_raw in raw.split(b"\0"):
        if not relative_raw:
            continue
        relative = os.fsdecode(relative_raw)
        path_label = matching_secret(relative_raw)
        if path_label is not None:
            _record_finding(
                findings,
                f"worktree-name:{_path_label(relative_raw)}: possible {path_label}"
            )
        label = matching_secret(_read_worktree_path(root, relative))
        if label is not None:
            _record_finding(
                findings,
                f"worktree:{_path_label(relative_raw)}: possible {label}"
            )
    return findings


class GitObjectReader:
    """Inspect and read objects without ever requesting a tree payload."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.process: subprocess.Popen[bytes] | None = None
        self.info_process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "GitObjectReader":
        try:
            self.info_process = subprocess.Popen(
                ("git", "cat-file", "--batch-check"),
                cwd=self.root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_closed_git_environment(),
            )
            self.process = subprocess.Popen(
                ("git", "cat-file", "--batch"),
                cwd=self.root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_closed_git_environment(),
            )
        except OSError as error:
            if self.info_process is not None:
                self.info_process.kill()
                self.info_process.wait()
            raise RepositoryScanError("Git object reader could not start") from error
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        failure: RepositoryScanError | None = None
        for process in (self.info_process, self.process):
            if process is None:
                continue
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                try:
                    return_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    failure = RepositoryScanError(
                        "Git object reader did not terminate"
                    )
                    continue
                if return_code != 0:
                    failure = RepositoryScanError("Git object reader failed closed")
            finally:
                if process.stdout is not None:
                    process.stdout.close()
        if failure is not None and exc_type is None:
            raise failure

    @staticmethod
    def _read_exact(stream: BinaryIO, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = stream.read(size - len(data))
            if not chunk:
                raise RepositoryScanError("Git object stream ended early")
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _request_header(
        process: subprocess.Popen[bytes], object_id: str
    ) -> tuple[str, int]:
        if process is None or process.stdin is None or process.stdout is None:
            raise RepositoryScanError("Git object reader is unavailable")
        try:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(256)
        except (BrokenPipeError, OSError, UnicodeEncodeError) as error:
            raise RepositoryScanError("Git object reader failed closed") from error
        fields = header.rstrip(b"\n").split()
        if (
            len(fields) != 3
            or fields[0].decode("ascii", errors="ignore") != object_id
            or fields[1] not in {b"blob", b"commit", b"tag", b"tree"}
        ):
            raise RepositoryScanError("Git object header is invalid")
        try:
            size = int(fields[2], 10)
            object_type = fields[1].decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as error:
            raise RepositoryScanError("Git object header is invalid") from error
        if size < 0:
            raise RepositoryScanError("Git object size is invalid")
        if object_type in {"blob", "commit", "tag"} and size > MAX_SCANNED_BYTES:
            raise RepositoryScanError(
                f"reachable Git {object_type} exceeds the {MAX_SCANNED_BYTES} "
                "byte scan bound"
            )
        return object_type, size

    def info(self, object_id: str) -> tuple[str, int]:
        process = self.info_process
        if process is None:
            raise RepositoryScanError("Git object metadata reader is unavailable")
        return self._request_header(process, object_id)

    def read(self, object_id: str) -> tuple[str, bytes]:
        object_type, size = self.info(object_id)
        if object_type == "tree":
            return object_type, b""
        if size > MAX_SCANNED_BYTES:
            raise RepositoryScanError(
                f"reachable Git {object_type} exceeds the {MAX_SCANNED_BYTES} "
                "byte scan bound"
            )
        process = self.process
        if process is None or process.stdout is None:
            raise RepositoryScanError("Git object reader is unavailable")
        content_type, content_size = self._request_header(process, object_id)
        if content_type != object_type or content_size != size:
            raise RepositoryScanError("Git object metadata changed while scanned")
        payload = self._read_exact(process.stdout, size)
        if self._read_exact(process.stdout, 1) != b"\n":
            raise RepositoryScanError("Git object batch framing is invalid")
        return object_type, payload


def scan_index(root: Path) -> list[str]:
    """Scan staged blobs, including values overwritten in the worktree."""

    raw = _git(root, "ls-files", "--stage", "-z")
    findings: list[str] = []
    inspected: set[str] = set()
    with GitObjectReader(root) as reader:
        for record in raw.split(b"\0"):
            if not record:
                continue
            header, separator, path = record.partition(b"\t")
            fields = header.split()
            if not separator or len(fields) != 3:
                raise RepositoryScanError("Git index record is malformed")
            path_secret = matching_secret(path)
            if path_secret is not None:
                _record_finding(
                    findings,
                    f"index-name:{_path_label(path)}: possible {path_secret}"
                )
            if fields[0] == b"160000":
                raise RepositoryScanError(
                    "Git submodules are unsupported by this scan policy"
                )
            try:
                object_id = fields[1].decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise RepositoryScanError(
                    "Git index object ID is not ASCII"
                ) from error
            if HEX_OBJECT_ID.fullmatch(object_id) is None:
                raise RepositoryScanError("Git index object ID is malformed")
            if object_id in inspected:
                continue
            inspected.add(object_id)
            object_type, data = reader.read(object_id)
            if object_type != "blob":
                raise RepositoryScanError(
                    "Git index entry does not reference a blob"
                )
            label = matching_secret(data)
            if label is not None:
                _record_finding(
                    findings,
                    f"index:{_path_label(path)}: possible {label}"
                )
    return findings


def scan_reachable_history(root: Path) -> list[str]:
    """Scan reachable blobs plus commit and annotated-tag messages."""

    # ``HEAD`` is explicit because pull-request checkout commonly leaves it
    # detached and therefore outside the refs expanded by ``--all``.
    raw = _git(root, "rev-list", "--objects", "--all", "HEAD")
    findings: list[str] = []
    inspected: set[str] = set()
    with GitObjectReader(root) as reader:
        for entry in raw.splitlines():
            if not entry:
                continue
            object_id_raw, separator, path = entry.partition(b" ")
            try:
                object_id = object_id_raw.decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise RepositoryScanError(
                    "reachable Git object ID is not ASCII"
                ) from error
            if HEX_OBJECT_ID.fullmatch(object_id) is None:
                raise RepositoryScanError("reachable Git object ID is malformed")
            if separator:
                path_secret = matching_secret(path)
                if path_secret is not None:
                    _record_finding(
                        findings,
                        f"history-name:{_path_label(path)}: possible {path_secret}"
                    )
            if object_id in inspected:
                continue
            inspected.add(object_id)
            object_type, data = reader.read(object_id)
            if object_type not in {"blob", "commit", "tag"}:
                continue
            label = matching_secret(data)
            if label is not None:
                location = (
                    _path_label(path)
                    if object_type == "blob" and separator
                    else object_type
                )
                _record_finding(
                    findings,
                    f"history:{object_id} ({location}): possible {label}"
                )
    return findings


def scan_repository(repository: Path = ROOT) -> list[str]:
    root = _canonical_root(repository)
    verify_complete_repository(root)
    findings = [
        *scan_ref_names(root),
        *scan_worktree(root),
        *scan_index(root),
        *scan_reachable_history(root),
    ]
    if len(findings) > MAX_REPORTED_FINDINGS:
        return findings[:MAX_REPORTED_FINDINGS] + [
            "additional findings omitted after deterministic report cap"
        ]
    return findings


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        findings = scan_repository(arguments.repository)
    except RepositoryScanError as error:
        print(f"REPOSITORY SECRET SCAN FAIL: {error}", file=sys.stderr)
        return 2
    except OSError:
        print(
            "REPOSITORY SECRET SCAN FAIL: operating-system inspection failed closed",
            file=sys.stderr,
        )
        return 2
    if findings:
        print("REPOSITORY SECRET SCAN FAIL", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print(
        "REPOSITORY SECRET SCAN PASS: worktree, index, refs, and all "
        "locally reachable objects"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
