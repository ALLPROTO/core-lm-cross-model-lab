#!/usr/bin/env python3
"""Reject a persisted HF token without placing the token in argv or env."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


MAX_TOKEN_BYTES = 512
MAX_SCANNED_FILE_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"TOKEN PERSISTENCE SCAN FAIL: {message}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", type=Path, required=True)
    return parser.parse_args()


def scan_file(path: Path, token: bytes) -> None:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode):
        fail("a scanned tree contains a symlink")
    if not stat.S_ISREG(status.st_mode):
        fail("a scanned tree contains a special file")
    if status.st_size > MAX_SCANNED_FILE_BYTES:
        return
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            if token in handle.read(MAX_SCANNED_FILE_BYTES + 1):
                fail("the downloader persisted the Hugging Face token value")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def main() -> None:
    arguments = parse_arguments()
    token = sys.stdin.buffer.read(MAX_TOKEN_BYTES + 1)
    if (
        not token.startswith(b"hf_")
        or len(token) < 20
        or len(token) > MAX_TOKEN_BYTES
        or any(byte in b" \t\r\n" for byte in token)
    ):
        fail("stdin is not one exact Hugging Face token")
    for supplied_root in arguments.root:
        root = Path(os.path.abspath(supplied_root))
        if not root.is_dir() or root.is_symlink() or root != root.resolve():
            fail("a scan root is absent or unsafe")
        for directory, directory_names, file_names in os.walk(
            root, topdown=True, followlinks=False
        ):
            base = Path(directory)
            for name in directory_names:
                child_status = (base / name).lstat()
                if not stat.S_ISDIR(child_status.st_mode) or stat.S_ISLNK(
                    child_status.st_mode
                ):
                    fail("a scanned tree contains an unsafe directory")
            for name in file_names:
                scan_file(base / name, token)


if __name__ == "__main__":
    main()
