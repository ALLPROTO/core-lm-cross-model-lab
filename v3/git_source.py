#!/usr/bin/env python3
"""Seal source bytes from Git objects and verify an exported source tree.

The sealing side reads only Git objects.  It never reads tracked bytes from the
working tree.  The verification side deliberately has no Git dependency: the
exact commit object is carried in the manifest, every blob is re-hashed using
Git's object framing, and the complete root tree object is reconstructed from
the copied regular files.

Only the portable source subset used by the experiment is accepted:
``100644`` and ``100755`` blobs beneath ``40000`` trees.  Symbolic links,
submodules, non-UTF-8 names, case-folding collisions, and unsafe path
components are rejected before any bytes are exported.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import re
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, NamedTuple, Sequence


SCHEMA_VERSION = "corelm-git-source-manifest-v1"
OBJECT_FORMAT = "sha1"
GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REGULAR_MODES = frozenset(("100644", "100755"))
TREE_MODE = "40000"
SYMLINK_MODE = "120000"
SUBMODULE_MODE = "160000"
READ_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAXIMUM_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_MAXIMUM_TOTAL_BYTES = 1024 * 1024 * 1024
DEFAULT_MAXIMUM_FILE_COUNT = 100_000
MAXIMUM_METADATA_OBJECT_BYTES = 64 * 1024 * 1024


class GitSourceError(ValueError):
    """The requested Git identity or exported source tree is not exact."""


class GitSourceFile(NamedTuple):
    """One exact tracked file, iterable as path/mode/bytes/blob OID."""

    path: str
    mode: str
    data: bytes
    blob_oid: str


@dataclass(frozen=True)
class GitSourceSeal:
    commit: str
    tree: str
    commit_object: bytes
    files: tuple[GitSourceFile, ...]

    def __iter__(self) -> Iterator[GitSourceFile]:
        return iter(self.files)


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    name_bytes: bytes
    name: str
    oid: str

    @property
    def is_tree(self) -> bool:
        return self.mode == TREE_MODE


def _sha1(value: bytes) -> str:
    try:
        digest = hashlib.sha1(value, usedforsecurity=False)
    except TypeError:  # pragma: no cover - compatibility with older Python
        digest = hashlib.sha1(value)
    return digest.hexdigest()


def git_object_oid(object_type: str, payload: bytes) -> str:
    if object_type not in {"blob", "tree", "commit"}:
        raise GitSourceError(f"unsupported Git object type: {object_type!r}")
    framed = object_type.encode("ascii") + b" " + str(len(payload)).encode("ascii")
    return _sha1(framed + b"\0" + payload)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise GitSourceError("source manifest is not canonical JSON data") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _full_oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID.fullmatch(value) is None:
        raise GitSourceError(f"{label} must be a full lowercase SHA-1 Git OID")
    return value


def _positive_bound(value: int, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise GitSourceError(f"{label} must be a positive integer")
    return value


def _repository_path(repository: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(repository)))
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        raise GitSourceError(f"Git repository is unavailable: {absolute}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise GitSourceError(f"Git repository must be a non-symlink directory: {absolute}")
    return absolute


def _git(repository: Path, arguments: Sequence[str]) -> bytes:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        if len(detail) > 1000:
            detail = detail[:1000] + "..."
        raise GitSourceError(
            f"git {' '.join(arguments[:2])} failed"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout


def _read_git_object(
    repository: Path,
    oid: str,
    expected_type: str,
    *,
    maximum_bytes: int,
) -> bytes:
    observed_type = _git(repository, ["cat-file", "-t", oid])
    if observed_type != expected_type.encode("ascii") + b"\n":
        raise GitSourceError(f"Git object {oid} is not a {expected_type}")
    raw_size = _git(repository, ["cat-file", "-s", oid])
    try:
        size = int(raw_size.rstrip(b"\n"))
    except ValueError as error:
        raise GitSourceError(f"Git object {oid} has an invalid size") from error
    if size < 0 or size > maximum_bytes:
        raise GitSourceError(f"Git object {oid} exceeds the fixed byte bound")
    payload = _git(repository, ["cat-file", expected_type, oid])
    if len(payload) != size:
        raise GitSourceError(f"Git object {oid} changed while it was read")
    if git_object_oid(expected_type, payload) != oid:
        raise GitSourceError(f"Git object hash mismatch: {oid}")
    return payload


def _commit_tree(commit_object: bytes) -> str:
    header, separator, _message = commit_object.partition(b"\n\n")
    if not separator or b"\0" in header:
        raise GitSourceError("Git commit object has malformed headers")
    lines = header.split(b"\n")
    tree_headers = [line for line in lines if line.startswith(b"tree ")]
    if not lines or lines[0] not in tree_headers or len(tree_headers) != 1:
        raise GitSourceError("Git commit must have exactly one leading tree header")
    raw_oid = tree_headers[0][5:]
    try:
        oid = raw_oid.decode("ascii")
    except UnicodeDecodeError as error:
        raise GitSourceError("Git commit tree OID is not ASCII") from error
    return _full_oid(oid, label="commit tree")


def _validate_component_bytes(value: bytes) -> str:
    if not value or value in {b".", b".."}:
        raise GitSourceError("Git tree contains an unsafe dot path component")
    if b"/" in value or b"\\" in value or b"\0" in value:
        raise GitSourceError("Git tree contains an unsafe path separator")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise GitSourceError("Git path is not strict UTF-8") from error
    if unicodedata.normalize("NFC", text) != text:
        raise GitSourceError("Git path is not NFC-normalized")
    if text.casefold() == ".git":
        raise GitSourceError("Git metadata path component is forbidden")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise GitSourceError("Git path contains a control character")
    return text


def _validate_component_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise GitSourceError("source manifest path component must be a string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise GitSourceError("source manifest path is not strict UTF-8") from error
    if _validate_component_bytes(encoded) != value:
        raise GitSourceError("source manifest path is not canonical UTF-8")
    return encoded


def _path_parts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise GitSourceError("source path must be a non-empty relative POSIX path")
    if "\\" in value:
        raise GitSourceError("source path contains a backslash")
    parts = tuple(value.split("/"))
    for component in parts:
        _validate_component_text(component)
    if "/".join(parts) != value:
        raise GitSourceError("source path is not normalized")
    return parts


def _tree_entry_compare(left: _TreeEntry, right: _TreeEntry) -> int:
    common = min(len(left.name_bytes), len(right.name_bytes))
    prefix_left = left.name_bytes[:common]
    prefix_right = right.name_bytes[:common]
    if prefix_left != prefix_right:
        return -1 if prefix_left < prefix_right else 1
    left_next = (
        left.name_bytes[common]
        if len(left.name_bytes) > common
        else (ord("/") if left.is_tree else 0)
    )
    right_next = (
        right.name_bytes[common]
        if len(right.name_bytes) > common
        else (ord("/") if right.is_tree else 0)
    )
    return (left_next > right_next) - (left_next < right_next)


def _parse_tree_object(payload: bytes) -> tuple[_TreeEntry, ...]:
    entries: list[_TreeEntry] = []
    position = 0
    while position < len(payload):
        space = payload.find(b" ", position)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        if space <= position or nul < 0 or nul + 21 > len(payload):
            raise GitSourceError("Git tree object has malformed framing")
        raw_mode = payload[position:space]
        raw_name = payload[space + 1 : nul]
        raw_oid = payload[nul + 1 : nul + 21]
        position = nul + 21
        try:
            mode = raw_mode.decode("ascii")
        except UnicodeDecodeError as error:
            raise GitSourceError("Git tree mode is not ASCII") from error
        if mode == SYMLINK_MODE:
            raise GitSourceError("symbolic links are forbidden in sealed source")
        if mode == SUBMODULE_MODE:
            raise GitSourceError("submodules are forbidden in sealed source")
        if mode not in REGULAR_MODES and mode != TREE_MODE:
            raise GitSourceError(f"non-canonical Git tree mode is forbidden: {mode!r}")
        name = _validate_component_bytes(raw_name)
        entries.append(_TreeEntry(mode, raw_name, name, raw_oid.hex()))
    if position != len(payload):
        raise GitSourceError("Git tree object has trailing bytes")
    if entries != sorted(entries, key=functools.cmp_to_key(_tree_entry_compare)):
        raise GitSourceError("Git tree entries are not in canonical Git order")
    names: set[bytes] = set()
    portable_names: dict[str, str] = {}
    for entry in entries:
        if entry.name_bytes in names:
            raise GitSourceError("Git tree contains a duplicate entry name")
        names.add(entry.name_bytes)
        folded = entry.name.casefold()
        previous = portable_names.get(folded)
        if previous is not None and previous != entry.name:
            raise GitSourceError("Git tree has a case-folding path collision")
        portable_names[folded] = entry.name
    return tuple(entries)


def _parse_ls_tree(payload: bytes) -> dict[bytes, tuple[str, str, str]]:
    result: dict[bytes, tuple[str, str, str]] = {}
    if payload and not payload.endswith(b"\0"):
        raise GitSourceError("git ls-tree returned a truncated record")
    for record in payload.split(b"\0")[:-1]:
        metadata, tab, path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not tab or len(fields) != 3 or not path:
            raise GitSourceError("git ls-tree returned a malformed record")
        try:
            mode, object_type, oid = (field.decode("ascii") for field in fields)
        except UnicodeDecodeError as error:
            raise GitSourceError("git ls-tree metadata is not ASCII") from error
        components = path.split(b"/")
        for component in components:
            _validate_component_bytes(component)
        if path in result:
            raise GitSourceError("git ls-tree returned a duplicate path")
        result[path] = (mode, object_type, oid)
    return result


def seal_git_source(
    repository: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
) -> GitSourceSeal:
    """Read and verify all regular files reachable from an exact Git commit."""

    repository = _repository_path(repository)
    commit = _full_oid(expected_commit, label="expected commit")
    tree = _full_oid(expected_tree, label="expected tree")
    maximum_file_bytes = _positive_bound(maximum_file_bytes, label="file byte bound")
    maximum_total_bytes = _positive_bound(maximum_total_bytes, label="total byte bound")
    maximum_file_count = _positive_bound(maximum_file_count, label="file count bound")

    commit_object = _read_git_object(
        repository,
        commit,
        "commit",
        maximum_bytes=MAXIMUM_METADATA_OBJECT_BYTES,
    )
    if _commit_tree(commit_object) != tree:
        raise GitSourceError("expected commit does not point to the expected tree")

    files: list[GitSourceFile] = []
    total_bytes = 0
    active_trees: set[str] = set()

    def visit(tree_oid: str, prefix: tuple[str, ...]) -> None:
        nonlocal total_bytes
        if tree_oid in active_trees:
            raise GitSourceError("Git tree graph contains a cycle")
        active_trees.add(tree_oid)
        try:
            tree_object = _read_git_object(
                repository,
                tree_oid,
                "tree",
                maximum_bytes=MAXIMUM_METADATA_OBJECT_BYTES,
            )
            for entry in _parse_tree_object(tree_object):
                components = (*prefix, entry.name)
                if entry.is_tree:
                    visit(entry.oid, components)
                    continue
                if len(files) >= maximum_file_count:
                    raise GitSourceError("Git source exceeds the fixed file count bound")
                blob = _read_git_object(
                    repository,
                    entry.oid,
                    "blob",
                    maximum_bytes=maximum_file_bytes,
                )
                total_bytes += len(blob)
                if total_bytes > maximum_total_bytes:
                    raise GitSourceError("Git source exceeds the fixed total byte bound")
                files.append(
                    GitSourceFile("/".join(components), entry.mode, blob, entry.oid)
                )
        finally:
            active_trees.remove(tree_oid)

    visit(tree, ())

    by_portable_path: dict[str, str] = {}
    for entry in files:
        folded = entry.path.casefold()
        previous = by_portable_path.get(folded)
        if previous is not None and previous != entry.path:
            raise GitSourceError("Git source has a case-folding path collision")
        by_portable_path[folded] = entry.path

    listed = _parse_ls_tree(
        _git(repository, ["ls-tree", "-r", "-z", "--full-tree", tree])
    )
    parsed = {
        entry.path.encode("utf-8"): (entry.mode, "blob", entry.blob_oid)
        for entry in files
    }
    if listed != parsed:
        raise GitSourceError("raw Git tree traversal disagrees with git ls-tree")

    files.sort(key=lambda entry: entry.path.encode("utf-8"))
    return GitSourceSeal(commit, tree, commit_object, tuple(files))


def iter_commit_files(
    repository: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
) -> Iterator[GitSourceFile]:
    """Yield ``(path, mode, bytes, blob_oid)`` records from Git objects."""

    yield from seal_git_source(
        repository,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        maximum_file_bytes=maximum_file_bytes,
        maximum_total_bytes=maximum_total_bytes,
        maximum_file_count=maximum_file_count,
    ).files


def build_source_manifest(seal: GitSourceSeal) -> dict[str, Any]:
    """Build the self-digested canonical manifest for an exported source tree."""

    if not isinstance(seal, GitSourceSeal):
        raise GitSourceError("GitSourceSeal required")
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "objectFormat": OBJECT_FORMAT,
        "commit": seal.commit,
        "tree": seal.tree,
        "commitObject": {
            "encoding": "base64",
            "bytes": len(seal.commit_object),
            "oid": seal.commit,
            "dataBase64": base64.b64encode(seal.commit_object).decode("ascii"),
        },
        "files": [
            {
                "path": entry.path,
                "mode": entry.mode,
                "bytes": len(entry.data),
                "sha256": _sha256(entry.data),
                "blobOID": entry.blob_oid,
            }
            for entry in seal.files
        ],
    }
    payload["contentSHA256"] = _sha256(canonical_json_bytes(payload))
    _validate_source_manifest(payload, expected_commit=seal.commit, expected_tree=seal.tree)
    return payload


def source_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Serialize an already validated manifest with one terminal LF."""

    normalized = _validate_source_manifest(
        manifest,
        expected_commit=manifest.get("commit"),
        expected_tree=manifest.get("tree"),
    )
    return canonical_json_bytes(normalized) + b"\n"


def load_source_manifest_bytes(raw: bytes) -> dict[str, Any]:
    """Load a byte-for-byte canonical source manifest, rejecting duplicates."""

    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise GitSourceError("source manifest must end in exactly one LF")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GitSourceError(f"duplicate source manifest key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitSourceError("source manifest is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise GitSourceError("source manifest root must be an object")
    normalized = _validate_source_manifest(
        value,
        expected_commit=value.get("commit"),
        expected_tree=value.get("tree"),
    )
    if raw != canonical_json_bytes(normalized) + b"\n":
        raise GitSourceError("source manifest bytes are not canonical")
    return normalized


def _required_mapping(value: Any, fields: set[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GitSourceError(f"{label} fields differ from the canonical contract")
    return value


def _portable_collision_check(paths: Sequence[tuple[str, ...]]) -> None:
    children: dict[tuple[str, ...], dict[str, str]] = {}
    for parts in paths:
        for index, component in enumerate(parts):
            parent = parts[:index]
            names = children.setdefault(parent, {})
            folded = component.casefold()
            previous = names.get(folded)
            if previous is not None and previous != component:
                raise GitSourceError("source manifest has a case-folding path collision")
            names[folded] = component


def _reconstruct_tree(entries: Sequence[Mapping[str, Any]]) -> str:
    root: dict[str, Any] = {}
    paths: list[tuple[str, ...]] = []
    for entry in entries:
        parts = _path_parts(entry["path"])
        paths.append(parts)
        node = root
        for component in parts[:-1]:
            present = node.get(component)
            if present is None:
                present = {}
                node[component] = present
            if not isinstance(present, dict):
                raise GitSourceError("source manifest has a file/directory prefix collision")
            node = present
        leaf = parts[-1]
        if leaf in node:
            raise GitSourceError("source manifest contains a duplicate path")
        node[leaf] = (entry["mode"], entry["blobOID"])
    _portable_collision_check(paths)

    def encode_tree(node: dict[str, Any]) -> str:
        direct: list[_TreeEntry] = []
        for name, value in node.items():
            raw_name = _validate_component_text(name)
            if isinstance(value, dict):
                oid = encode_tree(value)
                mode = TREE_MODE
            else:
                mode, oid = value
            direct.append(_TreeEntry(mode, raw_name, name, oid))
        direct.sort(key=functools.cmp_to_key(_tree_entry_compare))
        payload = b"".join(
            entry.mode.encode("ascii")
            + b" "
            + entry.name_bytes
            + b"\0"
            + bytes.fromhex(entry.oid)
            for entry in direct
        )
        return git_object_oid("tree", payload)

    return encode_tree(root)


def _validate_source_manifest(
    manifest: Mapping[str, Any], *, expected_commit: Any, expected_tree: Any
) -> dict[str, Any]:
    root = _required_mapping(
        manifest,
        {
            "schemaVersion",
            "objectFormat",
            "commit",
            "tree",
            "commitObject",
            "files",
            "contentSHA256",
        },
        label="source manifest",
    )
    if root["schemaVersion"] != SCHEMA_VERSION or root["objectFormat"] != OBJECT_FORMAT:
        raise GitSourceError("source manifest schema or object format differs")
    commit = _full_oid(root["commit"], label="manifest commit")
    tree = _full_oid(root["tree"], label="manifest tree")
    if commit != _full_oid(expected_commit, label="expected commit"):
        raise GitSourceError("source manifest commit differs from the expected commit")
    if tree != _full_oid(expected_tree, label="expected tree"):
        raise GitSourceError("source manifest tree differs from the expected tree")
    content_digest = root["contentSHA256"]
    if not isinstance(content_digest, str) or SHA256.fullmatch(content_digest) is None:
        raise GitSourceError("source manifest self-digest is invalid")
    unsigned = dict(root)
    del unsigned["contentSHA256"]
    if _sha256(canonical_json_bytes(unsigned)) != content_digest:
        raise GitSourceError("source manifest self-digest mismatch")

    commit_record = _required_mapping(
        root["commitObject"],
        {"encoding", "bytes", "oid", "dataBase64"},
        label="commit object",
    )
    if commit_record["encoding"] != "base64" or commit_record["oid"] != commit:
        raise GitSourceError("commit object identity differs")
    if type(commit_record["bytes"]) is not int or commit_record["bytes"] < 0:
        raise GitSourceError("commit object byte count is invalid")
    if not isinstance(commit_record["dataBase64"], str):
        raise GitSourceError("commit object base64 payload is invalid")
    try:
        commit_object = base64.b64decode(
            commit_record["dataBase64"].encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise GitSourceError("commit object base64 payload is invalid") from error
    if len(commit_object) != commit_record["bytes"]:
        raise GitSourceError("commit object byte count differs")
    if git_object_oid("commit", commit_object) != commit:
        raise GitSourceError("commit object hash differs")
    if _commit_tree(commit_object) != tree:
        raise GitSourceError("commit object does not bind the declared tree")

    raw_files = root["files"]
    if not isinstance(raw_files, list):
        raise GitSourceError("source manifest files must be an array")
    normalized_files: list[Mapping[str, Any]] = []
    previous_path: bytes | None = None
    for index, raw_entry in enumerate(raw_files):
        entry = _required_mapping(
            raw_entry,
            {"path", "mode", "bytes", "sha256", "blobOID"},
            label=f"source file {index}",
        )
        parts = _path_parts(entry["path"])
        encoded_path = "/".join(parts).encode("utf-8")
        if previous_path is not None and encoded_path <= previous_path:
            raise GitSourceError("source manifest files are not uniquely byte-sorted")
        previous_path = encoded_path
        if entry["mode"] not in REGULAR_MODES:
            raise GitSourceError("source manifest contains a forbidden Git mode")
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise GitSourceError("source file byte count is invalid")
        if not isinstance(entry["sha256"], str) or SHA256.fullmatch(entry["sha256"]) is None:
            raise GitSourceError("source file SHA-256 is invalid")
        _full_oid(entry["blobOID"], label="source blob OID")
        normalized_files.append(entry)
    if _reconstruct_tree(normalized_files) != tree:
        raise GitSourceError("source manifest does not reconstruct the declared Git tree")
    return dict(root)


def _scan_directory(
    descriptor: int,
    prefix: tuple[str, ...] = (),
) -> tuple[dict[str, tuple[int, int, int, int, int]], set[str]]:
    files: dict[str, tuple[int, int, int, int, int]] = {}
    directories: set[str] = set()
    try:
        names = os.listdir(descriptor)
    except OSError as error:
        raise GitSourceError("cannot inventory copied source directory") from error
    names.sort(key=lambda name: os.fsencode(name))
    for name in names:
        _validate_component_text(name)
        path_parts = (*prefix, name)
        path = "/".join(path_parts)
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise GitSourceError(f"cannot stat copied source path: {path}") from error
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            stat.S_IMODE(metadata.st_mode),
        )
        if stat.S_ISREG(metadata.st_mode):
            files[path] = identity
        elif stat.S_ISDIR(metadata.st_mode):
            directories.add(path)
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError as error:
                raise GitSourceError(f"unsafe copied source directory: {path}") from error
            try:
                child_files, child_directories = _scan_directory(child, path_parts)
            finally:
                os.close(child)
            files.update(child_files)
            directories.update(child_directories)
        elif stat.S_ISLNK(metadata.st_mode):
            raise GitSourceError(f"symbolic link in copied source: {path}")
        else:
            raise GitSourceError(f"non-regular object in copied source: {path}")
    return files, directories


def _read_exported_file(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    descriptor = os.dup(root_descriptor)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        child = os.open(parts[-1], file_flags, dir_fd=descriptor)
    except OSError as error:
        os.close(descriptor)
        raise GitSourceError(f"cannot safely open copied source file: {'/'.join(parts)}") from error
    os.close(descriptor)
    descriptor = child
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise GitSourceError(f"copied source file is invalid or too large: {'/'.join(parts)}")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise GitSourceError(f"copied source file exceeds bound: {'/'.join(parts)}")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            stat.S_IMODE(before.st_mode),
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            stat.S_IMODE(after.st_mode),
        )
        if before_identity != after_identity or observed != before.st_size:
            raise GitSourceError(f"copied source changed while reading: {'/'.join(parts)}")
        return b"".join(chunks), after_identity
    finally:
        os.close(descriptor)


def verify_copied_source(
    root: Path,
    manifest: Mapping[str, Any] | bytes,
    *,
    expected_commit: str,
    expected_tree: str,
    maximum_file_bytes: int = DEFAULT_MAXIMUM_FILE_BYTES,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
) -> tuple[GitSourceFile, ...]:
    """Verify a copied source tree without invoking Git or requiring ``.git``."""

    maximum_file_bytes = _positive_bound(maximum_file_bytes, label="file byte bound")
    maximum_total_bytes = _positive_bound(maximum_total_bytes, label="total byte bound")
    maximum_file_count = _positive_bound(maximum_file_count, label="file count bound")
    parsed = (
        load_source_manifest_bytes(manifest)
        if isinstance(manifest, bytes)
        else _validate_source_manifest(
            manifest,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
    )
    if parsed["commit"] != _full_oid(expected_commit, label="expected commit"):
        raise GitSourceError("copied source manifest commit differs")
    if parsed["tree"] != _full_oid(expected_tree, label="expected tree"):
        raise GitSourceError("copied source manifest tree differs")
    entries = parsed["files"]
    if len(entries) > maximum_file_count:
        raise GitSourceError("copied source exceeds the fixed file count bound")

    absolute = Path(os.path.abspath(os.fspath(root)))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_descriptor = os.open(absolute, flags)
    except OSError as error:
        raise GitSourceError(f"copied source root is not a safe directory: {absolute}") from error
    try:
        before_files, before_directories = _scan_directory(root_descriptor)
        expected_paths = {entry["path"] for entry in entries}
        expected_directories = {
            "/".join(parts[:index])
            for entry in entries
            for parts in [_path_parts(entry["path"])]
            for index in range(1, len(parts))
        }
        if set(before_files) != expected_paths or before_directories != expected_directories:
            raise GitSourceError("copied source inventory differs from the Git manifest")

        verified: list[GitSourceFile] = []
        total_bytes = 0
        for entry in entries:
            if entry["bytes"] > maximum_file_bytes:
                raise GitSourceError("copied source file exceeds the fixed byte bound")
            parts = _path_parts(entry["path"])
            data, identity = _read_exported_file(
                root_descriptor, parts, maximum_bytes=maximum_file_bytes
            )
            if identity != before_files[entry["path"]]:
                raise GitSourceError("copied source identity changed between inventory and read")
            executable = bool(identity[4] & 0o111)
            if executable != (entry["mode"] == "100755"):
                raise GitSourceError(f"copied source executable mode differs: {entry['path']}")
            if len(data) != entry["bytes"] or _sha256(data) != entry["sha256"]:
                raise GitSourceError(f"copied source bytes differ: {entry['path']}")
            if git_object_oid("blob", data) != entry["blobOID"]:
                raise GitSourceError(f"copied source blob OID differs: {entry['path']}")
            total_bytes += len(data)
            if total_bytes > maximum_total_bytes:
                raise GitSourceError("copied source exceeds the fixed total byte bound")
            verified.append(
                GitSourceFile(entry["path"], entry["mode"], data, entry["blobOID"])
            )
        after_files, after_directories = _scan_directory(root_descriptor)
        if after_files != before_files or after_directories != before_directories:
            raise GitSourceError("copied source tree changed during verification")
        return tuple(verified)
    finally:
        os.close(root_descriptor)


__all__ = [
    "GitSourceError",
    "GitSourceFile",
    "GitSourceSeal",
    "SCHEMA_VERSION",
    "build_source_manifest",
    "canonical_json_bytes",
    "git_object_oid",
    "iter_commit_files",
    "load_source_manifest_bytes",
    "seal_git_source",
    "source_manifest_bytes",
    "verify_copied_source",
]
