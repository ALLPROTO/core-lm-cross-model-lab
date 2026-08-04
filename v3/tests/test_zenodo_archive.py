from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping
from unittest.mock import patch

from v3.collect_github_gate_receipt import (
    HTTPSCapture as GateCapture,
    collect_github_gate_receipt_to_path,
)
from v3.github_gate_receipt import (
    API_ROLES as GATE_API_ROLES,
    AUTHOR_GITHUB_LOGIN,
    AUTHOR_NAME,
    AUTHOR_ORCID,
    AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
    AUTHOR_VERIFICATION_DECLARATION,
    AUTHOR_VERIFICATION_MODE,
    GITHUB_API_VERSION,
    REQUIRED_LINUX_JOB_NAME,
    REQUIRED_MACOS_JOB_NAME,
    REQUIRED_WORKFLOW_NAME,
    REQUIRED_WORKFLOW_PATH,
)
from v3.github_release_attestation import build_attestation_record
from v3.git_source import (
    GitSourceFile,
    GitSourceSeal,
    build_source_manifest,
    git_object_oid,
    source_manifest_bytes,
    _reconstruct_tree,
)
from v3.release_receipt import REQUIRED_ASSET_ROLES, ReleaseReceiptError
from v3.release_attestation_crypto import expected_known_answer_result
from v3.reproducibility import canonical_json_bytes, with_content_digest
from v3.tests.test_release_receipt import _fixture_crypto_record
from v3.zenodo_archive import (
    EVIDENCE_BOUNDARY,
    MANIFEST_FILE_NAME,
    HTTPSCapture,
    ZenodoArchiveError,
    build_deposit_manifest,
    build_deposit_manifest_to_path,
    build_zenodo_receipt,
    _annotated_tag_oid,
    _github_release_summary,
    _github_gate_summary,
    _verify_github_signed_tag_receipt,
    _verify_ci_payload,
    verify_zenodo_receipt,
)


DEPOSITION_ID = 31001
RECORD_ID = 31002
DOI = f"10.5281/zenodo.{RECORD_ID}"
CAPTURED = "2026-08-03T12:00:01Z"
CREATED = "2026-08-03T12:01:00Z"
REPOSITORY = "ALLPROTO/core-lm-cross-model-lab"
GATE_API_BASE = f"https://api.github.com/repos/{REPOSITORY}"
GATE_HTML_BASE = f"https://github.com/{REPOSITORY}"
GATE_PR = 19
RUN_ID = 30123456789
GATE_WORKFLOW_ID = 777001
EXPECTED_AUTHOR_VERIFICATION = {
    "mode": AUTHOR_VERIFICATION_MODE,
    "authorName": AUTHOR_NAME,
    "authorORCID": AUTHOR_ORCID,
    "authorGitHubLogin": AUTHOR_GITHUB_LOGIN,
    "independentHumanReviewRequired": False,
    "independentHumanReviewPerformed": False,
    "declaration": AUTHOR_VERIFICATION_DECLARATION,
    "claimBoundary": AUTHOR_VERIFICATION_CLAIM_BOUNDARY,
}
LAB_FILES = {
    "README.md": (0o644, b"laboratory source\n"),
    "v3/verifier.py": (0o755, b"#!/usr/bin/env python3\nprint('verified')\n"),
}


def _tree_oid(files: Mapping[str, tuple[int, bytes]]) -> str:
    return _reconstruct_tree(
        [
            {
                "path": path,
                "mode": "100755" if mode & 0o111 else "100644",
                "blobOID": git_object_oid("blob", payload),
            }
            for path, (mode, payload) in sorted(files.items())
        ]
    )


LAB_TREE = _tree_oid(LAB_FILES)
LAB_COMMIT_PAYLOAD = (
    f"tree {LAB_TREE}\n"
    "author Ivan Tyshchenko <ivan@example.invalid> 1785758400 +0000\n"
    "committer Ivan Tyshchenko <ivan@example.invalid> 1785758400 +0000\n\n"
    "Zenodo semantic fixture\n"
).encode()
LAB_COMMIT = hashlib.sha1(
    f"commit {len(LAB_COMMIT_PAYLOAD)}\0".encode() + LAB_COMMIT_PAYLOAD,
    usedforsecurity=False,
).hexdigest()


class _FixtureCryptographicVerifier:
    def verify(self, **_arguments: object) -> object:
        raise AssertionError(
            "the injected complete fixture verifier must own fixture replay"
        )


FIXTURE_CRYPTOGRAPHIC_VERIFIER = _FixtureCryptographicVerifier()


def _fixture_release_receipt_verifier(
    raw_receipt: bytes,
    asset_root: Path,
    **arguments: object,
) -> SimpleNamespace:
    """Test-only complete-verifier seam; production always uses SSH + Cosign."""

    receipt = json.loads(raw_receipt)
    if (
        arguments.get("cryptographic_attestation_verifier")
        is not FIXTURE_CRYPTOGRAPHIC_VERIFIER
    ):
        raise AssertionError("fixture cryptographic verifier was not propagated")
    expected = {
        "expected_repository": receipt["repository"]["slug"],
        "expected_kind": receipt["kind"],
        "expected_tag": receipt["tag"],
        "expected_commit": receipt["source"]["commit"],
        "expected_tree": receipt["source"]["tree"],
        "expected_deadline": receipt["release"]["deadline"],
        "expected_signature_type": receipt["signatureVerification"]["signatureType"],
        "expected_key_fingerprint": receipt["signatureVerification"]["keyFingerprint"],
        "expected_public_key_sha256": receipt["signatureVerification"]["publicKeySHA256"],
    }
    if any(arguments.get(key) != value for key, value in expected.items()):
        raise AssertionError("fixture release identity was not propagated exactly")
    root = asset_root.resolve()
    for asset in receipt["requiredAssets"]:
        payload = (root / asset["name"]).read_bytes()
        if len(payload) != asset["bytes"] or _sha256(payload) != asset["sha256"]:
            raise AssertionError("fixture release asset bytes differ")
    return SimpleNamespace(
        repository=expected["expected_repository"],
        kind=expected["expected_kind"],
        tag=expected["expected_tag"],
        commit=expected["expected_commit"],
        tree=expected["expected_tree"],
        signature_type=expected["expected_signature_type"],
        key_fingerprint=expected["expected_key_fingerprint"],
        public_key_sha256=expected["expected_public_key_sha256"],
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _md5(raw: bytes) -> str:
    return hashlib.md5(raw, usedforsecurity=False).hexdigest()


def _json_body(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _headers(body: bytes) -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "Date: Mon, 03 Aug 2026 12:00:00 GMT\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii")


def _canonical_receipt(value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("contentSHA256", None)
    unsigned["contentSHA256"] = _sha256(canonical_json_bytes(unsigned))
    return canonical_json_bytes(unsigned) + b"\n"


def _archived(raw: bytes) -> dict[str, object]:
    return {
        "encoding": "base64",
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "dataBase64": base64.b64encode(raw).decode("ascii"),
    }


def _release_attestation_output(
    *,
    repository: str,
    tag: str,
    release_subject_sha1: str,
    release_id: int,
    assets: list[dict[str, object]],
    attested_at: str,
) -> bytes:
    purl = f"pkg:github/{repository}@{tag}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"uri": purl, "digest": {"sha1": release_subject_sha1}},
            *[
                {
                    "name": item["name"],
                    "digest": {"sha256": item["sha256"]},
                }
                for item in assets
            ],
        ],
        "predicateType": "https://in-toto.io/attestation/release/v0.2",
        "predicate": {
            "databaseId": str(release_id),
            "ownerId": "12345",
            "packageId": "67890",
            "purl": purl,
            "repository": repository,
            "repositoryId": "67890",
            "tag": tag,
        },
    }
    payload = json.dumps(statement, separators=(",", ":")).encode()
    result = {
        "attestation": {
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [
                        {"sig": base64.b64encode(b"unit-signature").decode("ascii")}
                    ],
                },
                "verificationMaterial": {
                    "certificate": {
                        "rawBytes": base64.b64encode(b"unit-certificate").decode(
                            "ascii"
                        )
                    },
                    "timestampVerificationData": {
                        "rfc3161Timestamps": [
                            {
                                "signedTimestamp": base64.b64encode(
                                    b"unit-rfc3161-timestamp"
                                ).decode("ascii")
                            }
                        ]
                    },
                },
            },
            "bundle_url": "",
            "initiator": "",
        },
        "verificationResult": {
            "mediaType": (
                "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
            ),
            "signature": {
                "certificate": {
                    "certificateIssuer": "CN=Fulcio Intermediate l1,O=GitHub\\, Inc.",
                    "subjectAlternativeName": "https://dotcom.releases.github.com",
                }
            },
            "statement": statement,
            "verifiedIdentity": {
                "subjectAlternativeName": {
                    "subjectAlternativeName": "",
                    "regexp": "^https://dotcom\\.releases\\.github\\.com$",
                },
                "issuer": {"issuer": "", "regexp": ".*"},
            },
            "verifiedTimestamps": [
                {
                    "type": "TimestampAuthority",
                    "uri": "timestamp.githubapp.com",
                    "timestamp": attested_at,
                }
            ],
        },
    }
    return json.dumps(result, separators=(",", ":")).encode() + b"\n"


def _fixture_crypto_record(
    raw_output: bytes, assets: list[dict[str, object]]
) -> dict[str, object]:
    bundle = json.loads(raw_output)["attestation"]["bundle"]
    verified = min(assets, key=lambda item: str(item["name"]).encode("ascii"))
    return {
        "status": "VERIFIED",
        "method": "cosign verify-blob-attestation",
        "trustPolicy": (
            "PINNED_COSIGN_AND_GITHUB_TRUSTED_ROOT;"
            "DSSE_X509_RFC3161_AND_ASSET_DIGEST_VERIFIED;"
            "PRIVATE_INFRASTRUCTURE_WITHOUT_TLOG_OR_SCT"
        ),
        "tool": {
            "name": "cosign",
            "version": "v3.0.6",
            "platform": "darwin/arm64",
            "binaryBytes": 134320242,
            "binarySHA256": (
                "5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084"
            ),
            "distributionURL": (
                "https://github.com/sigstore/cosign/releases/download/"
                "v3.0.6/cosign-darwin-arm64"
            ),
        },
        "trustedRoot": {
            "bytes": 28886,
            "sha256": (
                "26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485"
            ),
        },
        "verifiedAsset": {
            "name": verified["name"],
            "sha256": verified["sha256"],
        },
        "bundleSHA256": _sha256(canonical_json_bytes(bundle)),
        "transcript": _archived(b"Verified OK\n"),
    }


def _tar_bytes(
    files: dict[str, tuple[int, bytes]], *, commit: str | None = None
) -> bytes:
    stream = io.BytesIO()
    headers = {"comment": commit} if commit is not None else None
    with tarfile.open(
        fileobj=stream,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers=headers,
    ) as archive:
        for name, (mode, payload) in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return stream.getvalue()


def _source_archive_bytes(
    files: dict[str, tuple[int, bytes]], *, commit_payload: bytes
) -> tuple[bytes, str, str]:
    tree = _tree_oid(files)
    commit = git_object_oid("commit", commit_payload)
    entries = tuple(
        GitSourceFile(
            path,
            "100755" if mode & 0o111 else "100644",
            payload,
            git_object_oid("blob", payload),
        )
        for path, (mode, payload) in sorted(files.items())
    )
    manifest = source_manifest_bytes(
        build_source_manifest(GitSourceSeal(commit, tree, commit_payload, entries))
    )
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
        encoding="utf-8",
        errors="strict",
    ) as archive:
        members = [("source-manifest.json", 0o644, manifest)] + [
            (f"source/{entry.path}", 0o755 if entry.mode == "100755" else 0o644, entry.data)
            for entry in entries
        ]
        for name, mode, payload in members:
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = member.linkname = ""
            member.devmajor = member.devminor = 0
            member.type = tarfile.REGTYPE
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return stream.getvalue(), commit, tree


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=(2026, 8, 3, 12, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, payload)
    return stream.getvalue()


def _gate_endpoints() -> dict[str, str]:
    return {
        "pull-request": f"{GATE_API_BASE}/pulls/{GATE_PR}",
        "workflow-run": f"{GATE_API_BASE}/actions/runs/{RUN_ID}",
        "workflow-jobs": (
            f"{GATE_API_BASE}/actions/runs/{RUN_ID}/jobs?filter=all&per_page=100&page=1"
        ),
        "workflow-artifacts": (
            f"{GATE_API_BASE}/actions/runs/{RUN_ID}/artifacts?per_page=100&page=1"
        ),
    }


def _gate_headers(second: int, role: str) -> bytes:
    observed = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=second
    )
    return (
        "HTTP/1.1 200 OK\r\n"
        f"Date: {observed.strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"X-GitHub-Api-Version-Selected: {GITHUB_API_VERSION}\r\n"
        f"X-GitHub-Request-Id: ZENODO-GATE-{role}-{second}\r\n\r\n"
    ).encode("ascii")


def _gate_bodies() -> dict[str, Any]:
    endpoints = _gate_endpoints()
    return {
        "pull-request": {
            "number": GATE_PR,
            "url": endpoints["pull-request"],
            "html_url": f"{GATE_HTML_BASE}/pull/{GATE_PR}",
            "state": "open",
            "head": {"sha": LAB_COMMIT, "repo": {"full_name": REPOSITORY}},
        },
        "workflow-run": {
            "id": RUN_ID,
            "workflow_id": GATE_WORKFLOW_ID,
            "url": endpoints["workflow-run"],
            "html_url": f"{GATE_HTML_BASE}/actions/runs/{RUN_ID}",
            "head_sha": LAB_COMMIT,
            "name": REQUIRED_WORKFLOW_NAME,
            "path": REQUIRED_WORKFLOW_PATH,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": REPOSITORY},
        },
        "workflow-jobs": {
            "total_count": 2,
            "jobs": [
                {
                    "id": 81001,
                    "run_id": RUN_ID,
                    "run_url": endpoints["workflow-run"],
                    "head_sha": LAB_COMMIT,
                    "name": REQUIRED_LINUX_JOB_NAME,
                    "status": "completed",
                    "conclusion": "success",
                    "labels": ["ubuntu-24.04"],
                },
                {
                    "id": 81002,
                    "run_id": RUN_ID,
                    "run_url": endpoints["workflow-run"],
                    "head_sha": LAB_COMMIT,
                    "name": REQUIRED_MACOS_JOB_NAME,
                    "status": "completed",
                    "conclusion": "success",
                    "labels": ["macos-15"],
                },
            ],
        },
        "workflow-artifacts": {"total_count": 0, "artifacts": []},
    }


class _GateTransport:
    def __init__(self, bodies: Mapping[str, Any]) -> None:
        self.bodies = bodies
        self.calls = 0

    def request(self, url: str, *, token: str | None = None) -> GateCapture:
        role = GATE_API_ROLES[self.calls]
        if url != _gate_endpoints()[role]:
            raise AssertionError(f"unexpected gate URL for {role}")
        second = self.calls
        self.calls += 1
        captured = datetime(2026, 8, 3, 12, 0, 1, tzinfo=timezone.utc) + timedelta(
            seconds=second
        )
        return GateCapture(
            200,
            _gate_headers(second, role),
            json.dumps(self.bodies[role], separators=(",", ":")).encode(),
            captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


def _collect_gate(root: Path, bodies: Mapping[str, Any]) -> bytes:
    output = root / "github-gate-receipt.json"
    collect_github_gate_receipt_to_path(
        output=output,
        repository=REPOSITORY,
        pull_request_number=GATE_PR,
        implementation_commit=LAB_COMMIT,
        workflow_run_id=RUN_ID,
        workflow_name=REQUIRED_WORKFLOW_NAME,
        workflow_path=REQUIRED_WORKFLOW_PATH,
        transport=_GateTransport(bodies),
        now=lambda: "2026-08-03T12:10:00Z",
    )
    raw = output.read_bytes()
    receipt = json.loads(raw)
    if receipt["authorVerification"] != EXPECTED_AUTHOR_VERIFICATION:
        raise AssertionError("gate fixture author self-verification differs")
    responses = receipt["githubAPIResponses"]
    if [response["role"] for response in responses] != list(GATE_API_ROLES):
        raise AssertionError("gate fixture must archive exactly four CI-only responses")
    return raw


class ZenodoFixture:
    def __init__(self, root: Path) -> None:
        root = root.resolve()
        self.root = root
        self.verification_kwargs = {
            "cryptographic_attestation_verifier": (
                FIXTURE_CRYPTOGRAPHIC_VERIFIER
            ),
            "release_receipt_verifier": _fixture_release_receipt_verifier,
        }
        self.deposit = root / "deposit"
        self.assets = self.deposit / "github-assets"
        self.assets.mkdir(parents=True)
        self.plan_files: list[dict[str, object]] = []
        codec_files = {
            "LICENSE": (0o644, b"MIT codec fixture\n"),
            "RealLLM/codecs.py": (0o644, b"def codec(): return 'voidtoken'\n"),
        }
        lab_tree = LAB_TREE
        codec_tree = _tree_oid(codec_files)
        codec_commit_payload = (
            f"tree {codec_tree}\n"
            "author Ivan Tyshchenko <ivan@example.invalid> 1785758400 +0000\n"
            "committer Ivan Tyshchenko <ivan@example.invalid> 1785758400 +0000\n\n"
            "Codec archive fixture\n"
        ).encode()
        lab_tar, lab_commit, archived_lab_tree = _source_archive_bytes(
            LAB_FILES, commit_payload=LAB_COMMIT_PAYLOAD
        )
        codec_tar, codec_commit, archived_codec_tree = _source_archive_bytes(
            codec_files, commit_payload=codec_commit_payload
        )
        if (lab_commit, archived_lab_tree, archived_codec_tree) != (
            LAB_COMMIT,
            lab_tree,
            codec_tree,
        ):
            raise AssertionError("source archive fixture identity differs")

        def runtime(system: str, machine: str) -> bytes:
            value = with_content_digest(
                {
                    "schemaVersion": "corelm-crossmodel-livewiki-v3-runtime-manifest-v1",
                    "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                    "countsTowardScientificVerdict": False,
                    "networkUsed": False,
                    "modelInferenceUsed": False,
                    "python": {
                        "registeredVersion": "3.12.10",
                        "version": "3.12.10",
                        "platformTag": (
                            "linux-x86_64" if system == "Linux" else "macosx-15.0-arm64"
                        ),
                        "executable": {"bytes": 1, "sha256": _sha256(b"python")},
                    },
                    "host": {
                        "system": system,
                        "release": "fixture-release",
                        "version": "fixture-version",
                        "machine": machine,
                        "processor": "fixture-processor",
                        "macVersion": "15.0" if system == "Darwin" else None,
                    },
                    "environment": {
                        "HF_HUB_DISABLE_TELEMETRY": None,
                        "MKL_NUM_THREADS": None,
                        "NUMEXPR_NUM_THREADS": None,
                        "OMP_NUM_THREADS": None,
                        "OPENBLAS_NUM_THREADS": None,
                        "PYTHONHASHSEED": None,
                        "TOKENIZERS_PARALLELISM": None,
                        "TRANSFORMERS_OFFLINE": None,
                    },
                    "requirementsLocks": [
                        {"name": "requirements.lock", "bytes": 1, "sha256": _sha256(b"lock")}
                    ],
                    "installedDistributions": [{"name": "fixture", "version": "1"}],
                    "installedDistributionCount": 1,
                    "runtimeTree": {
                        "entries": [{"path": "bin/python", "type": "file"}],
                        "entryCount": 1,
                        "regularFileBytes": 1,
                        "treeSHA256": _sha256(b"runtime-tree"),
                    },
                    "basePythonTree": {
                        "entries": [{"path": "bin/python", "type": "file"}],
                        "entryCount": 1,
                        "regularFileBytes": 1,
                        "treeSHA256": _sha256(b"base-tree"),
                    },
                    "basePythonDistinctFromRuntime": False,
                    "labSource": {
                        "commit": LAB_COMMIT,
                        "tree": lab_tree,
                        "origin": f"https://github.com/{REPOSITORY}.git",
                        "worktreeClean": True,
                        "worktreeStatusSHA256": _sha256(b""),
                    },
                    "codecSource": {
                        "commit": codec_commit,
                        "tree": codec_tree,
                        "origin": "https://github.com/ALLPROTO/core-lm-benchmark.git",
                        "worktreeClean": True,
                        "worktreeStatusSHA256": _sha256(b""),
                    },
                }
            )
            return canonical_json_bytes(value) + b"\n"

        def ci_zip(system: str, machine: str, suffix: str) -> bytes:
            preflight = {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-preflight-v1",
                "status": "DEVELOPMENT_PREFLIGHT_ONLY",
                "countsTowardScientificVerdict": False,
                "networkUsed": False,
                "modelInferenceUsed": False,
                "corpusOpened": False,
                "attemptMarkerCreated": False,
                "platformSafety": {"system": system, "machine": machine},
                "codec": {"commit": codec_commit, "tree": codec_tree},
            }
            check = {
                "schemaVersion": "corelm-crossmodel-livewiki-v3-design-check-v1",
                "status": "DRAFT_VERIFIED_NOT_PREREGISTERED",
                "countsTowardScientificVerdict": False,
                "networkUsed": False,
                "modelInferenceUsed": False,
                "corpusOpened": False,
            }
            return _zip_bytes(
                {
                    f"v3-preflight-{suffix}.json": canonical_json_bytes(preflight) + b"\n",
                    f"v3-runtime-{suffix}.json": runtime(system, machine),
                    f"v3-zero-skip-{suffix}.log": (
                        b"Ran 42 tests in 1.0s\nOK\n"
                        b"ZERO-SKIP POLICY PASS: 42 tests, 0 skipped\n"
                    ),
                    f"v3-design-check-{suffix}.json": canonical_json_bytes(check) + b"\n",
                    f"v3-release-attestation-known-answer-{suffix}.json": (
                        json.dumps(
                            expected_known_answer_result(
                                expected_platform=(
                                    "darwin/arm64"
                                    if system == "Darwin"
                                    else "linux/amd64"
                                )
                            ),
                            ensure_ascii=False,
                            allow_nan=False,
                            indent=2,
                            sort_keys=True,
                        ).encode("utf-8")
                        + b"\n"
                    ),
                }
            )

        linux_artifact_name = f"author-v3-linux-development-{RUN_ID}-1"
        macos_artifact_name = f"author-v3-macos-development-{RUN_ID}-1"
        linux_zip = ci_zip("Linux", "x86_64", "linux")
        macos_zip = ci_zip("Darwin", "arm64", "macos")
        gate_bodies = _gate_bodies()
        gate_bodies["workflow-artifacts"] = {
            "total_count": 2,
            "artifacts": [
                {
                    "id": 91001,
                    "name": linux_artifact_name,
                    "expired": False,
                    "archive_download_url": f"{GATE_API_BASE}/actions/artifacts/91001/zip",
                    "workflow_run": {"id": RUN_ID},
                    "digest": "sha256:" + _sha256(linux_zip),
                    "size_in_bytes": len(linux_zip),
                },
                {
                    "id": 91002,
                    "name": macos_artifact_name,
                    "expired": False,
                    "archive_download_url": f"{GATE_API_BASE}/actions/artifacts/91002/zip",
                    "workflow_run": {"id": RUN_ID},
                    "digest": "sha256:" + _sha256(macos_zip),
                    "size_in_bytes": len(macos_zip),
                },
            ],
        }
        gate_raw = _collect_gate(root, gate_bodies)

        sbom = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "name": "Core LM cross-model benchmark laboratory",
                    "version": LAB_COMMIT,
                    "purl": f"pkg:github/{REPOSITORY}@{LAB_COMMIT}",
                    "properties": [{"name": "corelm:git-tree", "value": lab_tree}],
                }
            },
            "components": [
                {
                    "name": "VoidToken codec",
                    "version": codec_commit,
                    "purl": f"pkg:github/ALLPROTO/core-lm-benchmark@{codec_commit}",
                    "properties": [{"name": "corelm:git-tree", "value": codec_tree}],
                }
            ],
        }
        sbom_raw = canonical_json_bytes(sbom) + b"\n"
        design_runtime_raw = runtime("Darwin", "arm64")
        development_tag = "corelm-crossmodel-livewiki-v3-development-control"
        development_release_id = 8999
        development_assets = [
            {
                "role": role,
                "assetId": 8000 + index,
                "name": f"{role}.json",
                "apiURL": f"{GATE_API_BASE}/releases/assets/{8000 + index}",
                "downloadURL": (
                    f"https://github.com/{REPOSITORY}/releases/download/"
                    f"{development_tag}/{role}.json"
                ),
                "bytes": len(role.encode()),
                "sha256": _sha256(role.encode()),
            }
            for index, role in enumerate(REQUIRED_ASSET_ROLES["development-control"])
        ]
        development_tag_payload = (
            f"object {LAB_COMMIT}\n"
            "type commit\n"
            f"tag {development_tag}\n"
            "tagger Ivan Tyshchenko <ivan@example.invalid> 1785758100 +0000\n\n"
            "Development-control fixture\n"
            "-----BEGIN SSH SIGNATURE-----\n"
            "ZmFrZQ==\n"
            "-----END SSH SIGNATURE-----\n"
        ).encode()
        development_tag_oid = hashlib.sha1(
            f"tag {len(development_tag_payload)}\0".encode()
            + development_tag_payload,
            usedforsecurity=False,
        ).hexdigest()
        development_attestation_raw = _release_attestation_output(
            repository=REPOSITORY,
            tag=development_tag,
            release_subject_sha1=development_tag_oid,
            release_id=development_release_id,
            assets=development_assets,
            attested_at="2026-08-03T09:55:00Z",
        )
        development_attestation_value = json.loads(development_attestation_raw)
        development_attestation_bundle_sha256 = _sha256(
            canonical_json_bytes(
                development_attestation_value["attestation"]["bundle"]
            )
        )
        development_receipt: dict[str, object] = {
            "schemaVersion": "corelm-github-release-receipt-v2",
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
            "githubAPIVersion": "2026-03-10",
            "repository": {"slug": REPOSITORY},
            "kind": "development-control",
            "tag": development_tag,
            "release": {
                "id": development_release_id,
                "publishedAt": "2026-08-03T09:54:00Z",
                "deadline": "2026-08-15T00:00:00Z",
            },
            "source": {"commit": LAB_COMMIT, "tree": lab_tree},
            "annotatedTag": {
                "objectOID": development_tag_oid,
                "targetType": "commit",
                "targetCommit": LAB_COMMIT,
                "rawPayload": _archived(development_tag_payload),
            },
            "signatureVerification": {},
            "githubReleaseAttestation": build_attestation_record(
                development_attestation_raw,
                _fixture_crypto_record(
                    development_attestation_raw, development_assets
                ),
            ),
            "requiredAssets": development_assets,
            "githubAPIResponses": [],
            "receiptCreatedAt": "2026-08-03T09:56:00Z",
        }
        development_receipt_raw = _canonical_receipt(development_receipt)
        design = {
            "schemaVersion": "corelm-crossmodel-livewiki-v3-design-v1",
            "status": "PUBLIC_DESIGN_FROZEN",
            "readyToFreeze": True,
            "countsTowardScientificVerdict": False,
            "freezeBlockers": [],
            "labSource": {
                "status": "FROZEN_BOUND",
                "commit": LAB_COMMIT,
                "tree": lab_tree,
            },
            "codecSource": {"commit": codec_commit, "tree": codec_tree},
            "runtime": {
                "primaryPlatform": "macOS-arm64-local-offline",
                "runtimeManifestSHA256": _sha256(design_runtime_raw),
            },
            "continuousIntegration": {"ciArtifactBytesMustBeArchivedSeparately": True},
            "developmentControls": {
                "realDataE2EFreezeGate": {
                    "completeNoLaterThan": "2026-08-15T00:00:00Z",
                    "archiveTag": development_tag,
                    "archiveReceiptSHA256": _sha256(development_receipt_raw),
                    "archivePublishedAt": "2026-08-03T09:54:00Z",
                    "archiveAttestedAt": "2026-08-03T09:55:00Z",
                    "releaseAttestationBundleSHA256": (
                        development_attestation_bundle_sha256
                    ),
                    "releaseAttestationOutputSHA256": _sha256(
                        development_attestation_raw
                    ),
                }
            },
            "designRelease": {
                "tag": "design-v1",
                "publishNoLaterThan": "2026-08-15T00:00:00Z",
                "serverTimestampRequired": True,
                "immutableReleaseRequired": True,
                "signedAnnotatedTagRequired": True,
                "signatureType": "SSH",
                "signingKeyFingerprint": "SHA256:" + "A" * 43,
                "signingPublicKeySHA256": "9" * 64,
            },
        }
        design_raw = canonical_json_bytes(design) + b"\n"
        asset_payloads = {
            "asset-source-manifest": b'{"fixture":"asset-source"}\n',
            "design-registration": design_raw,
            "development-control-report": b'{"fixture":"development-control-report"}\n',
            "development-control-archive-receipt": development_receipt_raw,
            "freeze-manifest": b'{"fixture":"freeze"}\n',
            "full-asset-receipt": b'{"fixture":"assets"}\n',
            "github-gate-receipt": gate_raw,
            "linux-ci-artifact": linux_zip,
            "macos-arm64-ci-artifact": macos_zip,
            "runtime-manifest": design_runtime_raw,
            "sbom": sbom_raw,
            "sha256-manifest": b'{"fixture":"sha256-manifest"}\n',
        }
        required_assets: list[dict[str, object]] = []
        for index, role in enumerate(REQUIRED_ASSET_ROLES["design"]):
            name = f"{role}.json"
            payload = asset_payloads[role]
            (self.assets / name).write_bytes(payload)
            required_assets.append(
                {
                    "role": role,
                    "assetId": 1000 + index,
                    "name": name,
                    "apiURL": f"{GATE_API_BASE}/releases/assets/{1000 + index}",
                    "downloadURL": (
                        f"https://github.com/{REPOSITORY}/releases/download/design-v1/{name}"
                    ),
                    "bytes": len(payload),
                    "sha256": _sha256(payload),
                }
            )
            self.plan_files.append(
                {
                    "path": f"github-assets/{name}",
                    "role": "github-release-asset",
                    "githubAssetRole": role,
                    "githubActionsArtifactName": None,
                    "mediaType": (
                        "application/zip"
                        if role in {"linux-ci-artifact", "macos-arm64-ci-artifact"}
                        else "application/json"
                    ),
                    "rightsIds": ["mit"],
                }
            )
        tag_payload = (
            f"object {LAB_COMMIT}\n"
            "type commit\n"
            "tag design-v1\n"
            "tagger Ivan Tyshchenko <ivan@example.invalid> 1785758400 +0000\n\n"
            "Frozen design fixture\n"
            "-----BEGIN SSH SIGNATURE-----\n"
            "ZmFrZQ==\n"
            "-----END SSH SIGNATURE-----\n"
        ).encode()
        tag_oid = hashlib.sha1(
            f"tag {len(tag_payload)}\0".encode() + tag_payload,
            usedforsecurity=False,
        ).hexdigest()
        release_attestation_raw = _release_attestation_output(
            repository=REPOSITORY,
            tag="design-v1",
            release_subject_sha1=tag_oid,
            release_id=9001,
            assets=required_assets,
            attested_at="2026-08-03T10:00:01Z",
        )
        release_attestation_bundle_sha256 = _sha256(
            canonical_json_bytes(
                json.loads(release_attestation_raw)["attestation"]["bundle"]
            )
        )
        github_receipt: dict[str, object] = {
            "schemaVersion": "corelm-github-release-receipt-v2",
            "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
            "githubAPIVersion": "2026-03-10",
            "repository": {
                "slug": REPOSITORY,
                "htmlURL": f"https://github.com/{REPOSITORY}",
                "apiURL": GATE_API_BASE,
            },
            "kind": "design",
            "tag": "design-v1",
            "release": {
                "id": 9001,
                "publishedAt": "2026-08-03T10:00:00Z",
                "deadline": "2026-08-15T00:00:00Z",
            },
            "source": {
                "commit": LAB_COMMIT,
                "tree": lab_tree,
                "commitObject": {
                    "oid": LAB_COMMIT,
                    "rawPayload": _archived(LAB_COMMIT_PAYLOAD),
                },
            },
            "annotatedTag": {
                "objectOID": tag_oid,
                "targetType": "commit",
                "targetCommit": LAB_COMMIT,
                "rawPayload": _archived(tag_payload),
            },
            "signatureVerification": {
                "status": "VERIFIED",
                "signatureType": "SSH",
                "method": "git verify-tag",
                "toolVersion": "git version fixture",
                "exitCode": 0,
                "trustPolicy": "FROZEN_KEY_FINGERPRINT_AND_SHA256_MATCH",
                "keyFingerprint": "SHA256:" + "A" * 43,
                "publicKeySHA256": "9" * 64,
                "tagObjectOID": tag_oid,
                "targetCommit": LAB_COMMIT,
                "verifiedAt": "2026-08-03T09:59:00Z",
                "transcript": _archived(b"Good SSH signature fixture\n"),
            },
            "githubReleaseAttestation": build_attestation_record(
                release_attestation_raw,
                _fixture_crypto_record(
                    release_attestation_raw, required_assets
                ),
            ),
            "requiredAssets": required_assets,
            "githubAPIResponses": [],
            "receiptCreatedAt": "2026-08-03T10:01:00Z",
        }
        github_receipt["contentSHA256"] = _sha256(canonical_json_bytes(github_receipt))
        self.github_receipt_raw = canonical_json_bytes(github_receipt) + b"\n"
        (self.deposit / "github-release-receipt.json").write_bytes(self.github_receipt_raw)
        self.plan_files.append(
            {
                "path": "github-release-receipt.json",
                "role": "github-release-receipt",
                "githubAssetRole": None,
                "githubActionsArtifactName": None,
                "mediaType": "application/json",
                "rightsIds": ["mit"],
            }
        )
        (self.deposit / "github-gate-receipt.json").write_bytes(gate_raw)

        def add_file(
            path: str,
            role: str,
            media_type: str,
            payload: bytes,
            *,
            actions_name: str | None = None,
            rights_ids: list[str] | None = None,
        ) -> None:
            (self.deposit / path).write_bytes(payload)
            self.plan_files.append(
                {
                    "path": path,
                    "role": role,
                    "githubAssetRole": None,
                    "githubActionsArtifactName": actions_name,
                    "mediaType": media_type,
                    "rightsIds": rights_ids or ["mit"],
                }
            )

        self.plan_files.append(
            {
                "path": "github-gate-receipt.json",
                "role": "github-gate-receipt",
                "githubAssetRole": None,
                "githubActionsArtifactName": None,
                "mediaType": "application/json",
                "rightsIds": ["mit"],
            }
        )
        citation = {
            "cff-version": "1.2.0",
            "message": "Cite this exact immutable release.",
            "type": "software",
            "title": "Core LM cross-model benchmark laboratory",
            "version": "design-v1",
            "date-released": "2026-08-03",
            "repository-code": f"https://github.com/{REPOSITORY}",
            "authors": [
                {
                    "family-names": "Tyshchenko",
                    "given-names": "Ivan",
                    "orcid": "https://orcid.org/0009-0000-7935-6090",
                }
            ],
            "identifiers": [{"type": "doi", "value": DOI}],
        }
        add_file(
            "CITATION.cff",
            "release-specific-citation",
            "application/yaml",
            canonical_json_bytes(citation) + b"\n",
        )
        codec_license = b"MIT codec fixture\n"
        source_evidence = {
            "schemaVersion": "corelm-crossmodel-livewiki-v2-license-source-evidence-v1",
            "status": "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED",
            "sources": [
                {
                    "component": "VoidToken codec source",
                    "repository": "ALLPROTO/core-lm-benchmark",
                    "revision": codec_commit,
                    "archivedPath": "upstream/voidtoken-LICENSE",
                    "archivedEncoding": "identity",
                    "bytes": len(codec_license),
                    "sha256": _sha256(codec_license),
                }
            ],
        }
        licenses_tar = _tar_bytes(
            {
                "ASSET_LICENSES.md": (0o644, b"# Rights matrix\n"),
                "README.md": (0o644, b"# License evidence\n"),
                "source-evidence.json": (0o644, canonical_json_bytes(source_evidence)),
                "upstream/voidtoken-LICENSE": (0o644, codec_license),
            }
        )
        add_file("LICENSES.tar", "license-material", "application/x-tar", licenses_tar)
        add_file(
            "NOTICE.md",
            "notice",
            "text/markdown",
            (
                f"# Notice\nRepository: {REPOSITORY}\nDOI: {DOI}\n"
                "Rights: cc-by-sa-4.0, mit\n"
            ).encode(),
            rights_ids=["cc-by-sa-4.0", "mit"],
        )
        add_file("sbom.cdx.json", "sbom", "application/json", sbom_raw)
        add_file(
            "linux-ci-artifact.zip",
            "linux-ci-artifact",
            "application/zip",
            linux_zip,
            actions_name=linux_artifact_name,
        )
        add_file(
            "macos-arm64-ci-artifact.zip",
            "macos-arm64-ci-artifact",
            "application/zip",
            macos_zip,
            actions_name=macos_artifact_name,
        )
        add_file("lab-source.tar", "lab-source-archive", "application/x-tar", lab_tar)
        add_file("codec-source.tar", "codec-source-archive", "application/x-tar", codec_tar)
        projection = with_content_digest(
            {
                "schemaVersion": "corelm-signed-tag-verification-v1",
                "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
                "status": "VERIFIED",
                "repository": REPOSITORY,
                "tag": "design-v1",
                "commit": LAB_COMMIT,
                "tree": lab_tree,
                "signatureType": "SSH",
                "keyFingerprint": "SHA256:" + "A" * 43,
                "publicKeySHA256": "9" * 64,
                "tagObjectOID": tag_oid,
                "verifiedAt": "2026-08-03T09:59:00Z",
                "attestedAt": "2026-08-03T10:00:01Z",
                "releaseAttestationBundleSHA256": (
                    release_attestation_bundle_sha256
                ),
                "releaseAttestationOutputSHA256": _sha256(
                    release_attestation_raw
                ),
                "releaseReceiptSHA256": _sha256(self.github_receipt_raw),
                "transcriptSHA256": _sha256(b"Good SSH signature fixture\n"),
            }
        )
        add_file(
            "signed-tag-verification.json",
            "signed-tag-verification",
            "application/json",
            canonical_json_bytes(projection) + b"\n",
        )

        rights_declarations = [
            {
                "rightsId": "cc-by-sa-4.0",
                "title": "Creative Commons Attribution Share Alike 4.0 International",
                "uri": "https://creativecommons.org/licenses/by-sa/4.0/",
                "zenodoIdentifier": "cc-by-sa-4.0",
            },
            {
                "rightsId": "mit",
                "title": "MIT License",
                "uri": "https://spdx.org/licenses/MIT.html",
                "zenodoIdentifier": "mit",
            },
        ]
        self.plan_files.append(
            {
                "path": "rights.json",
                "role": "rights-metadata",
                "githubAssetRole": None,
                "githubActionsArtifactName": None,
                "mediaType": "application/json",
                "rightsIds": ["cc-by-sa-4.0", "mit"],
            }
        )
        file_rights = [
            {"path": item["path"], "rightsIds": sorted(item["rightsIds"])}
            for item in self.plan_files
        ] + [{"path": MANIFEST_FILE_NAME, "rightsIds": ["mit"]}]
        file_rights.sort(key=lambda item: item["path"])
        rights_metadata = with_content_digest(
            {
                "schemaVersion": "corelm-zenodo-rights-metadata-v1",
                "suiteId": "corelm-voidtoken-crossmodel-livewiki-v3-author-verified",
                "releaseKind": "design",
                "doi": DOI,
                "rightsDeclarations": rights_declarations,
                "fileRights": file_rights,
            }
        )
        (self.deposit / "rights.json").write_bytes(
            canonical_json_bytes(rights_metadata) + b"\n"
        )
        self.plan = {
            "schemaVersion": "corelm-zenodo-deposit-plan-v1",
            "releaseKind": "design",
            "githubReleaseReceiptPath": "github-release-receipt.json",
            "githubReleaseAssetsDirectory": "github-assets",
            "zenodoReservation": {
                "depositionId": DEPOSITION_ID,
                "recordId": RECORD_ID,
                "doi": DOI,
            },
            "rightsDeclarations": rights_declarations,
            "manifestRightsIds": ["mit"],
            "files": self.plan_files,
        }
        self.manifest = build_deposit_manifest(
            self.deposit,
            self.plan,
            **self.verification_kwargs,
        )
        self.manifest_path = root / MANIFEST_FILE_NAME
        self.manifest_raw = canonical_json_bytes(self.manifest) + b"\n"
        self.manifest_path.write_bytes(self.manifest_raw)
        local: dict[str, bytes] = {}
        for path in self.deposit.rglob("*"):
            if path.is_file():
                local[path.relative_to(self.deposit).as_posix()] = path.read_bytes()
        local[MANIFEST_FILE_NAME] = self.manifest_raw
        self.local = local
        deposition_files = [
            {
                "id": f"dep-{index}",
                "filename": path,
                "filesize": len(payload),
                "checksum": f"md5:{_md5(payload)}",
            }
            for index, (path, payload) in enumerate(sorted(local.items()))
        ]
        record_files = [
            {
                "id": f"rec-{index}",
                "key": path,
                "size": len(payload),
                "checksum": f"md5:{_md5(payload)}",
                "links": {
                    "self": f"https://zenodo.org/api/records/{RECORD_ID}/files/{path}/content"
                },
            }
            for index, (path, payload) in enumerate(sorted(local.items()))
        ]
        rights = [
            {
                "id": "mit",
                "title": "MIT License",
                "link": "https://spdx.org/licenses/MIT.html",
            },
            {
                "id": "cc-by-sa-4.0",
                "title": "Creative Commons Attribution Share Alike 4.0 International",
                "link": "https://creativecommons.org/licenses/by-sa/4.0/",
            },
        ]
        self.bodies: dict[str, object] = {
            "deposition": {
                "id": DEPOSITION_ID,
                "record_id": RECORD_ID,
                "doi": DOI,
                "doi_url": f"https://doi.org/{DOI}",
                "record_url": f"https://zenodo.org/api/records/{RECORD_ID}",
                "state": "done",
                "submitted": True,
                "metadata": {"rights": rights},
                "files": deposition_files,
            },
            "deposition-files": deposition_files,
            "record": {
                "id": RECORD_ID,
                "recid": str(RECORD_ID),
                "doi": DOI,
                "doi_url": f"https://doi.org/{DOI}",
                "state": "done",
                "status": "published",
                "submitted": True,
                "metadata": {
                    "doi": DOI,
                    "publication_date": "2026-08-03",
                    "rights": rights,
                },
                "links": {
                    "self": f"https://zenodo.org/api/records/{RECORD_ID}",
                    "self_html": f"https://zenodo.org/records/{RECORD_ID}",
                    "doi": f"https://doi.org/{DOI}",
                },
                "files": record_files,
            },
        }

    def captures(self, bodies: dict[str, object] | None = None) -> dict[str, HTTPSCapture]:
        result: dict[str, HTTPSCapture] = {}
        for role, value in (bodies or self.bodies).items():
            body = _json_body(value)
            result[role] = HTTPSCapture(200, _headers(body), body, CAPTURED)
        return result

    def receipt(self) -> dict[str, object]:
        return build_zenodo_receipt(
            manifest_path=self.manifest_path,
            deposit_root=self.deposit,
            deposition_id=DEPOSITION_ID,
            record_id=RECORD_ID,
            doi=DOI,
            captures=self.captures(),
            receipt_created_at=CREATED,
            **self.verification_kwargs,
        )


class ZenodoArchiveTests(unittest.TestCase):
    def test_annotated_tag_oid_rehashes_and_strictly_parses_raw_payload(self) -> None:
        tag = "development-control-v1"
        payload = (
            f"object {LAB_COMMIT}\n"
            "type commit\n"
            f"tag {tag}\n"
            "tagger Ivan Tyshchenko <ivan@example.invalid> 1785758100 +0000\n\n"
            "Development-control fixture\n"
        ).encode("utf-8")

        def receipt_for(raw: bytes) -> dict[str, object]:
            object_oid = hashlib.sha1(
                f"tag {len(raw)}\0".encode("ascii") + raw,
                usedforsecurity=False,
            ).hexdigest()
            return {
                "annotatedTag": {
                    "objectOID": object_oid,
                    "targetType": "commit",
                    "targetCommit": LAB_COMMIT,
                    "rawPayload": _archived(raw),
                }
            }

        receipt = receipt_for(payload)
        self.assertEqual(
            _annotated_tag_oid(
                receipt,
                expected_commit=LAB_COMMIT,
                expected_tag=tag,
                label="fixture tag",
            ),
            receipt["annotatedTag"]["objectOID"],
        )

        changed_oid = deepcopy(receipt)
        changed_oid["annotatedTag"]["objectOID"] = "0" * 40
        mutations = {
            "claimed OID": changed_oid,
            "target object": receipt_for(
                payload.replace(
                    f"object {LAB_COMMIT}".encode("ascii"), b"object " + b"0" * 40
                )
            ),
            "object type": receipt_for(payload.replace(b"type commit", b"type blob")),
            "tag name": receipt_for(
                payload.replace(f"tag {tag}".encode("utf-8"), b"tag another-tag")
            ),
        }
        for case, mutated in mutations.items():
            with self.subTest(case=case), self.assertRaisesRegex(
                ZenodoArchiveError, "identity differs"
            ):
                _annotated_tag_oid(
                    mutated,
                    expected_commit=LAB_COMMIT,
                    expected_tag=tag,
                    label="fixture tag",
                )

    def test_gate_projection_rejects_forged_independent_review_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            gate = json.loads(
                (fixture.deposit / "github-gate-receipt.json").read_bytes()
            )
            gate["authorVerification"]["independentHumanReviewPerformed"] = True
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "failed canonical offline verification",
            ):
                _github_gate_summary(
                    _canonical_receipt(gate),
                    receipt_path="github-gate-receipt.json",
                    expected_implementation_commit=LAB_COMMIT,
                )

    def test_manifest_and_receipt_fail_closed_without_crypto_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "pinned cryptographic release-attestation verifier is required",
            ):
                build_deposit_manifest(fixture.deposit, fixture.plan)
            raw = canonical_json_bytes(fixture.receipt()) + b"\n"
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "pinned cryptographic release-attestation verifier is required",
            ):
                verify_zenodo_receipt(
                    raw,
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    expected_deposition_id=DEPOSITION_ID,
                    expected_record_id=RECORD_ID,
                    expected_doi=DOI,
                )

    def test_full_release_replay_rejects_forged_signature_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = json.loads(fixture.github_receipt_raw)
            receipt["signatureVerification"]["status"] = "UNVERIFIED"
            (fixture.deposit / "github-release-receipt.json").write_bytes(
                _canonical_receipt(receipt)
            )
            calls = 0

            def rejecting_verifier(
                raw: bytes, _asset_root: Path, **_arguments: object
            ) -> SimpleNamespace:
                nonlocal calls
                calls += 1
                self.assertEqual(
                    json.loads(raw)["signatureVerification"]["status"],
                    "UNVERIFIED",
                )
                raise ReleaseReceiptError("signature status is forged")

            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "failed full SSH/Cosign verification",
            ):
                build_deposit_manifest(
                    fixture.deposit,
                    fixture.plan,
                    cryptographic_attestation_verifier=(
                        FIXTURE_CRYPTOGRAPHIC_VERIFIER
                    ),
                    release_receipt_verifier=rejecting_verifier,
                )
            self.assertEqual(calls, 1)

    def test_receipt_rejects_changed_evidence_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = fixture.receipt()
            receipt["evidenceBoundary"] = "ZENODO_SIGNED_THESE_RESPONSES"
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "schema/suite/environment/evidence boundary differs",
            ):
                verify_zenodo_receipt(
                    _canonical_receipt(receipt),
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    expected_deposition_id=DEPOSITION_ID,
                    expected_record_id=RECORD_ID,
                    expected_doi=DOI,
                    **fixture.verification_kwargs,
                )

    def test_closeout_release_attestation_must_precede_its_own_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = json.loads(fixture.github_receipt_raw)
            receipt["kind"] = "closeout"
            assets: list[dict[str, object]] = []
            inventory: dict[str, dict[str, object]] = {}
            for index, role in enumerate(REQUIRED_ASSET_ROLES["closeout"]):
                payload = role.encode("ascii")
                name = f"{role}.json"
                assets.append(
                    {
                        "role": role,
                        "assetId": 20_000 + index,
                        "name": name,
                        "apiURL": f"{GATE_API_BASE}/releases/assets/{20_000 + index}",
                        "downloadURL": (
                            f"https://github.com/{REPOSITORY}/releases/download/"
                            f"{receipt['tag']}/{name}"
                        ),
                        "bytes": len(payload),
                        "sha256": _sha256(payload),
                    }
                )
                inventory[f"github-assets/{name}"] = {
                    "bytes": len(payload),
                    "sha256": _sha256(payload),
                }
            receipt["requiredAssets"] = assets
            raw = _canonical_receipt(receipt)
            inventory["github-release-receipt.json"] = {
                "bytes": len(raw),
                "sha256": _sha256(raw),
            }
            verified = SimpleNamespace(
                attested_at="2026-08-03T10:00:01Z",
                bundle_sha256="1" * 64,
                raw_output_sha256="2" * 64,
            )
            with patch(
                "v3.zenodo_archive.verify_attestation_record",
                return_value=verified,
            ) as verifier:
                summary, _roles = _github_release_summary(
                    raw,
                    "github-release-receipt.json",
                    inventory=inventory,
                    github_asset_directory="github-assets",
                )
            self.assertEqual(summary["kind"], "closeout")
            self.assertEqual(
                verifier.call_args.kwargs["expected_attestation_relation"],
                "STRICTLY_BEFORE_DEADLINE",
            )
            self.assertEqual(
                verifier.call_args.kwargs["expected_tag_oid"],
                receipt["annotatedTag"]["objectOID"],
            )

    def test_manifest_is_deterministic_and_exact_superset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            again = build_deposit_manifest(
                fixture.deposit,
                fixture.plan,
                **fixture.verification_kwargs,
            )
            self.assertEqual(again, fixture.manifest)
            self.assertEqual(
                tuple(item["path"] for item in again["files"]),
                tuple(sorted(item["path"] for item in again["files"])),
            )
            self.assertEqual(
                {
                    item["githubAssetRole"]
                    for item in again["files"]
                    if item["role"] == "github-release-asset"
                },
                set(REQUIRED_ASSET_ROLES["design"]),
            )
            self.assertEqual(
                again["githubRelease"]["attestedAt"],
                "2026-08-03T10:00:01Z",
            )
            self.assertEqual(
                again["developmentControlArchive"]["archiveAttestedAt"],
                "2026-08-03T09:55:00Z",
            )
            self.assertEqual(
                again["developmentControlArchive"][
                    "releaseAttestationOutputSHA256"
                ],
                json.loads(
                    (
                        fixture.assets
                        / "development-control-archive-receipt.json"
                    ).read_bytes()
                )["githubReleaseAttestation"]["rawVerificationOutput"]["sha256"],
            )
            self.assertEqual(again["fileCount"], len(fixture.local) - 1)

    def test_manifest_rejects_rehashed_development_attestation_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            manifest = deepcopy(fixture.manifest)
            manifest["developmentControlArchive"][
                "releaseAttestationBundleSHA256"
            ] = "0" * 64
            manifest.pop("contentSHA256")
            manifest["contentSHA256"] = _sha256(canonical_json_bytes(manifest))
            fixture.manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "development-control archive projection differs",
            ):
                fixture.receipt()

    def test_manifest_rejects_legacy_github_receipt_without_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            legacy = json.loads(fixture.github_receipt_raw)
            del legacy["githubReleaseAttestation"]
            (fixture.deposit / "github-release-receipt.json").write_bytes(
                _canonical_receipt(legacy)
            )
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "GitHub receipt root differs from the canonical release contract",
            ):
                build_deposit_manifest(
                    fixture.deposit,
                    fixture.plan,
                    **fixture.verification_kwargs,
                )

    def test_manifest_rejects_release_attestation_at_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = json.loads(fixture.github_receipt_raw)
            archived = receipt["githubReleaseAttestation"][
                "rawVerificationOutput"
            ]
            output = json.loads(base64.b64decode(archived["dataBase64"]))
            output["verificationResult"]["verifiedTimestamps"][0][
                "timestamp"
            ] = "2026-08-15T00:00:00Z"
            raw = json.dumps(output, separators=(",", ":")).encode() + b"\n"
            receipt["githubReleaseAttestation"] = build_attestation_record(
                raw,
                _fixture_crypto_record(raw, receipt["requiredAssets"]),
            )
            (fixture.deposit / "github-release-receipt.json").write_bytes(
                _canonical_receipt(receipt)
            )
            with self.assertRaisesRegex(
                ZenodoArchiveError,
                "immutable-release attestation differs",
            ):
                build_deposit_manifest(
                    fixture.deposit,
                    fixture.plan,
                    **fixture.verification_kwargs,
                )

    def test_manifest_builder_writes_new_external_file_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            output = fixture.root / "second-manifest.json"
            built = build_deposit_manifest_to_path(
                fixture.deposit,
                fixture.plan,
                output,
                **fixture.verification_kwargs,
            )
            self.assertEqual(output.read_bytes(), canonical_json_bytes(built) + b"\n")
            with self.assertRaises(FileExistsError):
                build_deposit_manifest_to_path(
                    fixture.deposit,
                    fixture.plan,
                    output,
                    **fixture.verification_kwargs,
                )
            with self.assertRaises(ZenodoArchiveError):
                build_deposit_manifest_to_path(
                    fixture.deposit,
                    fixture.plan,
                    fixture.deposit / "forbidden.json",
                    **fixture.verification_kwargs,
                )

    def test_manifest_rejects_unmanifested_and_changed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            (fixture.deposit / "extra.bin").write_bytes(b"unmanifested")
            with self.assertRaisesRegex(ZenodoArchiveError, "exact deposit root"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            first_asset = fixture.assets / f"{REQUIRED_ASSET_ROLES['design'][0]}.json"
            first_asset.write_bytes(b"changed")
            with self.assertRaisesRegex(ZenodoArchiveError, "bytes differ"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )

    def test_manifest_rejects_incomplete_archival_roles_and_undeclared_own_rights(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            (fixture.deposit / "NOTICE.md").unlink()
            fixture.plan["files"] = [
                item for item in fixture.plan["files"] if item["path"] != "NOTICE.md"
            ]
            with self.assertRaisesRegex(ZenodoArchiveError, "omits required archival roles"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            fixture.plan["manifestRightsIds"] = ["not-declared"]
            with self.assertRaisesRegex(ZenodoArchiveError, "manifest rightsIds"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )

    def test_manifest_semantically_verifies_citation_source_and_ci_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            citation = json.loads((fixture.deposit / "CITATION.cff").read_bytes())
            citation["identifiers"][0]["value"] = "10.5281/zenodo.999999"
            (fixture.deposit / "CITATION.cff").write_bytes(
                canonical_json_bytes(citation) + b"\n"
            )
            with self.assertRaisesRegex(ZenodoArchiveError, "CITATION.cff identity"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            archive = fixture.deposit / "lab-source.tar"
            changed = archive.read_bytes().replace(
                b"laboratory source\n", b"Laboratory source\n", 1
            )
            archive.write_bytes(changed)
            with self.assertRaisesRegex(ZenodoArchiveError, "canonical source-manifest"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            (fixture.deposit / "linux-ci-artifact.zip").write_bytes(
                _zip_bytes({"v3-zero-skip-linux.log": b"fabricated PASS\n"})
            )
            with self.assertRaisesRegex(ZenodoArchiveError, "CI artifact bytes differ"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            artifact = fixture.deposit / "linux-ci-artifact.zip"
            with zipfile.ZipFile(io.BytesIO(artifact.read_bytes()), "r") as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            known_answer_name = "v3-release-attestation-known-answer-linux.json"
            known_answer = json.loads(members[known_answer_name])
            known_answer["bundleSHA256"] = "0" * 64
            members[known_answer_name] = (
                json.dumps(
                    known_answer,
                    ensure_ascii=False,
                    allow_nan=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            changed_zip = _zip_bytes(members)
            runtime = json.loads(members["v3-runtime-linux.json"])
            with self.assertRaisesRegex(
                ZenodoArchiveError, "release-attestation known answer differs"
            ):
                _verify_ci_payload(
                    changed_zip,
                    role="linux-ci-artifact",
                    lab_commit=LAB_COMMIT,
                    lab_tree=LAB_TREE,
                    codec_commit=runtime["codecSource"]["commit"],
                    codec_tree=runtime["codecSource"]["tree"],
                    lab_repository=REPOSITORY,
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            path = fixture.deposit / "signed-tag-verification.json"
            projection = json.loads(path.read_bytes())
            projection["transcriptSHA256"] = "0" * 64
            unsigned = dict(projection)
            unsigned.pop("contentSHA256")
            projection["contentSHA256"] = _sha256(canonical_json_bytes(unsigned))
            path.write_bytes(canonical_json_bytes(projection) + b"\n")
            with self.assertRaisesRegex(ZenodoArchiveError, "projection differs"):
                build_deposit_manifest(
                    fixture.deposit, fixture.plan, **fixture.verification_kwargs
                )

    def test_archival_projection_rejects_legacy_non_ssh_release_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = json.loads(fixture.github_receipt_raw)
            tag = receipt["annotatedTag"]
            tag_payload = base64.b64decode(tag["rawPayload"]["dataBase64"])
            tag_payload = tag_payload.replace(
                b"-----BEGIN SSH SIGNATURE-----",
                b"-----BEGIN PGP SIGNATURE-----",
            ).replace(
                b"-----END SSH SIGNATURE-----",
                b"-----END PGP SIGNATURE-----",
            )
            tag_oid = hashlib.sha1(
                f"tag {len(tag_payload)}\0".encode() + tag_payload,
                usedforsecurity=False,
            ).hexdigest()
            tag["objectOID"] = tag_oid
            tag["rawPayload"] = _archived(tag_payload)
            signature = receipt["signatureVerification"]
            signature["signatureType"] = "OPEN" + "PGP"
            signature["tagObjectOID"] = tag_oid
            with self.assertRaisesRegex(
                ZenodoArchiveError, "signed annotated tag evidence differs"
            ):
                _verify_github_signed_tag_receipt(
                    receipt,
                    github_release={
                        "commit": receipt["source"]["commit"],
                        "tree": receipt["source"]["tree"],
                        "tag": receipt["tag"],
                    },
                )

    def test_valid_published_receipt_verifies_entirely_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = fixture.receipt()
            raw = canonical_json_bytes(receipt) + b"\n"
            verified = verify_zenodo_receipt(
                raw,
                manifest_path=fixture.manifest_path,
                deposit_root=fixture.deposit,
                expected_deposition_id=DEPOSITION_ID,
                expected_record_id=RECORD_ID,
                expected_doi=DOI,
                **fixture.verification_kwargs,
            )
            self.assertEqual(verified.doi, DOI)
            self.assertEqual(receipt["evidenceBoundary"], EVIDENCE_BOUNDARY)
            self.assertEqual(len(verified.file_sha256), len(fixture.local))

    def test_receipt_rejects_sandbox_or_fabricated_doi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            with self.assertRaisesRegex(ZenodoArchiveError, "production version DOI"):
                build_zenodo_receipt(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=f"10.5072/zenodo.{RECORD_ID}",
                    captures=fixture.captures(),
                    receipt_created_at=CREATED,
                    **fixture.verification_kwargs,
                )

    def test_receipt_rejects_missing_rights_and_unpublished_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            bodies = deepcopy(fixture.bodies)
            bodies["record"]["metadata"]["rights"] = [  # type: ignore[index]
                {"id": "mit", "title": "MIT License", "link": "https://spdx.org/licenses/MIT.html"}
            ]
            with self.assertRaisesRegex(ZenodoArchiveError, "omits cc-by-sa"):
                build_zenodo_receipt(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    captures=fixture.captures(bodies),
                    receipt_created_at=CREATED,
                    **fixture.verification_kwargs,
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            bodies = deepcopy(fixture.bodies)
            bodies["record"]["status"] = "draft"  # type: ignore[index]
            with self.assertRaisesRegex(ZenodoArchiveError, "identity/state"):
                build_zenodo_receipt(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    captures=fixture.captures(bodies),
                    receipt_created_at=CREATED,
                    **fixture.verification_kwargs,
                )

    def test_receipt_rejects_remote_checksum_and_local_sha256_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            bodies = deepcopy(fixture.bodies)
            bodies["record"]["files"][0]["checksum"] = "md5:" + "0" * 32  # type: ignore[index]
            with self.assertRaisesRegex(ZenodoArchiveError, "file metadata differs"):
                build_zenodo_receipt(
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    deposition_id=DEPOSITION_ID,
                    record_id=RECORD_ID,
                    doi=DOI,
                    captures=fixture.captures(bodies),
                    receipt_created_at=CREATED,
                    **fixture.verification_kwargs,
                )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            raw = canonical_json_bytes(fixture.receipt()) + b"\n"
            (fixture.deposit / "rights.json").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(ZenodoArchiveError, "differs from manifest"):
                verify_zenodo_receipt(
                    raw,
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    expected_deposition_id=DEPOSITION_ID,
                    expected_record_id=RECORD_ID,
                    expected_doi=DOI,
                    **fixture.verification_kwargs,
                )

    def test_receipt_rejects_target_and_archived_body_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ZenodoFixture(Path(temporary))
            receipt = fixture.receipt()
            changed = deepcopy(receipt)
            changed["apiResponses"][0]["requestTarget"] += (  # type: ignore[index,operator]
                "/actions/publish"
            )
            with self.assertRaisesRegex(ZenodoArchiveError, "request target"):
                verify_zenodo_receipt(
                    _canonical_receipt(changed),
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    expected_deposition_id=DEPOSITION_ID,
                    expected_record_id=RECORD_ID,
                    expected_doi=DOI,
                    **fixture.verification_kwargs,
                )
            changed = deepcopy(receipt)
            changed["apiResponses"][2]["responseBody"]["sha256"] = "0" * 64  # type: ignore[index]
            with self.assertRaisesRegex(ZenodoArchiveError, "archived bytes differ"):
                verify_zenodo_receipt(
                    _canonical_receipt(changed),
                    manifest_path=fixture.manifest_path,
                    deposit_root=fixture.deposit,
                    expected_deposition_id=DEPOSITION_ID,
                    expected_record_id=RECORD_ID,
                    expected_doi=DOI,
                    **fixture.verification_kwargs,
                )


if __name__ == "__main__":
    unittest.main()
