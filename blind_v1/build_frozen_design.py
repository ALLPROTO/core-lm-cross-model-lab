#!/usr/bin/env python3
"""Build the external, canonical blind-v1 frozen-design release asset.

The command is deliberately not a general JSON editor.  It reads the exact
tracked draft from the author-verified checkout and permits only the lifecycle and
artifact-binding changes accepted by :func:`blind_v1.runner.validate_frozen_design`.
It never creates an attempt, fetches a pulse, or runs model inference.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


BLIND_V1_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BLIND_V1_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from blind_v1.freeze_manifest import (  # noqa: E402
    CAVerifier,
    DevelopmentArchiveVerifier,
    DevelopmentControlVerifier,
    MAX_DESIGN_BYTES,
    TrustVerifier,
    default_ca_verifier,
    default_trust_verifier,
    load_freeze_manifest,
    read_regular_bytes,
    verify_artifact_inputs,
    verify_design_binding,
    verify_development_control_archive,
    verify_development_control_report,
    verify_frozen_nist_trust_bundle,
)
from blind_v1.protocol import (  # noqa: E402
    NIST_CANDIDATE_TRUST_BUNDLE_SHA256,
    NIST_FROZEN_TRUST_BUNDLE_SHA256,
    load_json_strict_bytes,
    validate_design_registration,
    validate_frozen_design_registration,
)
from blind_v1.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    write_new_bytes,
)
from blind_v1.runner import RunnerError, validate_frozen_design  # noqa: E402
from blind_v1.release_attestation_crypto import (  # noqa: E402
    PinnedCosignReleaseAttestationVerifier,
)
from blind_v1.release_receipt import (  # noqa: E402
    ReleaseAttestationCryptographicVerifier,
)


DRAFT_RELATIVE_PATH = "blind_v1/design-registration.draft.json"
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SSH_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
RELEASE_FIELDS = (
    "designRelease",
    "snapshotRelease",
    "reservationRelease",
    "evidenceRelease",
    "closeoutRelease",
)
ALLOWED_MUTATION_PATHS = {
    ("schemaVersion",),
    ("status",),
    ("readyToFreeze",),
    ("freezeBlockers",),
    ("developmentControls", "realDataE2EFreezeGate", "status"),
    ("developmentControls", "realDataE2EFreezeGate", "executionId"),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "archiveReceiptSHA256",
    ),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "archivePublishedAt",
    ),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "archiveAttestedAt",
    ),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "releaseAttestationBundleSHA256",
    ),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "releaseAttestationOutputSHA256",
    ),
    ("developmentControls", "realDataE2EFreezeGate", "reportSHA256"),
    ("developmentControls", "realDataE2EFreezeGate", "artifactSetSHA256"),
    (
        "developmentControls",
        "realDataE2EFreezeGate",
        "controlConfigurationSHA256",
    ),
    ("developmentControls", "realDataE2EFreezeGate", "completedAt"),
    ("labSource", "status"),
    ("labSource", "commit"),
    ("labSource", "tree"),
    ("labSource", "freezeManifestSHA256"),
    ("runtime", "status"),
    ("runtime", "runtimeManifestSHA256"),
    ("beacon", "transportCABundleSHA256"),
    ("beacon", "offlineTrustBundleSHA256"),
    ("beacon", "trustBundleStatus"),
}


class FrozenDesignBuildError(ValueError):
    """The author-verified checkout or a freeze binding is incomplete or mutable."""


NIST_TRUST_BLOCKER_REQUIRED_PHRASES = (
    "NIST Beacon signing certificate chain",
    "rotation/revocation policy",
    "not yet frozen",
)


def _git(root: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError):
            detail = error.stderr.decode("utf-8", "replace").strip()
        raise FrozenDesignBuildError(
            f"Git identity query failed{': ' + detail if detail else ''}"
        ) from error
    return completed.stdout


def _repository_slug(value: str) -> str:
    if value.startswith("https://github.com/"):
        slug = value[len("https://github.com/") :]
    elif value.startswith("git@github.com:"):
        slug = value[len("git@github.com:") :]
    else:
        raise FrozenDesignBuildError("lab origin is not a GitHub repository URL")
    slug = slug.rstrip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", slug):
        raise FrozenDesignBuildError("lab repository identity is invalid")
    return slug.casefold()


def _ensure_external_output(output: Path, lab_root: Path) -> None:
    destination = Path(os.path.abspath(os.fspath(output)))
    root = lab_root.resolve(strict=True)
    try:
        destination.relative_to(root)
    except ValueError:
        return
    raise FrozenDesignBuildError(
        "frozen design output must remain outside the author-verified implementation tree"
    )


def verify_author_verified_checkout(
    lab_root: Path,
    *,
    expected_repository: str,
    expected_commit: str,
    expected_tree: str,
    require_running_checkout: bool = True,
) -> tuple[dict[str, Any], bytes]:
    """Verify exact HEAD/tree, a clean worktree, and the tracked draft blob."""

    if GIT_OBJECT.fullmatch(expected_commit) is None:
        raise FrozenDesignBuildError("expected lab commit is not lowercase 40-hex")
    if GIT_OBJECT.fullmatch(expected_tree) is None:
        raise FrozenDesignBuildError("expected lab tree is not lowercase 40-hex")
    root = lab_root.resolve(strict=True)
    if require_running_checkout and root != PROJECT_ROOT.resolve(strict=True):
        raise FrozenDesignBuildError(
            "builder must execute from the exact author-verified lab checkout"
        )
    observed_commit = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).strip().decode()
    observed_tree = _git(root, ["rev-parse", "--verify", "HEAD^{tree}"]).strip().decode()
    if observed_commit != expected_commit:
        raise FrozenDesignBuildError("author-verified checkout commit differs")
    if observed_tree != expected_tree:
        raise FrozenDesignBuildError("author-verified checkout tree differs")
    origin = _git(root, ["remote", "get-url", "origin"]).strip().decode()
    if _repository_slug(origin) != _repository_slug(expected_repository):
        raise FrozenDesignBuildError("author-verified checkout origin differs")
    if _git(root, ["status", "--porcelain=v1", "--untracked-files=all"]):
        raise FrozenDesignBuildError("author-verified checkout is not clean")

    entry = _git(root, ["ls-tree", expected_commit, "--", DRAFT_RELATIVE_PATH])
    if not entry.startswith(b"100644 blob ") or not entry.endswith(
        b"\t" + DRAFT_RELATIVE_PATH.encode("ascii") + b"\n"
    ):
        raise FrozenDesignBuildError("tracked draft is not one regular Git blob")
    blob_raw = _git(root, ["cat-file", "blob", f"{expected_commit}:{DRAFT_RELATIVE_PATH}"])
    draft_path = root / DRAFT_RELATIVE_PATH
    draft_raw = read_regular_bytes(draft_path, maximum_bytes=MAX_DESIGN_BYTES)
    if draft_raw != blob_raw:
        raise FrozenDesignBuildError(
            "working draft bytes differ from author-verified Git blob"
        )
    try:
        draft = load_json_strict_bytes(draft_raw, label="tracked design draft")
        validate_design_registration(draft)
    except ValueError as error:
        raise FrozenDesignBuildError("tracked design draft is not normative") from error
    if not isinstance(draft, dict):
        raise FrozenDesignBuildError("tracked design draft must be an object")
    return draft, draft_raw


def _release_key_identity(path: Path) -> tuple[str, str]:
    raw = read_regular_bytes(path, maximum_bytes=1024 * 1024)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise FrozenDesignBuildError("release signing public key is not ASCII") from error
    if "\n" in text.rstrip("\n") or not text.endswith("\n"):
        raise FrozenDesignBuildError("release signing public key must be one LF-terminated line")
    parts = text.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise FrozenDesignBuildError("release signing public key is not one Ed25519 key")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise FrozenDesignBuildError("release signing public key base64 is invalid") from error
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode(
        "ascii"
    ).rstrip("=")
    if SSH_FINGERPRINT.fullmatch(fingerprint) is None:
        raise FrozenDesignBuildError("release signing key fingerprint is invalid")
    return fingerprint, sha256_bytes(raw)


def _verify_release_identity(draft: Mapping[str, Any], public_key_path: Path) -> None:
    fingerprint, public_key_sha256 = _release_key_identity(public_key_path)
    if SHA256.fullmatch(public_key_sha256) is None:
        raise FrozenDesignBuildError("release public-key file digest is invalid")
    for field in RELEASE_FIELDS:
        release = draft.get(field)
        if not isinstance(release, dict) or (
            release.get("signedAnnotatedTagRequired") is not True
            or release.get("signatureType") != "SSH"
            or release.get("signingKeyFingerprint") != fingerprint
            or release.get("signingPublicKeySHA256") != public_key_sha256
        ):
            raise FrozenDesignBuildError(f"tracked {field} release identity differs")


def _different_paths(left: Any, right: Any, prefix: tuple[Any, ...] = ()) -> set[tuple[Any, ...]]:
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        paths: set[tuple[Any, ...]] = set()
        for key in set(left) | set(right):
            if key not in left or key not in right:
                paths.add(prefix + (key,))
            else:
                paths.update(_different_paths(left[key], right[key], prefix + (key,)))
        return paths
    if isinstance(left, list):
        if len(left) != len(right):
            return {prefix}
        paths: set[tuple[Any, ...]] = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            paths.update(_different_paths(left_item, right_item, prefix + (index,)))
        return paths
    return set() if left == right else {prefix}


def assert_only_allowed_freeze_mutations(
    draft: Mapping[str, Any], frozen: Mapping[str, Any]
) -> None:
    unexpected = _different_paths(draft, frozen) - ALLOWED_MUTATION_PATHS
    if unexpected:
        rendered = ".".join(str(item) for item in sorted(unexpected, key=repr)[0])
        raise FrozenDesignBuildError(
            f"frozen design changed a non-lifecycle field: {rendered}"
        )


def require_nist_trust_blocker_discharge(
    draft: Mapping[str, Any],
    manifest: Mapping[str, Any],
    trust_manifest_path: Path,
) -> dict[str, Any]:
    """Re-open exact frozen trust and bind its proof to the tracked blocker."""

    blockers = draft.get("freezeBlockers")
    if not isinstance(blockers, list) or not blockers:
        raise FrozenDesignBuildError(
            "tracked design has no NIST trust blocker to discharge"
        )
    matches = [
        blocker
        for blocker in blockers
        if isinstance(blocker, str)
        and all(
            phrase in blocker for phrase in NIST_TRUST_BLOCKER_REQUIRED_PHRASES
        )
    ]
    if len(matches) != 1:
        raise FrozenDesignBuildError(
            "tracked design NIST trust blocker identity differs"
        )
    beacon = draft.get("beacon")
    if (
        not isinstance(beacon, Mapping)
        or beacon.get("trustBundleStatus")
        != "CANDIDATE_OFFLINE_TRUST_BUNDLE"
        or beacon.get("candidateOfflineTrustBundleSHA256")
        != NIST_CANDIDATE_TRUST_BUNDLE_SHA256
        or beacon.get("frozenOfflineTrustBundleSHA256")
        != NIST_FROZEN_TRUST_BUNDLE_SHA256
        or beacon.get("offlineTrustBundleSHA256")
        != NIST_CANDIDATE_TRUST_BUNDLE_SHA256
    ):
        raise FrozenDesignBuildError(
            "tracked design NIST trust lifecycle commitments differ"
        )
    try:
        expected_sha256 = manifest["artifacts"]["offlineTrustBundleSHA256"]
        if expected_sha256 != beacon["frozenOfflineTrustBundleSHA256"]:
            raise FrozenDesignBuildError(
                "freeze manifest NIST trust artifact is not the preregistered frozen bundle"
            )
        discharge = verify_frozen_nist_trust_bundle(
            trust_manifest_path, expected_sha256
        )
    except (KeyError, OSError, ValueError) as error:
        raise FrozenDesignBuildError(
            "NIST trust blocker lacks machine-verifiable discharge evidence"
        ) from error
    if (
        discharge.get("status")
        != "VERIFIED_FROZEN_NIST_TRUST_DISCHARGE"
        or discharge.get("manifestSHA256") != expected_sha256
        or discharge.get("candidateManifestSHA256")
        != NIST_CANDIDATE_TRUST_BUNDLE_SHA256
        or discharge.get("statusOnlyPromotionVerified") is not True
        or discharge.get("independentVerified") is not True
        or discharge.get("certificateChainVerified") is not True
        or discharge.get("leafEndEntityKeyUsageVerified") is not True
        or discharge.get("leafExtendedKeyUsageVerified") is not True
        or discharge.get("targetValidityVerified") is not True
        or discharge.get("revocationChecked") is not False
    ):
        raise FrozenDesignBuildError(
            "NIST trust blocker discharge evidence is incomplete"
        )
    return {
        **discharge,
        "draftFreezeBlockerSHA256": sha256_bytes(
            matches[0].encode("utf-8", errors="strict")
        ),
    }


def construct_frozen_design(
    draft: Mapping[str, Any],
    manifest: Mapping[str, Any],
    manifest_raw: bytes,
    *,
    trust_manifest_path: Path,
) -> dict[str, Any]:
    require_nist_trust_blocker_discharge(
        draft, manifest, trust_manifest_path
    )
    frozen = copy.deepcopy(dict(draft))
    frozen.update(
        schemaVersion="corelm-blind-crossmodel-v1-design-v1",
        status="PUBLIC_DESIGN_FROZEN",
        readyToFreeze=True,
        freezeBlockers=[],
    )
    frozen["labSource"].update(
        status="FROZEN_BOUND",
        commit=manifest["implementation"]["commit"],
        tree=manifest["implementation"]["tree"],
        freezeManifestSHA256=sha256_bytes(manifest_raw),
    )
    frozen["runtime"].update(
        status="FROZEN_BOUND",
        runtimeManifestSHA256=manifest["artifacts"]["runtimeManifestSHA256"],
    )
    frozen["developmentControls"]["realDataE2EFreezeGate"].update(
        status="ARCHIVED_VERIFIED_BEFORE_FREEZE",
        executionId=manifest["developmentControl"]["executionId"],
        archiveReceiptSHA256=manifest["artifacts"][
            "developmentControlArchiveReceiptSHA256"
        ],
        archivePublishedAt=manifest["developmentControl"]["archivePublishedAt"],
        archiveAttestedAt=manifest["developmentControl"]["archiveAttestedAt"],
        releaseAttestationBundleSHA256=manifest["artifacts"][
            "developmentControlReleaseAttestationBundleSHA256"
        ],
        releaseAttestationOutputSHA256=manifest["artifacts"][
            "developmentControlReleaseAttestationOutputSHA256"
        ],
        reportSHA256=manifest["artifacts"]["developmentControlReportSHA256"],
        artifactSetSHA256=manifest["artifacts"][
            "developmentControlArtifactSetSHA256"
        ],
        controlConfigurationSHA256=manifest["artifacts"][
            "developmentControlConfigurationSHA256"
        ],
        completedAt=manifest["developmentControl"]["completedAt"],
    )
    frozen["beacon"].update(
        trustBundleStatus="FROZEN_OFFLINE_TRUST_BUNDLE",
        transportCABundleSHA256=manifest["artifacts"]["transportCABundleSHA256"],
        offlineTrustBundleSHA256=manifest["artifacts"]["offlineTrustBundleSHA256"],
    )
    assert_only_allowed_freeze_mutations(draft, frozen)
    try:
        validate_frozen_design_registration(frozen)
        validate_frozen_design(frozen)
    except (ValueError, RunnerError) as error:
        raise FrozenDesignBuildError("constructed frozen design fails validation") from error
    return frozen


def build_frozen_design(
    *,
    lab_root: Path,
    expected_lab_commit: str,
    expected_lab_tree: str,
    expected_freeze_manifest_sha256: str,
    freeze_manifest_path: Path,
    runtime_manifest_path: Path,
    asset_receipt_path: Path,
    transport_ca_bundle_path: Path,
    offline_trust_manifest_path: Path,
    github_gate_receipt_path: Path,
    development_control_report_path: Path,
    development_control_artifact_root: Path,
    development_control_archive_receipt_path: Path,
    development_control_archive_asset_root: Path,
    signing_public_key_path: Path,
    output_path: Path,
    ca_verifier: CAVerifier = default_ca_verifier,
    trust_verifier: TrustVerifier = default_trust_verifier,
    development_control_verifier: DevelopmentControlVerifier = (
        verify_development_control_report
    ),
    development_archive_verifier: DevelopmentArchiveVerifier = (
        verify_development_control_archive
    ),
    cryptographic_attestation_verifier: (
        ReleaseAttestationCryptographicVerifier | None
    ) = None,
    require_running_checkout: bool = True,
) -> dict[str, Any]:
    """Re-open every freeze input and publish one new canonical design asset."""

    _ensure_external_output(output_path, lab_root)
    manifest, manifest_raw = load_freeze_manifest(freeze_manifest_path)
    observed_manifest_sha256 = sha256_bytes(manifest_raw)
    if SHA256.fullmatch(expected_freeze_manifest_sha256) is None:
        raise FrozenDesignBuildError("expected freeze-manifest hash is not lowercase SHA-256")
    if observed_manifest_sha256 != expected_freeze_manifest_sha256:
        raise FrozenDesignBuildError("freeze-manifest file SHA-256 differs")
    implementation = manifest["implementation"]
    if implementation["commit"] != expected_lab_commit:
        raise FrozenDesignBuildError("freeze manifest binds a different lab commit")
    if implementation["tree"] != expected_lab_tree:
        raise FrozenDesignBuildError("freeze manifest binds a different lab tree")

    draft, draft_raw = verify_author_verified_checkout(
        lab_root,
        expected_repository=implementation["repository"],
        expected_commit=expected_lab_commit,
        expected_tree=expected_lab_tree,
        require_running_checkout=require_running_checkout,
    )
    _verify_release_identity(draft, signing_public_key_path)
    artifact_report = verify_artifact_inputs(
        manifest,
        runtime_manifest_path=runtime_manifest_path,
        asset_receipt_path=asset_receipt_path,
        ca_bundle_path=transport_ca_bundle_path,
        trust_manifest_path=offline_trust_manifest_path,
        github_gate_receipt_path=github_gate_receipt_path,
        development_control_report_path=development_control_report_path,
        development_control_artifact_root=development_control_artifact_root,
        development_control_archive_receipt_path=(
            development_control_archive_receipt_path
        ),
        development_control_archive_asset_root=(
            development_control_archive_asset_root
        ),
        ca_verifier=ca_verifier,
        trust_verifier=trust_verifier,
        development_control_verifier=development_control_verifier,
        development_archive_verifier=development_archive_verifier,
        cryptographic_attestation_verifier=(
            cryptographic_attestation_verifier
        ),
    )
    # Recheck the source after the potentially long full runtime/asset reads.
    _draft_again, draft_raw_again = verify_author_verified_checkout(
        lab_root,
        expected_repository=implementation["repository"],
        expected_commit=expected_lab_commit,
        expected_tree=expected_lab_tree,
        require_running_checkout=require_running_checkout,
    )
    if draft_raw_again != draft_raw:
        raise FrozenDesignBuildError(
            "author-verified draft changed during freeze construction"
        )

    frozen = construct_frozen_design(
        draft,
        manifest,
        manifest_raw,
        trust_manifest_path=offline_trust_manifest_path,
    )
    output_raw = canonical_json_bytes(frozen) + b"\n"
    # Exercise the path-based stage-two verifier before publishing the output.
    with tempfile.TemporaryDirectory(prefix="corelm-frozen-design-check-") as temporary:
        # macOS exposes /var as a symlink to /private/var.  Resolve the
        # system-created temporary directory before passing it to the strict
        # no-symlink publisher; user-controlled output paths remain unresolved
        # and are checked component by component by write_new_bytes().
        provisional = Path(temporary).resolve() / "design-registration.json"
        write_new_bytes(provisional, output_raw)
        verify_design_binding(manifest, manifest_raw, provisional)
    write_new_bytes(output_path, output_raw)
    binding_report = verify_design_binding(manifest, manifest_raw, output_path)
    return {
        "status": "PUBLIC_DESIGN_FROZEN",
        "output": str(output_path),
        "bytes": len(output_raw),
        "sha256": sha256_bytes(output_raw),
        "freezeManifestSHA256": observed_manifest_sha256,
        "labCommit": expected_lab_commit,
        "labTree": expected_lab_tree,
        "artifactVerification": artifact_report,
        "designBinding": binding_report,
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-lab-commit", required=True)
    parser.add_argument("--expected-lab-tree", required=True)
    parser.add_argument("--expected-freeze-manifest-sha256", required=True)
    parser.add_argument("--freeze-manifest", type=Path, required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--asset-receipt", type=Path, required=True)
    parser.add_argument("--transport-ca-bundle", type=Path, required=True)
    parser.add_argument("--offline-trust-manifest", type=Path, required=True)
    parser.add_argument("--github-gate-receipt", type=Path, required=True)
    parser.add_argument("--development-control-report", type=Path, required=True)
    parser.add_argument(
        "--development-control-artifact-root", type=Path, required=True
    )
    parser.add_argument(
        "--development-control-archive-receipt", type=Path, required=True
    )
    parser.add_argument(
        "--development-control-archive-asset-root", type=Path, required=True
    )
    parser.add_argument("--signing-public-key", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        report = build_frozen_design(
            lab_root=PROJECT_ROOT,
            expected_lab_commit=arguments.expected_lab_commit,
            expected_lab_tree=arguments.expected_lab_tree,
            expected_freeze_manifest_sha256=arguments.expected_freeze_manifest_sha256,
            freeze_manifest_path=arguments.freeze_manifest,
            runtime_manifest_path=arguments.runtime_manifest,
            asset_receipt_path=arguments.asset_receipt,
            transport_ca_bundle_path=arguments.transport_ca_bundle,
            offline_trust_manifest_path=arguments.offline_trust_manifest,
            github_gate_receipt_path=arguments.github_gate_receipt,
            development_control_report_path=arguments.development_control_report,
            development_control_artifact_root=(
                arguments.development_control_artifact_root
            ),
            development_control_archive_receipt_path=(
                arguments.development_control_archive_receipt
            ),
            development_control_archive_asset_root=(
                arguments.development_control_archive_asset_root
            ),
            signing_public_key_path=arguments.signing_public_key,
            output_path=arguments.output,
            cryptographic_attestation_verifier=(
                PinnedCosignReleaseAttestationVerifier(arguments.cosign)
            ),
        )
    except (OSError, ValueError, KeyError) as error:
        print(f"FROZEN DESIGN BUILD FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
