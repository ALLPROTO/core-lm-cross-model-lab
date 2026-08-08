from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import blind_v1.reproducibility as reproducibility_module
from blind_v1.create_asset_receipt import (
    _historical_build_asset_receipt as build_asset_receipt,
)
from blind_v1.create_sbom import build_sbom
from blind_v1.reproducibility import (
    RUNTIME_ENVIRONMENT_KEYS,
    canonical_json_bytes,
    publish_new_path_exclusive,
    scan_tree,
    verify_content_digest,
    verify_runtime_manifest_integrity,
    with_content_digest,
    write_new_bytes,
)


class ReproducibilityTests(unittest.TestCase):
    @staticmethod
    def runtime_manifest_fixture() -> dict[str, object]:
        entries = [
            {
                "path": "bin/python3.12",
                "type": "file",
                "bytes": 7,
                "mode": "0755",
                "sha256": "a" * 64,
            }
        ]
        tree = {
            "entries": entries,
            "entryCount": 1,
            "regularFileBytes": 7,
            "treeSHA256": hashlib.sha256(canonical_json_bytes(entries)).hexdigest(),
        }
        clean_status = hashlib.sha256(b"").hexdigest()
        source = lambda origin, commit, git_tree: {
            "commit": commit,
            "tree": git_tree,
            "origin": origin,
            "worktreeClean": True,
            "worktreeStatusSHA256": clean_status,
        }
        return with_content_digest(
            {
                "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                "status": "COMPLETE_LOCAL_RUNTIME_BYTE_INVENTORY",
                "countsTowardScientificVerdict": False,
                "networkUsed": False,
                "modelInferenceUsed": False,
                "python": {
                    "registeredVersion": "3.12.10",
                    "version": "3.12.10",
                    "versionDetail": "3.12.10 (unit contract)",
                    "implementation": "CPython",
                    "cacheTag": "cpython-312",
                    "byteorder": "little",
                    "executable": {"bytes": 7, "mode": "0755", "sha256": "a" * 64},
                    "soabi": "cpython-312-darwin",
                    "multiarch": "darwin",
                    "platformTag": "macosx-15.0-arm64",
                },
                "host": {
                    "system": "Darwin",
                    "release": "unit-release",
                    "version": "unit-version",
                    "machine": "arm64",
                    "processor": "arm",
                    "macVersion": "15.0",
                },
                "environment": {
                    key: None for key in sorted(RUNTIME_ENVIRONMENT_KEYS)
                },
                "requirementsLocks": [
                    {"name": "requirements.lock", "bytes": 1, "sha256": "b" * 64}
                ],
                "installedDistributions": [
                    {
                        "name": "Fixture_Package",
                        "normalizedName": "fixture-package",
                        "version": "1.0",
                        "metadataSHA256": "c" * 64,
                        "recordSHA256": "d" * 64,
                        "declaredFiles": 3,
                        "licenseExpression": "MIT",
                        "licenseDeclared": None,
                        "requiresDist": [],
                    }
                ],
                "installedDistributionCount": 1,
                "runtimeTree": tree,
                "basePythonTree": copy.deepcopy(tree),
                "basePythonDistinctFromRuntime": False,
                "labSource": source(
                    "https://github.com/ALLPROTO/core-lm-cross-model-lab.git",
                    "1" * 40,
                    "2" * 40,
                ),
                "codecSource": source(
                    "https://github.com/ALLPROTO/core-lm-benchmark.git",
                    "3" * 40,
                    "4" * 40,
                ),
            }
        )

    def test_asset_receipt_rehashes_exact_bytes_without_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            assets = root / "assets"
            model_root = assets / "fixture-model"
            model_root.mkdir(parents=True)
            payload = b"fixture-safetensors-control"
            weight = model_root / "model.safetensors"
            weight.write_bytes(payload)
            manifest = {
                "schemaVersion": "corelm-blind-crossmodel-v1-model-assets-draft-v1",
                "completeRuntimeFileList": True,
                "models": {
                    "fixture-model": {
                        "repository": "fixture/model",
                        "revision": "a" * 40,
                        "license": "mit",
                        "licenseURL": "https://huggingface.co/fixture/model/tree/" + "a" * 40,
                        "files": {
                            "model.safetensors": {
                                "bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "digestSource": "fixture",
                            }
                        },
                    }
                },
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            receipt = build_asset_receipt(manifest_path, assets)
            verify_content_digest(receipt)
            self.assertTrue(receipt["fullSafetensorsBytesLocallyVerified"])
            self.assertEqual(receipt["totalBytes"], len(payload))
            self.assertNotIn(str(root), canonical_json_bytes(receipt).decode("utf-8"))

    def test_tree_inventory_binds_files_symlinks_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            target = root / "python3.12"
            target.write_bytes(b"registered-python-fixture")
            (root / "python").symlink_to("python3.12")
            first = scan_tree(root)
            second = scan_tree(root)
            self.assertEqual(first["treeSHA256"], second["treeSHA256"])
            self.assertEqual(first["entryCount"], 2)
            self.assertEqual(
                {item["type"] for item in first["entries"]}, {"file", "symlink"}
            )

    def test_tree_inventory_normalizes_registered_external_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            runtime = root / "runtime"
            base = root / "base"
            runtime.mkdir()
            base.mkdir()
            executable = base / "python3.12"
            executable.write_bytes(b"python")
            (runtime / "python").symlink_to(executable)
            inventory = scan_tree(
                runtime, external_roots={"base-python-root": base}
            )
            entry = inventory["entries"][0]
            self.assertEqual(entry["target"], "<base-python-root>/python3.12")
            self.assertNotIn(str(root), canonical_json_bytes(inventory).decode("utf-8"))

    def test_tree_inventory_accepts_internal_linux_lib64_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            library = root / "lib"
            library.mkdir()
            (library / "runtime.py").write_bytes(b"linux-venv-fixture")
            (root / "lib64").symlink_to("lib", target_is_directory=True)
            inventory = scan_tree(root)
            link = next(
                item for item in inventory["entries"] if item["path"] == "lib64"
            )
            self.assertEqual(
                link,
                {
                    "path": "lib64",
                    "type": "directory-symlink",
                    "target": "lib",
                    "resolvedDirectory": "lib",
                },
            )
            manifest = self.runtime_manifest_fixture()
            del manifest["contentSHA256"]
            manifest["runtimeTree"] = inventory
            manifest["basePythonTree"] = copy.deepcopy(inventory)
            verify_runtime_manifest_integrity(with_content_digest(manifest))

            forged = copy.deepcopy(manifest)
            for tree_name in ("runtimeTree", "basePythonTree"):
                forged_link = next(
                    item
                    for item in forged[tree_name]["entries"]
                    if item["path"] == "lib64"
                )
                forged_link["target"] = "../external"
                forged[tree_name]["treeSHA256"] = hashlib.sha256(
                    canonical_json_bytes(forged[tree_name]["entries"])
                ).hexdigest()
            with self.assertRaisesRegex(ValueError, "escapes the runtime tree"):
                verify_runtime_manifest_integrity(with_content_digest(forged))

    def test_tree_inventory_rejects_external_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve(strict=True)
            root = parent / "runtime"
            external = parent / "external"
            root.mkdir()
            external.mkdir()
            (root / "lib64").symlink_to("../external", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "escapes the runtime tree"):
                scan_tree(root)

    def test_tree_inventory_canonicalizes_only_parent_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            library = root / "lib"
            library.mkdir(parents=True)
            (library / "runtime.py").write_bytes(b"parent-symlink-fixture")
            (root / "lib64").symlink_to("lib", target_is_directory=True)
            inventory = scan_tree(root)
            self.assertEqual(
                next(
                    item
                    for item in inventory["entries"]
                    if item["path"] == "lib64"
                )["resolvedDirectory"],
                "lib",
            )
            link_root = root.parent / "runtime-link"
            link_root.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "non-symlink directory"):
                scan_tree(link_root)

    def test_self_digest_detects_mutation(self) -> None:
        value = with_content_digest({"schemaVersion": "fixture-v1", "value": 1})
        verify_content_digest(value)
        value["value"] = 2
        with self.assertRaisesRegex(ValueError, "self-digest mismatch"):
            verify_content_digest(value)

    def test_runtime_manifest_integrity_recomputes_tree_and_source_status(self) -> None:
        manifest = self.runtime_manifest_fixture()
        verify_runtime_manifest_integrity(manifest)

        forged_tree = copy.deepcopy(manifest)
        del forged_tree["contentSHA256"]
        forged_tree["runtimeTree"]["entries"][0]["bytes"] = 8
        forged_tree = with_content_digest(forged_tree)
        with self.assertRaisesRegex(ValueError, "regularFileBytes differs"):
            verify_runtime_manifest_integrity(forged_tree)

        forged_status = copy.deepcopy(manifest)
        del forged_status["contentSHA256"]
        forged_status["labSource"]["worktreeStatusSHA256"] = "e" * 64
        forged_status = with_content_digest(forged_status)
        with self.assertRaisesRegex(ValueError, "non-empty status digest"):
            verify_runtime_manifest_integrity(forged_status)

    def test_runtime_manifest_integrity_rejects_distribution_shape_forgery(self) -> None:
        manifest = self.runtime_manifest_fixture()
        del manifest["contentSHA256"]
        manifest["installedDistributions"][0]["declaredFiles"] = -1
        manifest = with_content_digest(manifest)
        with self.assertRaisesRegex(ValueError, "declaredFiles"):
            verify_runtime_manifest_integrity(manifest)

    def test_new_file_publication_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve(strict=True) / "receipt.json"
            write_new_bytes(destination, b"first\n")
            with self.assertRaises(FileExistsError):
                write_new_bytes(destination, b"second\n")
            self.assertEqual(destination.read_bytes(), b"first\n")

    def test_directory_fsync_failure_retains_complete_forensic_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve(strict=True) / "receipt.json"
            payload = b"complete-before-directory-fsync\n"
            with mock.patch.object(
                reproducibility_module,
                "_fsync_directory_descriptor",
                side_effect=OSError("unit directory fsync failure"),
            ), self.assertRaisesRegex(OSError, "directory fsync failure"):
                write_new_bytes(destination, payload)
            self.assertEqual(destination.read_bytes(), payload)
            with self.assertRaises(FileExistsError):
                write_new_bytes(destination, b"replacement-forbidden\n")

    def test_exclusive_path_publication_never_replaces_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "source.txt").write_bytes(b"source")
            (destination / "destination.txt").write_bytes(b"destination")
            with self.assertRaises(FileExistsError):
                publish_new_path_exclusive(source, destination)
            self.assertEqual((source / "source.txt").read_bytes(), b"source")
            self.assertEqual(
                (destination / "destination.txt").read_bytes(), b"destination"
            )

    def test_exclusive_path_publication_moves_new_directory_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            (source / "payload.txt").write_bytes(b"payload")
            publish_new_path_exclusive(source, destination)
            self.assertFalse(source.exists())
            self.assertEqual((destination / "payload.txt").read_bytes(), b"payload")

    def test_sbom_is_deterministic_and_binds_both_receipts(self) -> None:
        runtime = with_content_digest(
            {
                "schemaVersion": "corelm-blind-crossmodel-v1-runtime-manifest-v1",
                "python": {
                    "version": "3.12.10",
                    "soabi": "cpython-312-fixture",
                    "executable": {"bytes": 12345, "sha256": "a" * 64},
                },
                "runtimeTree": {"treeSHA256": "b" * 64},
                "basePythonTree": {"treeSHA256": "c" * 64},
                "labSource": {
                    "origin": "https://github.com/ALLPROTO/core-lm-cross-model-lab.git",
                    "commit": "d" * 40,
                    "tree": "e" * 40,
                    "worktreeClean": True,
                },
                "codecSource": {
                    "origin": "https://github.com/ALLPROTO/core-lm-benchmark.git",
                    "commit": "f" * 40,
                    "tree": "0" * 40,
                    "worktreeClean": True,
                },
                "installedDistributions": [
                    {
                        "name": "Fixture_Package",
                        "normalizedName": "fixture-package",
                        "version": "1.0",
                        "metadataSHA256": "1" * 64,
                        "recordSHA256": "2" * 64,
                        "licenseExpression": "MIT",
                        "licenseDeclared": None,
                        "requiresDist": [],
                    }
                ],
            }
        )
        assets = with_content_digest(
            {
                "schemaVersion": "corelm-blind-crossmodel-v1-asset-receipt-v1",
                "fullSafetensorsBytesLocallyVerified": True,
                "models": {
                    "fixture-model": {
                        "repository": "fixture/model",
                        "revision": "a" * 40,
                        "license": "mit",
                        "licenseURL": "https://huggingface.co/fixture/model",
                        "files": {
                            "model.safetensors": {
                                "bytes": 123,
                                "sha256": "3" * 64,
                            }
                        },
                    }
                },
            }
        )
        first = build_sbom(runtime, assets)
        second = build_sbom(runtime, assets)
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(
            first["$schema"], "http://cyclonedx.org/schema/bom-1.5.schema.json"
        )
        self.assertEqual(first["bomFormat"], "CycloneDX")
        self.assertEqual(first["specVersion"], "1.5")
        self.assertEqual(len(first["components"]), 4)
        self.assertTrue(first["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(len(first["dependencies"]), 5)


if __name__ == "__main__":
    unittest.main()
