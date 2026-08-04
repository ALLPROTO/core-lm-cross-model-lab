#!/usr/bin/env python3
"""Build a deterministic CycloneDX SBOM from verified v3 provenance receipts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


V3_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = V3_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from v3.protocol import load_json_strict  # noqa: E402
from v3.reproducibility import (  # noqa: E402
    canonical_json_bytes,
    sha256_bytes,
    verify_content_digest,
    write_new_bytes,
)


LICENSE_IDENTIFIERS = {
    "apache-2.0": {"license": {"id": "Apache-2.0"}},
    "mit": {"license": {"id": "MIT"}},
    "bigcode-openrail-m": {"license": {"name": "BigCode OpenRAIL-M"}},
}


def _pypi_purl(name: str, version: str) -> str:
    normalized = name.lower().replace("_", "-")
    return f"pkg:pypi/{urllib.parse.quote(normalized, safe='.-')}@{urllib.parse.quote(version, safe='.-+')}"


def _huggingface_purl(repository: str, revision: str) -> str:
    namespace, name = repository.split("/", 1)
    return (
        "pkg:huggingface/"
        + urllib.parse.quote(namespace, safe=".-")
        + "/"
        + urllib.parse.quote(name, safe=".-")
        + "@"
        + revision
    )


def _github_slug(repository: str) -> str:
    parsed = urllib.parse.urlsplit(repository)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ValueError("SBOM source repository is not an HTTPS GitHub URL")
    slug = parsed.path.strip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    if len(slug.split("/")) != 2:
        raise ValueError("SBOM GitHub source slug differs")
    return slug


def _git_component(
    source: dict[str, Any], *, name: str, component_type: str, license_id: str
) -> dict[str, Any]:
    slug = _github_slug(source["origin"])
    commit, tree = source["commit"], source["tree"]
    return {
        "type": component_type,
        "bom-ref": f"github:{slug}@{commit}",
        "name": name,
        "version": commit,
        "purl": f"pkg:github/{slug}@{commit}",
        "licenses": [{"license": {"id": license_id}}],
        "externalReferences": [
            {"type": "vcs", "url": f"https://github.com/{slug}/tree/{commit}"}
        ],
        "properties": [
            {"name": "corelm:git-tree", "value": tree},
            {
                "name": "corelm:worktree-clean-at-inventory",
                "value": str(source["worktreeClean"]).lower(),
            },
        ],
    }


def _requirement_name(value: str) -> str | None:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", value)
    return match.group(1).lower().replace("_", "-") if match else None


def build_sbom(runtime: dict[str, Any], assets: dict[str, Any]) -> dict[str, Any]:
    verify_content_digest(runtime)
    verify_content_digest(assets)
    if runtime.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-runtime-manifest-v1":
        raise ValueError("unexpected runtime manifest schema")
    if assets.get("schemaVersion") != "corelm-crossmodel-livewiki-v3-asset-receipt-v1":
        raise ValueError("unexpected asset receipt schema")
    if assets.get("fullSafetensorsBytesLocallyVerified") is not True:
        raise ValueError("SBOM requires a full verified asset receipt")

    required_runtime_fields = {"python", "runtimeTree", "basePythonTree", "labSource", "codecSource"}
    if not required_runtime_fields.issubset(runtime):
        raise ValueError("SBOM requires complete runtime and source provenance")

    lab_component = _git_component(
        runtime["labSource"],
        name="Core LM cross-model benchmark laboratory",
        component_type="application",
        license_id="MIT",
    )
    codec_component = _git_component(
        runtime["codecSource"],
        name="VoidToken codec",
        component_type="library",
        license_id="MIT",
    )
    python = runtime["python"]
    executable = python["executable"]
    python_component = {
        "type": "platform",
        "bom-ref": f"cpython:{python['version']}",
        "name": "CPython",
        "version": python["version"],
        "hashes": [{"alg": "SHA-256", "content": executable["sha256"]}],
        "licenses": [
            {"license": {"name": "Python Software Foundation License 2.0"}}
        ],
        "properties": [
            {"name": "corelm:python-executable-bytes", "value": str(executable["bytes"])},
            {"name": "corelm:runtime-tree-sha256", "value": runtime["runtimeTree"]["treeSHA256"]},
            {"name": "corelm:base-python-tree-sha256", "value": runtime["basePythonTree"]["treeSHA256"]},
            {"name": "corelm:python-soabi", "value": python.get("soabi") or "absent"},
        ],
    }
    components: list[dict[str, Any]] = [codec_component, python_component]
    package_refs: dict[str, str] = {}
    for package in runtime["installedDistributions"]:
        package_ref = f"pypi:{package['normalizedName']}@{package['version']}"
        package_refs[package["normalizedName"]] = package_ref
        component = {
                "type": "library",
                "bom-ref": package_ref,
                "name": package["name"],
                "version": package["version"],
                "purl": _pypi_purl(package["name"], package["version"]),
                "properties": [
                    {
                        "name": "corelm:distribution-metadata-sha256",
                        "value": package["metadataSHA256"] or "absent",
                    },
                    {
                        "name": "corelm:distribution-record-sha256",
                        "value": package["recordSHA256"] or "absent",
                    },
                ],
            }
        declared_license = package.get("licenseExpression") or package.get("licenseDeclared")
        component["licenses"] = [
            {"license": {"name": declared_license or "NOASSERTION"}}
        ]
        components.append(component)
    for model_key, model in assets["models"].items():
        weight = model["files"]["model.safetensors"]
        components.append(
            {
                "type": "machine-learning-model",
                "bom-ref": f"hf:{model['repository']}@{model['revision']}",
                "name": model_key,
                "version": model["revision"],
                "purl": _huggingface_purl(model["repository"], model["revision"]),
                "hashes": [{"alg": "SHA-256", "content": weight["sha256"]}],
                "licenses": [LICENSE_IDENTIFIERS[model["license"]]],
                "externalReferences": [
                    {"type": "license", "url": model["licenseURL"]}
                ],
                "properties": [
                    {
                        "name": "corelm:model-weight-bytes",
                        "value": str(weight["bytes"]),
                    },
                    {
                        "name": "corelm:complete-runtime-file-count",
                        "value": str(len(model["files"])),
                    },
                ],
            }
        )
    components.sort(key=lambda item: item["bom-ref"])

    dependencies: list[dict[str, Any]] = []
    model_refs = [
        f"hf:{model['repository']}@{model['revision']}"
        for model in assets["models"].values()
    ]
    dependencies.append(
        {
            "ref": lab_component["bom-ref"],
            "dependsOn": sorted(
                [codec_component["bom-ref"], python_component["bom-ref"], *package_refs.values(), *model_refs]
            ),
        }
    )
    dependencies.append({"ref": codec_component["bom-ref"], "dependsOn": []})
    dependencies.append({"ref": python_component["bom-ref"], "dependsOn": []})
    for package in runtime["installedDistributions"]:
        required = {
            package_refs[name]
            for raw in package.get("requiresDist", [])
            if (name := _requirement_name(raw)) in package_refs
        }
        dependencies.append(
            {"ref": package_refs[package["normalizedName"]], "dependsOn": sorted(required)}
        )
    dependencies.extend({"ref": ref, "dependsOn": []} for ref in model_refs)
    dependencies.sort(key=lambda item: item["ref"])

    provenance_digest = sha256_bytes(
        canonical_json_bytes(
            {
                "runtime": runtime["contentSHA256"],
                "assets": assets["contentSHA256"],
            }
        )
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, provenance_digest)}",
        "version": 1,
        "metadata": {
            "component": {
                **lab_component,
            },
            "properties": [
                {
                    "name": "corelm:runtime-manifest-content-sha256",
                    "value": runtime["contentSHA256"],
                },
                {
                    "name": "corelm:asset-receipt-content-sha256",
                    "value": assets["contentSHA256"],
                },
                {
                    "name": "corelm:counts-toward-scientific-verdict",
                    "value": "false",
                },
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--asset-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        runtime = load_json_strict(arguments.runtime_manifest)
        assets = load_json_strict(arguments.asset_receipt)
        sbom = build_sbom(runtime, assets)
        output_bytes = canonical_json_bytes(sbom) + b"\n"
        write_new_bytes(arguments.output, output_bytes)
    except (OSError, ValueError, KeyError) as error:
        print(f"SBOM FAIL: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "SBOM_CREATED",
                "output": str(arguments.output),
                "components": len(sbom["components"]),
                "fileBytes": len(output_bytes),
                "fileSHA256": sha256_bytes(output_bytes),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
