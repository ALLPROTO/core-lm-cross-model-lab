from __future__ import annotations

import hashlib
import base64
import re
import unittest
from pathlib import Path
from typing import Any

import yaml

from blind_v1.protocol import load_json_strict
from blind_v1.model_card_evidence import (
    ModelCardEvidenceError,
    validate_design_binding as validate_model_card_design_binding,
    verify_model_card_evidence_tree,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORCID = "0009-0000-7935-6090"
REPOSITORY = "https://github.com/ALLPROTO/core-lm-cross-model-lab"
LICENSE_COMMITMENT_SET_SHA256 = (
    "7d379029956e91c194e37ec09881c7b345e5637b2b480c14bd395941a0ce0306"
)
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)

EXPECTED_LICENSE_SOURCES = {
    "VoidToken codec source": {
        "repository": "ALLPROTO/core-lm-benchmark",
        "revision": "2e8d3b1591ee4a1ed822310f330317936871ff2b",
        "relativePath": "LICENSE",
        "archivedPath": "upstream/voidtoken-LICENSE",
        "archivedEncoding": "identity",
        "url": "https://raw.githubusercontent.com/ALLPROTO/core-lm-benchmark/2e8d3b1591ee4a1ed822310f330317936871ff2b/LICENSE",
        "bytes": 1072,
        "sha256": "aa536fc6b86f44c958fcff0ce9945304978fe45bc0da380a0519652f1c199155",
        "declaredLicense": "MIT",
    },
    "UD English PUD development corpus README": {
        "repository": "UniversalDependencies/UD_English-PUD",
        "revision": "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
        "relativePath": "README.md",
        "archivedPath": "upstream/ud-english-pud-r2.18-README.md",
        "archivedEncoding": "identity",
        "url": "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/e173a1be1b442faf34e7d5a502189ad5d9d1e197/README.md",
        "bytes": 6986,
        "sha256": "9558eb70a6565a40e2ecf06d0f38c9f6117de0f0f8bc5021805bdce51ee0d67f",
        "declaredLicense": "CC-BY-SA-3.0",
    },
    "UD English PUD development corpus license": {
        "repository": "UniversalDependencies/UD_English-PUD",
        "revision": "e173a1be1b442faf34e7d5a502189ad5d9d1e197",
        "relativePath": "LICENSE.txt",
        "archivedPath": "upstream/ud-english-pud-r2.18-LICENSE.txt",
        "archivedEncoding": "identity",
        "url": "https://raw.githubusercontent.com/UniversalDependencies/UD_English-PUD/e173a1be1b442faf34e7d5a502189ad5d9d1e197/LICENSE.txt",
        "bytes": 19556,
        "sha256": "b278eb53fe50b8bb7fa0d90fb8536c35fdcaa80f9d63812cb51db539555d2a89",
        "declaredLicense": "CC-BY-SA-3.0",
    },
    "GPT-Neo-125M model card": {
        "repository": "EleutherAI/gpt-neo-125m",
        "revision": "21def0189f5705e2521767faed922f1f15e7d7db",
        "relativePath": "README.md",
        "archivedPath": "upstream/gpt-neo-125m-README.md",
        "archivedEncoding": "identity",
        "url": "https://huggingface.co/EleutherAI/gpt-neo-125m/resolve/21def0189f5705e2521767faed922f1f15e7d7db/README.md",
        "bytes": 4100,
        "sha256": "c76aab9c03b38833cf58c4f30f6a2617b578106fb62f2e52bfc34bfb3d370fda",
        "declaredLicense": "mit",
    },
    "SmolLM2-360M model card": {
        "repository": "HuggingFaceTB/SmolLM2-360M",
        "revision": "f8027fd0eaeea54caa13c31d31b9fdc459c38b49",
        "relativePath": "README.md",
        "archivedPath": "upstream/smollm2-360m-README.md.base64",
        "archivedEncoding": "base64",
        "url": "https://huggingface.co/HuggingFaceTB/SmolLM2-360M/resolve/f8027fd0eaeea54caa13c31d31b9fdc459c38b49/README.md",
        "bytes": 6623,
        "sha256": "631f842e4a02262e07fc522ede86c816114541319dea53dbf86bac4539a24ac9",
        "declaredLicense": "apache-2.0",
    },
    "Tiny StarCoder Python model card": {
        "repository": "bigcode/tiny_starcoder_py",
        "revision": "8547527bef0bc927268c1653cce6948c5c242dd1",
        "relativePath": "README.md",
        "archivedPath": "upstream/tiny-starcoder-py-README.md",
        "archivedEncoding": "identity",
        "url": "https://huggingface.co/bigcode/tiny_starcoder_py/resolve/8547527bef0bc927268c1653cce6948c5c242dd1/README.md",
        "bytes": 2703,
        "sha256": "6bb27540fd61fe67452f66a2d7e26d8d047512ebffc13010abdfff263941eff6",
        "declaredLicense": "bigcode-openrail-m",
    },
    "BigCode OpenRAIL-M v1 full agreement source": {
        "repository": "bigcode/bigcode-model-license-agreement",
        "revision": "63da045c89345c6533561b3cd933dda4a1616ea8",
        "relativePath": "app.py",
        "archivedPath": "upstream/bigcode-openrail-m-v1-app.py",
        "archivedEncoding": "identity",
        "url": "https://huggingface.co/spaces/bigcode/bigcode-model-license-agreement/resolve/63da045c89345c6533561b3cd933dda4a1616ea8/app.py",
        "bytes": 14190,
        "sha256": "0d2ae47a5e9ec61b9e6b653e805e5318b07c3a194b4baa9e88fcc179efcf4874",
        "declaredLicense": "bigcode-openrail-m-v1-full-agreement-source",
    },
}


def orcid_check_character(orcid: str) -> str:
    digits = orcid.replace("-", "")
    if not re.fullmatch(r"[0-9]{15}[0-9X]", digits):
        raise ValueError("ORCID format is invalid")
    total = 0
    for character in digits[:-1]:
        total = (total + int(character)) * 2
    result = (12 - total % 11) % 11
    return "X" if result == 10 else str(result)


class ArchivalMetadataTests(unittest.TestCase):
    def test_citation_is_software_only_and_orcid_is_valid(self) -> None:
        citation_path = PROJECT_ROOT / "CITATION.cff"
        citation = yaml.safe_load(citation_path.read_text(encoding="utf-8"))
        self.assertIsInstance(citation, dict)
        self.assertEqual(citation["cff-version"], "1.2.0")
        self.assertEqual(citation["type"], "software")
        self.assertEqual(citation["license"], "MIT")
        self.assertEqual(citation["repository-code"], REPOSITORY)
        self.assertEqual(citation["url"], REPOSITORY)
        self.assertNotIn("doi", citation)
        self.assertNotIn("identifiers", citation)

        self.assertEqual(len(citation["authors"]), 1)
        author = citation["authors"][0]
        self.assertEqual(author["given-names"], "Ivan")
        self.assertEqual(author["family-names"], "Tyshchenko")
        self.assertEqual(author["orcid"], f"https://orcid.org/{ORCID}")
        self.assertEqual(orcid_check_character(ORCID), ORCID[-1])

        scoped_text = " ".join(
            str(citation[field]) for field in ("message", "abstract")
        ).lower()
        self.assertIn("software", scoped_text)
        self.assertNotIn("use this software or its evidence", scoped_text)
        self.assertIn("separate citation metadata", scoped_text)

    def test_notice_and_manual_archive_boundary_are_present(self) -> None:
        notice = (PROJECT_ROOT / "NOTICE.md").read_text(encoding="utf-8")
        for required in (
            "Copyright 2026 Ivan Tyshchenko",
            "root MIT `LICENSE`",
            "BigCode OpenRAIL-M",
            "UD English PUD r2.18",
            "CC BY-SA 3.0",
            "CycloneDX SBOM",
            "cli/cli",
            "DSSE/X.509/RFC3161",
            "LICENSES/ASSET_LICENSES.md",
            "Blind V1",
            "Pythia-160M",
            "blind_v1/model-assets.draft.json",
        ):
            self.assertIn(required, notice)
        self.assertNotIn("expires before the proposed pulse", notice)

        self.assertFalse((PROJECT_ROOT / ".zenodo.json").exists())
        workflow = (
            PROJECT_ROOT / ".github/workflows/blind-v1-development-controls.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn(".zenodo.json", workflow)

        archival = (PROJECT_ROOT / "blind_v1/ARCHIVAL.md").read_text(encoding="utf-8")
        self.assertIn("one manual Zenodo draft", archival)
        self.assertIn("manifested superset", archival)
        self.assertIn("multiple licenses/custom rights", archival)
        self.assertNotIn("exact same asset set to Zenodo", archival)

    def test_license_source_commitments_have_exact_offline_shape(self) -> None:
        evidence = load_json_strict(PROJECT_ROOT / "LICENSES/source-evidence.json")
        self.assertEqual(
            set(evidence), {"schemaVersion", "status", "retrievedAt", "sources"}
        )
        self.assertEqual(
            evidence["schemaVersion"],
            "corelm-crossmodel-livewiki-v2-license-source-evidence-v1",
        )
        self.assertEqual(evidence["status"], "PINNED_UPSTREAM_METADATA_BYTES_VERIFIED")
        self.assertRegex(evidence["retrievedAt"], UTC_SECOND)
        self.assertEqual(len(evidence["sources"]), 7)
        self.assertEqual(len(evidence["sources"]), len(EXPECTED_LICENSE_SOURCES))

        observed: dict[str, dict[str, Any]] = {}
        urls: set[str] = set()
        for source in evidence["sources"]:
            self.assertEqual(
                set(source),
                {
                    "component",
                    "repository",
                    "revision",
                    "relativePath",
                    "archivedPath",
                    "archivedEncoding",
                    "url",
                    "bytes",
                    "sha256",
                    "declaredLicense",
                },
            )
            component = source["component"]
            self.assertNotIn(component, observed)
            self.assertRegex(source["revision"], HEX_40)
            self.assertRegex(source["sha256"], HEX_64)
            self.assertIs(type(source["bytes"]), int)
            self.assertGreater(source["bytes"], 0)
            self.assertTrue(source["url"].startswith("https://"))
            self.assertNotIn(source["url"], urls)
            urls.add(source["url"])

            expected = EXPECTED_LICENSE_SOURCES[component]
            self.assertEqual(
                {key: source[key] for key in expected},
                expected,
            )
            archived = PROJECT_ROOT / "LICENSES" / source["archivedPath"]
            archived_bytes = archived.read_bytes()
            if source["archivedEncoding"] == "base64":
                archived_bytes = base64.b64decode(
                    b"".join(archived_bytes.split()), validate=True
                )
            else:
                self.assertEqual(source["archivedEncoding"], "identity")
            self.assertEqual(len(archived_bytes), source["bytes"])
            self.assertEqual(hashlib.sha256(archived_bytes).hexdigest(), source["sha256"])
            observed[component] = source
        self.assertEqual(set(observed), set(EXPECTED_LICENSE_SOURCES))
        self.assertNotIn("WikiText development dataset card", observed)

        matrix = (PROJECT_ROOT / "LICENSES/ASSET_LICENSES.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("| VoidToken codec source |", matrix)
        self.assertIn("| UD English PUD r2.18 development corpus |", matrix)
        self.assertIn("| MIT | No |", matrix)
        for source in evidence["sources"]:
            self.assertIn(source["revision"], matrix)

        confirmatory = load_json_strict(
            PROJECT_ROOT / "blind_v1/model-assets.draft.json"
        )
        self.assertEqual(len(confirmatory["models"]), 6)
        for model in confirmatory["models"].values():
            self.assertIn(model["repository"], matrix)
            self.assertIn(model["revision"], matrix)
            self.assertIn(model["licenseURL"], matrix)
        self.assertIn("blind_v1/trust/", matrix)
        self.assertIn("2026-08-21T18:00:00.000Z", matrix)
        self.assertNotIn("expires before the proposed pulse", matrix)

        # The file commits upstream bytes; this offline test never fetches them.
        commitment_digest = hashlib.sha256(
            "".join(sorted(source["sha256"] for source in evidence["sources"])).encode(
                "ascii"
            )
        ).hexdigest()
        self.assertEqual(commitment_digest, LICENSE_COMMITMENT_SET_SHA256)

    def test_blind_v1_model_cards_are_offline_and_cross_bound(self) -> None:
        design = load_json_strict(
            PROJECT_ROOT / "blind_v1/design-registration.draft.json"
        )
        summary = verify_model_card_evidence_tree(PROJECT_ROOT, design["models"])
        validate_model_card_design_binding(design["modelCardEvidence"], summary)
        self.assertEqual(summary["status"], "VERIFIED_EXACT_MODEL_CARD_EVIDENCE")
        self.assertEqual(summary["manifestBytes"], 3421)
        self.assertEqual(
            summary["manifestSHA256"],
            "fcee9ffcc88b6fef26d092c29214fd43125f77ee6c1bca9894eedb5cb15bee23",
        )
        self.assertEqual(summary["cardCount"], 6)
        self.assertEqual(summary["totalDecodedCardBytes"], 57703)
        self.assertFalse(summary["weightsRedistributed"])
        self.assertEqual(
            [card["modelKey"] for card in summary["cards"]],
            [model["key"] for model in design["models"]],
        )
        self.assertEqual(
            {card["declaredLicense"] for card in summary["cards"]},
            {"apache-2.0", "mit"},
        )

        manifest_path = PROJECT_ROOT / design["modelCardEvidence"]["path"]
        tampered = bytearray(manifest_path.read_bytes())
        tampered[-2] ^= 1
        with self.assertRaises(ModelCardEvidenceError):
            from blind_v1.model_card_evidence import validate_model_card_evidence_bytes

            validate_model_card_evidence_bytes(
                bytes(tampered), {}, design["models"]
            )


if __name__ == "__main__":
    unittest.main()
