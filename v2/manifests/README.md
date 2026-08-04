# Generated provenance manifests

Development receipts are generated under the ignored `v2/.working/` directory:

- `asset-receipt.json` — exact local rehash of all registered model assets;
- `runtime-manifest.json` — complete byte inventory of the active venv and base
  Python plus package, lock, host, and Git identities;
- `cyclonedx-sbom.json` — deterministic CycloneDX component inventory derived
  from the two verified receipts.
- `freeze-manifest.json` — canonical two-stage implementation freeze binding
  the reviewed/green implementation commit, codec, runtime, full asset receipt,
  CA/trust material, approved review identity, and exact successful CI run.

`model-assets.full-rehash.json` is tracked because it has no source-commit
self-reference. It commits one complete byte-for-byte rehash of all 24
registered files on this Mac and matches three retained local receipts:
1,916,375,741 total bytes, including 1,906,255,408 safetensors bytes. Its file
SHA-256 is
`0e57aa43f52569cf6910a248ee2ad4ee36dcf73d7c8ce9f33a4f50f738d5f5c2`.
The ignored asset bytes are not redistributed; a fresh clone can reproduce the
receipt by downloading the immutable revisions and rerunning
`create_asset_receipt.py`.

Runtime manifests cannot be committed into the same Git tree whose commit/tree
they bind. The final clean macOS and Linux manifests are therefore immutable
design-release/CI assets. Their hashes enter the frozen design and freeze
manifest; generated dirty-worktree development manifests are never accepted.

No generated file becomes normative merely by existing. The eventual reviewed
freeze manifest must bind exact receipt bytes and hashes, and the subsequently
frozen design must bind the exact freeze-manifest file SHA-256. An independent
verifier must reconstruct both stages before one-shot execution.
