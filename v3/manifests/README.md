# Generated provenance manifests

Development receipts are generated under the ignored `v3/.working/` directory:

- `asset-receipt.json` — exact local rehash of all registered model assets;
- `runtime-manifest.json` — complete byte inventory of the active venv and base
  Python plus package, lock, host, and Git identities;
- `cyclonedx-sbom.json` — deterministic CycloneDX component inventory derived
  from the two verified receipts.
- `freeze-manifest.json` — canonical two-stage implementation freeze binding
  the author-verified exact implementation commit, codec, runtime, full asset
  receipt, CA/trust material, explicit non-independent governance boundary, and
  exact successful CI run.

`model-assets.full-rehash.json` is tracked because it has no source-commit
self-reference. It commits one complete byte-for-byte rehash of all 24
registered files on this Mac and matches three retained local receipts:
1,916,375,741 total bytes, including 1,906,255,408 safetensors bytes. Its file
SHA-256 is
`a576fd188afd9ace4368c2bc30fd0bbf90492741efa342a847a5805147333d2b`.
The ignored asset bytes are not redistributed; a fresh clone can reproduce the
receipt by downloading the immutable revisions and rerunning
`create_asset_receipt.py`.

Runtime manifests cannot be committed into the same Git tree whose commit/tree
they bind. The final clean macOS and Linux manifests are therefore immutable
design-release/CI assets. Their hashes enter the frozen design and freeze
manifest; generated dirty-worktree development manifests are never accepted.

No generated file becomes normative merely by existing. The eventual author-verified
freeze manifest must bind exact receipt bytes and hashes, and the subsequently
frozen design must bind the exact freeze-manifest file SHA-256. The separately
implemented software verifier must reconstruct both stages before one-shot
execution; this is not independent human validation.
