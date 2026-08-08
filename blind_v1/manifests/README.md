# Generated provenance manifests (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

The abandoned design would have created generated receipts under the ignored
`blind_v1/.working/` directory:

- `asset-receipt.json` — exact local rehash of the six-revision confirmatory
  pool; it performs no model import or inference and becomes a frozen external
  design asset only after exact-commit verification;
- `development-asset-receipt.json` — reproducible local rehash of the three
  previously observed pilot revisions excluded from the confirmatory pool;
- `runtime-manifest.json` — complete byte inventory of the active venv and base
  Python plus package, lock, host, and Git identities;
- `cyclonedx-sbom.json` — deterministic CycloneDX component inventory derived
  from the two verified receipts.
- `freeze-manifest.json` — canonical two-stage implementation freeze binding
  the author-verified exact implementation commit, codec, runtime, full asset
  receipt, CA/trust material, explicit non-independent governance boundary, and
  exact successful CI run.

`development-model-assets.full-rehash.json` is tracked because it has no
source-commit self-reference. It commits one complete byte-for-byte rehash of
the 24 pilot files: 1,916,375,741 total bytes, including 1,906,255,408
safetensors bytes. It is development-control provenance only and cannot satisfy
the confirmatory-pool asset gate. The separate confirmatory receipt binds 18
files and 3,438,516,676 bytes, including 3,427,365,620 safetensors bytes, and is
frozen as an external design-release asset.

The ignored asset bytes are not redistributed. A fresh clone can reproduce
either receipt by selecting the matching immutable manifest and rerunning
`create_asset_receipt.py`. Mixing the pilot and confirmatory manifests or
receipts is a hard failure.

Runtime manifests cannot be committed into the same Git tree whose commit/tree
they bind. The frozen primary macOS arm64 runtime manifest is therefore an
external design-release asset whose hash enters the design and freeze manifest.
The Linux runtime manifest remains inside the exact Linux CI portability
artifact and is bound through that artifact and the GitHub gate; it is not a
second primary numerical runtime. Generated dirty-worktree development
manifests are never accepted.

No generated file becomes normative merely by existing. Under the abandoned
design, an author-verified freeze manifest would have bound exact receipt bytes
and hashes, and the subsequently frozen design would have bound the exact
freeze-manifest file SHA-256. The separately implemented software verifier
would have reconstructed both stages before one-shot execution; this would not
have constituted independent human validation.
