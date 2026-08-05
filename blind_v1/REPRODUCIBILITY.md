# Blind cross-model v1 author-self-verified clean-clone reproducibility

This document covers development controls, static confirmatory-asset
preparation, and provenance preparation only. It does not authorize the
scientific one-shot, collect the future corpus, fetch a NIST pulse, create an
attempt marker, or run inference on any of the six confirmatory revisions.

The repository owner is the author, experiment operator, and release operator.
No independent human review, peer review, operator blindness, or independent
replication is claimed. “Independent verifier” below means a separately
implemented verification path inside the same author-controlled artifact, not
an external person or organization.

The six exact confirmatory revisions have not been run in this project, but
their GPT-2, GPT-NeoX/Pythia, and Llama architecture families have prior
observations disclosed in `prior-observations.json`. Reproduction of the
development controls therefore establishes implementation readiness only. It
does not establish universal LLM generalization or the future exact-sample
claim.

## Required capacity

- Python: exactly 3.12.10.
- Excluded pilot model/tokenizer assets: 24 files and 1,916,375,741 bytes,
  including 1,906,255,408 bytes of safetensors weights.
- Six-revision confirmatory pool: 18 files and 3,438,516,676 bytes, including
  3,427,365,620 bytes of safetensors weights. Static acquisition and hashing are
  allowed; model import, cache generation, forward passes, and candidate
  scoring are not.
- Development runtime: approximately 1 GB on one platform.
- Free disk before the full real-model control: at least 12 GiB.
- The full real-model control requires macOS arm64, AC power, and at least 50%
  free physical memory at startup and before every producer/replay child.
  Passing it still does not prove the future-corpus one-shot result.

## Start from exact source identities

Never reproduce a frozen design from a moving branch. The signed annotated
design tag must point directly to the exact implementation commit that received
the archived author-self-verification record and green zero-skip CI. There is
no separate, later publication
commit. The frozen design JSON, freeze manifest, and provenance records are
immutable release assets generated outside that tagged tree.

Replace `<IMPLEMENTATION_COMMIT>` and `<IMPLEMENTATION_TREE>` below with
`labSource.commit` and `labSource.tree` from the frozen design asset. Independently
verify that the signed design tag and canonical publication receipt resolve to
that same pair.

```sh
git clone https://github.com/ALLPROTO/core-lm-cross-model-lab.git lab
git -C lab fetch origin tag corelm-blind-crossmodel-v1-design
test "$(git -C lab rev-list -n 1 corelm-blind-crossmodel-v1-design)" = \
  <IMPLEMENTATION_COMMIT>
git -C lab checkout --detach <IMPLEMENTATION_COMMIT>
test "$(git -C lab rev-parse 'HEAD^{tree}')" = <IMPLEMENTATION_TREE>

git clone https://github.com/ALLPROTO/core-lm-benchmark.git codec-source
git -C codec-source checkout --detach 2e8d3b1591ee4a1ed822310f330317936871ff2b
test "$(git -C codec-source rev-parse 'HEAD^{tree}')" = \
  c0bb15784d252cd5036757bc64765c773a5f16e8
```

The current development branch is not a substitute for the tagged
`<IMPLEMENTATION_COMMIT>`.

## Build only the locked runtime

The helper consumes locks from the exact codec tree and deliberately does not
download the older Qwen/WikiText assets used by the root regression.

Linux x86-64:

```sh
cd lab
RUNTIME_ROOT="$PWD/blind_v1/.runtime/linux"
./blind_v1/bootstrap_runtime.sh \
  --platform linux \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$(command -v python3.12)"
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/run_zero_skip_tests.py
```

macOS Apple Silicon:

```sh
cd lab
RUNTIME_ROOT="$PWD/blind_v1/.runtime/macos"
./blind_v1/bootstrap_runtime.sh \
  --platform macos \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$(command -v python3.12)"
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/run_zero_skip_tests.py
```

The runtime destination must not already exist. This prevents a stale package
from being silently reused. The zero-skip runner fails if NumPy, Torch, or
Transformers controls are unavailable.

`bootstrap_runtime.sh` does not download or trust an interpreter implicitly: a
local reproducer must supply an exact Python 3.12.10 executable, and the helper
rejects every other patch version. The tracked CI is the portable canonical
construction path: it uses the commit-pinned `actions/setup-python` action for
3.12.10 and then inventories the complete resulting runtime bytes. For a local
freeze-quality run, archive the provenance of the supplied interpreter and bind
its executable plus base/runtime trees in the generated runtime manifest; a
matching version string alone is not an equivalence claim.

The scientific supervisor must invoke the exact absolute
`$RUNTIME_ROOT/bin/python` launcher without resolving its virtual-environment
symlink to the base interpreter. `verify_scientific_python_subprocess` now
starts a disposable child with the frozen flags and closed environment, imports
all inference dependencies, and verifies the exact package versions and venv
identity. This is a mandatory regression gate for the worker-launch boundary,
not a substitute for the complete real-model readiness control.

## Materialize and rehash pilot and confirmatory assets separately

The model files retain their upstream licenses and are intentionally ignored by
Git. The two manifests have different scientific roles and must never share a
receipt identity, even when their non-overlapping model directories live under
the same local asset root.

The license fields and revision pages are not the sole offline evidence. The
separate
[`../LICENSES/blind-v1-model-card-evidence.json`](../LICENSES/blind-v1-model-card-evidence.json)
binds all six exact upstream README bytes and is cross-bound to the ordered
frozen model pool. The six revision trees expose no standalone `LICENSE*` or
`NOTICE*` file. The evidence therefore preserves the exact model-card
declarations and does not represent a generic Apache or MIT text as a file from
those revisions.

First acquire and rehash the six confirmatory revisions without importing or
executing them:

```sh
python3 blind_v1/fetch_assets.py \
  --manifest blind_v1/model-assets.draft.json \
  --destination blind_v1/.assets
mkdir -p blind_v1/.working
python3 blind_v1/create_asset_receipt.py \
  --manifest blind_v1/model-assets.draft.json \
  --asset-root blind_v1/.assets \
  --output blind_v1/.working/asset-receipt.json
python3 blind_v1/verify_model_weight_layouts.py \
  --asset-root blind_v1/.assets
```

That 18-file output is the proposed confirmatory `full-asset-receipt`. Freeze
must bind its exact canonical bytes. It is not a development-control receipt,
and generating it does not authorize inference.

The last command deterministically re-derives
`blind_v1/model-weight-layouts.json` from the exact downloaded configs and the
six safetensors JSON headers. For each weight file it reads only the 8-byte
length prefix and the declared header, stops before the tensor payload, and
reports `tensorPayloadBytesRead: 0`, `modelInferenceUsed: false`, and
`networkUsed: false`. Full-file weight hashes come from the separately
full-rehashed asset manifest and receipt; the header verifier does not pretend
to recompute them. A clean clone without model assets still runs the tracked
fixture known-answer tests and both independently implemented key transforms;
with `.assets` present, the same zero-skip suite additionally compares all six
local headers byte-for-byte with the design-bound fixture.

Then acquire the three previously observed, excluded pilot revisions and the
real development corpus:

```sh
python3 blind_v1/fetch_assets.py \
  --manifest blind_v1/development-model-assets.json \
  --destination blind_v1/.assets \
  --include-development-dataset
python3 blind_v1/create_asset_receipt.py \
  --manifest blind_v1/development-model-assets.json \
  --asset-root blind_v1/.assets \
  --output blind_v1/.working/development-asset-receipt.json
cmp blind_v1/.working/development-asset-receipt.json \
  blind_v1/manifests/development-model-assets.full-rehash.json
```

The same standard-library downloader writes the byte-pinned real-data input to
`blind_v1/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`. It verifies commit
`e173a1be1b442faf34e7d5a502189ad5d9d1e197`, the 1,386,858-byte length, and
SHA-256 `c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa`
before atomic no-overwrite publication. Corpus decoding uses the project's
strict standard-library CoNLL-U parser and needs no dataset framework.

`create_asset_receipt.py` performs no model import or inference. The tracked
pilot receipt
`blind_v1/manifests/development-model-assets.full-rehash.json` binds the 24
pilot files and must compare byte-for-byte equal to the regenerated pilot
output. It cannot satisfy the confirmatory-pool receipt gate. Conversely, the
confirmatory receipt cannot be used by the pilot E2E.

## Create runtime inventory and SBOM

Run the manifest generator with the interpreter it is inventorying. The final
freeze must use `--require-clean-git`; the command below omits it only while the
development branch contains uncommitted implementation work.

Linux:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/create_runtime_manifest.py \
  --runtime-root "$RUNTIME_ROOT" \
  --requirements-lock ../codec-source/.github/locks/pip-bootstrap.txt \
  --requirements-lock ../codec-source/.github/locks/real-llm-linux-cpu-py312.txt \
  --requirements-lock ../codec-source/.github/locks/torch-linux-cpu-py312.txt \
  --codec-root ../codec-source \
  --output blind_v1/.working/runtime-manifest.json
```

For macOS replace the last two platform locks with:

```text
--requirements-lock ../codec-source/RealLLM/requirements.lock
```

Then generate the deterministic CycloneDX inventory:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/create_sbom.py \
  --runtime-manifest blind_v1/.working/runtime-manifest.json \
  --asset-receipt blind_v1/.working/asset-receipt.json \
  --output blind_v1/.working/cyclonedx-sbom.json
```

All three outputs remain ignored development artifacts until an
author-self-verified freeze
manifest binds their exact hashes. They do not count toward the scientific
verdict.

## Reproduce the archival verification boundary

Manifest creation, read-only receipt collection, and independent receipt replay
all require the platform's byte-pinned Cosign 3.0.6 executable. The manifest
builder and verifier rerun the complete canonical GitHub release-receipt check
over the deposited `github-assets/`: tracked SSH trust verifies the annotated
tag, then Cosign independently replays the archived DSSE/X.509/RFC3161 bundle.
For example:

```sh
"$RUNTIME_ROOT/bin/python" -B -m blind_v1.create_zenodo_deposit_manifest \
  --deposit-root /path/to/exact-payload-root \
  --plan /path/to/exact-plan.json \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output /path/outside-payload/zenodo-deposit-manifest.json

"$RUNTIME_ROOT/bin/python" -B -m blind_v1.verify_zenodo_receipt \
  --receipt /path/to/zenodo-receipt.json \
  --manifest /path/outside-payload/zenodo-deposit-manifest.json \
  --deposit-root /path/to/exact-payload-root \
  --deposition-id '<production-deposition-id>' \
  --record-id '<production-record-id>' \
  --doi '10.5281/zenodo.<production-record-id>' \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6
```

The Zenodo receipt's exact `evidenceBoundary` is
`DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_ZENODO_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`.
The collector validates direct hostname-checked TLS while connected, but Zenodo
does not sign the archived HTTP bodies or headers. Offline replay therefore
checks their internal structure and agreement with local manifested bytes; it
does not authenticate Zenodo origin or make the captured `Date` header an
authoritative server timestamp. See [`ARCHIVAL.md`](ARCHIVAL.md) for the
read-only collection command and deposit procedure.

## Two-stage implementation freeze

The implementation tree cannot contain a future freeze manifest that commits
that same tree and cannot contain the final frozen design asset that commits the
future manifest bytes. The freeze therefore has two artifact-construction
stages but only one Git source identity:

1. Complete the tracked author self-verification and obtain green zero-skip CI
   for one exact implementation commit.
   Generate the clean runtime manifest from that commit and do not change any
   implementation byte afterward.
2. Generate `freeze-manifest.json` outside the implementation tree, then put
   the SHA-256 of its exact canonical bytes into the frozen design field
   `labSource.freezeManifestSHA256`. Keep both files outside the Git tree and
   package them as immutable release assets. Create the signed annotated design
   tag with the exact stage-one implementation commit as its target. Do not
   create or use a later publication commit. Any implementation change requires
   a new commit, author self-verification, CI run, runtime manifest, and freeze
   manifest.

The generator requires the author-self-verification policy and successful
Actions run to bind the same exact implementation commit. The CI claims come
only from a canonical direct-TLS GitHub CI-only observation produced as described
in [`GITHUB_GATE_RECEIPTS.md`](GITHUB_GATE_RECEIPTS.md), never from
operator-entered CI strings. The collector archives exactly four API responses
(PR, workflow run, all jobs, and artifacts), never calls the reviews endpoint,
and contains no reviewer, review approval, or review declaration. Its separate
canonical author self-declaration and `NO_INDEPENDENT_HUMAN_REVIEW` boundary
remain mandatory. Its required
`evidenceBoundary` makes clear
that GitHub did not sign the archived responses and offline verification proves
only structural consistency, not their origin. It independently reopens the
runtime manifest, full asset receipt, pinned transport CA bundle, and normative
offline NIST trust bundle. Fixture trust, dirty source identities, mutable or
noncanonical receipts, mismatched commits, and non-success CI all fail closed.
Both `create` and `verify` first inspect the live Git checkout itself: canonical
`origin`, `HEAD` commit/tree, every tracked change, and every non-ignored
untracked path must match the frozen lab identity. Ignored runtime/release
artifacts are permitted; the verifier does not rely on a curated source-file
list and rejects index flags that could conceal tracked changes.

First promote the exact tracked NIST candidate into a new external,
self-contained frozen bundle. This deterministic offline step changes only the
manifest status: candidate SHA-256
`cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`
becomes the exact 1,930-byte frozen SHA-256
`5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`.
The tool verifies both states with the producer and independent implementations,
copies every committed certificate byte, never overwrites, and performs no
network request, pulse fetch, or inference:

```sh
"$RUNTIME_ROOT/bin/python" -I -B \
  blind_v1/build_frozen_nist_trust_bundle.py \
  --output-root /external/frozen-nist-trust
```

Every following freeze command uses that external frozen manifest. The tracked
candidate is intentionally rejected on freeze/scientific paths.
The design's `candidateOfflineTrustBundleSHA256` and
`frozenOfflineTrustBundleSHA256` remain fixed across lifecycle states;
construction changes only `trustBundleStatus` from candidate to frozen and the
active `offlineTrustBundleSHA256` from the candidate hash to the exact frozen
hash.

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/freeze_manifest.py create \
  --runtime-manifest blind_v1/.working/runtime-manifest.json \
  --asset-receipt blind_v1/.working/asset-receipt.json \
  --transport-ca-bundle blind_v1/trust/transport-ca.pem \
  --offline-trust-manifest /external/frozen-nist-trust/manifest.json \
  --github-gate-receipt /path/to/github-gate-receipt.json \
  --development-control-report /path/to/development-control-report.json \
  --development-control-artifact-root /path/to/development-control \
  --development-control-archive-receipt /path/to/development-control-archive-receipt.json \
  --development-control-archive-asset-root /path/to/downloaded-development-assets \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --lab-repository https://github.com/ALLPROTO/core-lm-cross-model-lab.git \
  --lab-commit "$IMPLEMENTATION_COMMIT" \
  --lab-tree "$IMPLEMENTATION_TREE" \
  --codec-repository https://github.com/ALLPROTO/core-lm-benchmark.git \
  --codec-commit 2e8d3b1591ee4a1ed822310f330317936871ff2b \
  --codec-tree c0bb15784d252cd5036757bc64765c773a5f16e8 \
  --output /external/freeze-manifest.json
```

The production CLI derives `createdAt` from whole-second system UTC at the
moment it builds the manifest; it does not accept an operator-supplied
timestamp.

The command prints two different digests. `contentSHA256` is the manifest's
self-digest over the payload with that field omitted. `freezeManifestSHA256`
is SHA-256 over the complete canonical JSON, including `contentSHA256` and the
terminal LF; this second value is the one stored in the frozen design.

Do not edit a copy of the draft by hand. From the same clean, detached exact
implementation
checkout, use the bounded builder below. The output path must be outside the
lab Git tree. The builder reopens the tracked draft blob, exact HEAD/tree,
clean runtime and asset receipts, GitHub CI-only gate, CA and NIST trust
bytes, and the preregistered signing public key. It permits only the lifecycle
bindings accepted by the scientific runner, creates canonical JSON plus one
terminal LF without overwrite, and immediately runs both the normative frozen
design validator and the two-stage freeze-manifest binding verifier.

```sh
FREEZE_MANIFEST_SHA256=$(shasum -a 256 \
  /external/freeze-manifest.json | awk '{print $1}')

"$RUNTIME_ROOT/bin/python" -I -B blind_v1/build_frozen_design.py \
  --expected-lab-commit "$IMPLEMENTATION_COMMIT" \
  --expected-lab-tree "$IMPLEMENTATION_TREE" \
  --expected-freeze-manifest-sha256 "$FREEZE_MANIFEST_SHA256" \
  --freeze-manifest /external/freeze-manifest.json \
  --runtime-manifest blind_v1/.working/runtime-manifest.json \
  --asset-receipt blind_v1/.working/asset-receipt.json \
  --transport-ca-bundle blind_v1/trust/transport-ca.pem \
  --offline-trust-manifest /external/frozen-nist-trust/manifest.json \
  --github-gate-receipt /external/github-gate-receipt.json \
  --development-control-report /external/development-control-report.json \
  --development-control-artifact-root /external/development-control \
  --development-control-archive-receipt /external/development-control-archive-receipt.json \
  --development-control-archive-asset-root /external/downloaded-development-assets \
  --signing-public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output /external/design-registration.json
```

Any wrong commit, tree, manifest or artifact hash, dirty tracked draft, changed
release key, non-success/foreign GitHub gate, late freeze manifest, or existing
output fails before a frozen asset can be published.

After creating the frozen design, use the separate implementation verifier to
re-open every input and verify
the stage-two binding:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/freeze_manifest.py verify \
  --manifest /external/freeze-manifest.json \
  --runtime-manifest blind_v1/.working/runtime-manifest.json \
  --asset-receipt blind_v1/.working/asset-receipt.json \
  --transport-ca-bundle blind_v1/trust/transport-ca.pem \
  --offline-trust-manifest /external/frozen-nist-trust/manifest.json \
  --github-gate-receipt /path/to/github-gate-receipt.json \
  --development-control-report /path/to/development-control-report.json \
  --development-control-artifact-root /path/to/development-control \
  --development-control-archive-receipt /path/to/development-control-archive-receipt.json \
  --development-control-archive-asset-root /path/to/downloaded-development-assets \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --frozen-design /path/to/frozen-design.json
```

The machine-readable contract is
[`schemas/freeze-manifest.schema.json`](schemas/freeze-manifest.schema.json).

After that verification has re-opened the CA and NIST trust inputs, download
the two raw GitHub Actions artifact ZIPs named by the gate receipt and build
the exact twelve design-release assets offline. The signing public key is an
external preregistered trust input and is deliberately not included among
those twelve release assets:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/package_design_release.py package \
  --frozen-design /path/to/frozen-design.json \
  --development-control-report /path/to/development-control-report.json \
  --development-control-archive-receipt /path/to/development-control-archive-receipt.json \
  --freeze-manifest /external/freeze-manifest.json \
  --github-gate-receipt /path/to/github-gate-receipt.json \
  --linux-ci-artifact /path/to/downloaded-linux-artifact.zip \
  --macos-arm64-ci-artifact /path/to/downloaded-macos-artifact.zip \
  --asset-source-manifest blind_v1/model-assets.draft.json \
  --full-asset-receipt blind_v1/.working/asset-receipt.json \
  --runtime-manifest blind_v1/.working/runtime-manifest.json \
  --sbom blind_v1/.working/cyclonedx-sbom.json \
  --signing-public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --output-root /new/path/design-release-assets

"$RUNTIME_ROOT/bin/python" -I -B blind_v1/package_design_release.py verify \
  --asset-root /new/path/design-release-assets \
  --signing-public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub
```

Upload the twelve filenames exactly as emitted. The self-excluding
`sha256-manifest.json` commits the other eleven assets; the later signed release
receipt commits all twelve, including that manifest, without a hash cycle. The
packager reopens each CI ZIP without extraction and rejects any mismatch in its
GitHub run/digest binding, platform identity, runtime locks, registered workflow
bytes, five-file inventory (including the real cryptographic known-answer
result), or terminal zero-skip log. The workflow executes that known-answer
verification under `unshare --net` on Linux and `sandbox-exec` with
`deny network*` on macOS; its `networkUsed=false` field is therefore tied to
an OS-enforced isolation mechanism named in the result, not merely to proxy
environment variables.

## Development preflight

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/verify_design.py
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/preflight.py \
  --codec-root ../codec-source \
  --asset-root blind_v1/.assets \
  --asset-receipt blind_v1/.working/asset-receipt.json \
  --require-assets
```

The current draft is expected to report `executionReady=false`; treating that
fail-closed result as PASS is forbidden.

## Full real-data development control on macOS arm64

This is the single registered pre-freeze inference control. It uses the three
real, previously observed pilot revisions that are excluded from the
confirmatory pool—GPT-Neo-125M, SmolLM2-360M, and Tiny StarCoder—and the exact
UD English PUD r2.18 CoNLL-U source. It runs producer and implementation-level
independent real-model replay processes sequentially, invokes the fixed VTL5
candidate, and writes only non-scientific readiness evidence. It never imports
a confirmatory revision, requests NIST, reads the future corpus, creates
scientific attempt state, applies confirmatory thresholds, or counts toward the
scientific verdict. Linux CI is not a substitute for this macOS arm64 pilot
control.

Run it only from the exact clean implementation commit after regenerating the
runtime manifest with `--require-clean-git`. The output path must be a new,
absent directory outside both repositories and outside every scientific
`.one-shot-result` path. Other applications may remain open. The fail-closed
host gate waits for at most five minutes when free memory is temporarily below
the registered 50% floor, without lowering that floor. It aborts immediately
once any power, disk, platform, configuration, or inspection failure is
observed, and aborts before model loading if memory does not recover within the
fixed window. This wait belongs only to the non-scientific development control;
the prospective one-shot uses its separate immediate pre-marker gate.

Before the development-control release exists, the canonical entrypoint
derives the current clean `HEAD` commit and tree and requires the runtime and
report input bindings to name that exact source identity; the self-referential
tracked draft design fixes the repository and rule, while the later external
frozen design binds the resulting commit/tree through the freeze manifest. It
accepts no historical release identity. After the signed annotated
`corelm-blind-crossmodel-v1-development-control` tag exists, only
`run_post_release_regression.py` may run this workload: it verifies that tag
and permits a non-scientific regression only from its exact target commit and
tree. There is no separate post-release source tag, and a changed source tree
requires a newly registered implementation identity. Both source gates permit
ignored runtime inputs only below `blind_v1/.assets`, `blind_v1/.runtime`, and
`blind_v1/.working`; every other ignored path fails closed.

```sh
cd /absolute/path/to/lab
test -z "$(git status --porcelain=v1 --untracked-files=all)"
IMPLEMENTATION_COMMIT="$(git rev-parse 'HEAD^{commit}')"
IMPLEMENTATION_TREE="$(git rev-parse 'HEAD^{tree}')"
CODEC_ROOT="$(cd ../codec-source && pwd -P)"
RUNTIME_ROOT="$PWD/blind_v1/.runtime/macos"
RUNTIME_MANIFEST="$PWD/blind_v1/.working/runtime-manifest.json"
DATASET="$PWD/blind_v1/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu"
CONTROL_ROOT="/absolute/new/path/development-control"
PYCACHE_ROOT="/absolute/new/empty/path/development-control-pycache"

mkdir -m 700 "$PYCACHE_ROOT"
test -z "$(find "$PYCACHE_ROOT" -mindepth 1 -maxdepth 1 -print -quit)"

PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B -X \
  "pycache_prefix=$PYCACHE_ROOT" \
  blind_v1/run_real_e2e_control.py \
  --asset-root "$PWD/blind_v1/.assets" \
  --dataset "$DATASET" \
  --codec-root "$CODEC_ROOT" \
  --runtime-manifest "$RUNTIME_MANIFEST" \
  --output "$CONTROL_ROOT"
```

A successful run ends by exclusively creating
`development-control-report.json`. A failed or interrupted run instead keeps a
durable `development-control-failure.json`; never delete, overwrite, resume, or
rename it to PASS. Every later diagnostic run needs another new output path and
must remain labelled development/regression.

After the signed development-control tag exists, a regression uses the separate
entrypoint and another empty external bytecode directory:

```sh
POST_RELEASE_CONTROL_ROOT="/absolute/new/path/post-release-regression"
POST_RELEASE_PYCACHE_ROOT="/absolute/new/empty/path/post-release-pycache"

mkdir -m 700 "$POST_RELEASE_PYCACHE_ROOT"
test -z "$(find "$POST_RELEASE_PYCACHE_ROOT" -mindepth 1 -maxdepth 1 -print -quit)"

PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B -X \
  "pycache_prefix=$POST_RELEASE_PYCACHE_ROOT" \
  blind_v1/run_post_release_regression.py \
  --asset-root "$PWD/blind_v1/.assets" \
  --dataset "$DATASET" \
  --codec-root "$CODEC_ROOT" \
  --runtime-manifest "$RUNTIME_MANIFEST" \
  --output "$POST_RELEASE_CONTROL_ROOT"
```

This command verifies the signed development tag before importing the control
implementation and emits only post-release regression evidence. It cannot
replace, repair, or extend the canonical development-control release.

The producer does not preload its 32 selected records. It finishes model
loading, releases the model-asset byte buffers, then reads, verifies, evaluates,
and releases one record before opening the next. For the future corpus, the
inclusive canonical-record limit is exactly 8,388,608 bytes; 8,388,609 bytes is
ineligible before ledger construction and selection, and snapshot verification
recomputes that decision from the archived API response.

The reported `peakAggregateRSSBytes` is the maximum observed aggregate for the
worker process group at 250 ms polling intervals, including one observation
after exit is detected. It is a sampled watchdog, not a kernel RLIMIT, so it
does not establish that no shorter sub-interval peak occurred. Every observed
sample above 4,294,967,296 bytes fails the execution.

The registered model loader separately limits simultaneous weight-payload
representations. Its exact order is
`verified-owned-bytes->deserialize-owned-state->destroy-weight-bytes->construct-fp32-model->strict-copy`:
no more than two payload representations coexist and raw verified weight bytes
are destroyed before FP32 model construction. The exact
`staticWorstCaseWeightStorageOverlapBytes` value `2,894,634,160` covers only
weight-file/decoded-state/FP32-weight storage overlap. It deliberately excludes
Python/runtime and model metadata, allocator overhead, tokenizer, activations,
and evidence buffers, so it must not be described as a complete worker-memory
bound. The separate sampled 4 GiB aggregate-RSS gate above remains mandatory.
The old triple-payload lower bound `4,341,886,040` is a superseded comparison,
not the active allocation plan.

Reverify every artifact and build the three deterministic local archive
assets. This step does not merely rehash files: it independently parses all
1,000 CoNLL-U sentence blocks, reconstructs all 32 partitions and jobs, parses
every JSONL/VTL5 record, recomputes worker page metrics and replay digests, and
checks the consolidated streams byte-for-byte. The local 2,088-member evidence
set includes the exact corpus manifest/source,
`inputs/LICENSES/source-evidence.json`, `inputs/LICENSES/ASSET_LICENSES.md`, the
upstream README and license, and
`inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md`. It does not contain model
weights. The 24 pilot-model files are external private inputs whose exact paths,
sizes, and SHA-256 values are jointly bound by `development-plan.json`, the
pinned asset manifest, and the full-rehash receipt.

Inside this evidence set the pilot receipt's canonical member path is
`inputs/development-model-assets.full-rehash.json`. Do not rename it to
`inputs/full-asset-receipt.json`; that name is reserved for the separate
six-model confirmatory receipt in the design release. The pilot receipt can be
published with the development-control archive, but its bytes must not be
substituted for the design release's confirmatory receipt.

The upstream metadata, README, and license consistently declare CC BY-SA 3.0.
The package therefore records contributor attribution, the license and URI,
the extraction/partition changes, and share-alike handling for reversible or
source-derived evidence; it adds no effective restrictions. This is not an
independent ownership or chain-of-title conclusion. The packager re-verifies
those exact rights bytes and all 2,088 artifact commitments before creating
exactly three files: report, artifact ZIP, and SHA-256 manifest. It proves a
conservative upper bound before opening the ZIP, checks the completed file
again, and rejects any ZIP whose size is not strictly below 1,800,000,000
bytes. A missing member, extra member, or accidentally embedded model file is
therefore a hard verification failure.

```sh
PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B \
  blind_v1/package_development_control_release.py package \
  --report "$CONTROL_ROOT/development-control-report.json" \
  --artifact-root "$CONTROL_ROOT" \
  --runtime-manifest "$RUNTIME_MANIFEST" \
  --lab-repository https://github.com/ALLPROTO/core-lm-cross-model-lab.git \
  --lab-commit "$IMPLEMENTATION_COMMIT" \
  --lab-tree "$IMPLEMENTATION_TREE" \
  --codec-repository https://github.com/ALLPROTO/core-lm-benchmark.git \
  --codec-commit 2e8d3b1591ee4a1ed822310f330317936871ff2b \
  --codec-tree c0bb15784d252cd5036757bc64765c773a5f16e8 \
  --output-root /absolute/new/path/development-control-release-assets
```

> **Current blind-v1 status (2026-08-05): active development draft.** No blind-v1
> development-control or design release exists yet, and no blind-v1 result counts
> toward a scientific verdict. Blind-v1 has a new suite identity and timeline and
> must repeat the complete real-model control on its exact implementation. The
> immutable v3 release remains a separate, transparent failed-freeze archive;
> none of its report, receipt, tag, or release identity can satisfy a blind-v1 gate.
> The current NIST leaf is time-valid at the proposed blind-v1 pulse: its
> `2026-09-04T23:59:59Z` expiry is after the `2026-08-21T18:00:00.000Z` target.
> The tracked candidate now fixes the exact chain, root pin, wire profile,
> singleton certificate policy, rotation policy, and explicit no-revocation
> residual risk. The design still cannot freeze until the exact external
> status-only frozen bundle, full real-model development control and archive,
> CI gate, runtime/assets, and every dependent release binding all verify on the
> same implementation commit.

Before `2026-08-09T00:00:00Z`, the exact three blind-v1 development-control files must
be published in an immutable
GitHub release named by the signed annotated tag
`corelm-blind-crossmodel-v1-development-control`. The tag must directly
target `$IMPLEMENTATION_COMMIT`. Then collect the canonical immutable-release
attested receipt; normal publication requires the verified RFC3161 `attestedAt`
to be strictly before the deadline. The collector archives the pinned GitHub
CLI result and immediately performs independent offline cryptographic
verification with the byte-pinned Cosign 3.0.6 executable and tracked
`blind_v1/trust/github/trusted_root.json`. The release ID is an explicit input:

```sh
PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B \
  blind_v1/collect_release_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --kind development-control \
  --tag corelm-blind-crossmodel-v1-development-control \
  --commit "$IMPLEMENTATION_COMMIT" \
  --tree "$IMPLEMENTATION_TREE" \
  --deadline 2026-08-09T00:00:00Z \
  --signature-type SSH \
  --key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --repo-path "$PWD" \
  --release-id '<numeric-release-id>' \
  --assets-dir /absolute/path/to/exact-downloaded-development-assets \
  --github-cli /absolute/path/to/pinned-gh-2.97.0-macos-arm64 \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64 \
  --asset development-control-report=development-control-report.json \
  --asset development-control-artifacts=development-control-artifacts.zip \
  --asset sha256-manifest=sha256-manifest.json \
  --signature-failure-output /absolute/new/path/development-signature-failure.json \
  --output /absolute/new/path/development-control-archive-receipt.json
```

The Cosign verification uses the complete archived DSSE bundle, the SHA-256 of
the lexicographically first ASCII release asset, the exact GitHub release SAN,
the release predicate type, and the signed RFC3161 timestamp. The selected
asset is fully copied and SHA-256 verified locally before Cosign receives that
digest; digest mode avoids Cosign's 128 MiB blob-input limit. The semantic
replay then binds every signed subject in that same statement. `attestedAt` is
parsed from the raw signed timestamp and cross-checked against the GitHub CLI result.
Because GitHub's bundle has neither a Rekor entry nor a certificate SCT, the
fixed command uses `--private-infrastructure --insecure-ignore-sct`. This
deliberately excludes transparency-log/SCT claims; it does not weaken the DSSE,
X.509 chain, exact SAN, selected-asset digest, or RFC3161 signature/chain checks.
See [`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md) for binary/root hashes and the
exact underlying Cosign command.

The freeze builder must receive the completed report, its artifact root, the
three downloaded archive assets, and this receipt. An operator-written status,
an unsigned tag, a mutable release, a missing/invalid GitHub immutable-release
attestation, an `attestedAt` that is not strictly before the deadline, or a
report from a different commit/tree/runtime fails closed. API `Date` and
`published_at` remain archived collection observations, not deadline proof.

## CI boundary

The development workflow builds the exact locked runtime on Linux and macOS
arm64 and enforces zero skipped tests. GitHub's `macos-15` standard runner is an
arm64 M1 VM with limited memory and disk, so it is suitable for clean-clone and
preflight controls, not for the registered local one-shot. See the
[GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Linux x86-64 and macOS arm64 CI reproduce source, dependency, schema,
known-answer, packaging, and verifier portability. They do not establish
bit-identical cross-platform model numerics. The sole primary numerical outcome
is produced on the frozen macOS arm64 CPU runtime. A Linux real-model run must
use a separately preregistered replication or regression identity and cannot
replace, average with, rescue, or alter the macOS terminal outcome.

## Pre-pulse public execution reservation and scientific boundary

Clean-clone preparation may download, byte-count, hash, strict-parse
configuration/tokenizer data, validate safetensors headers, and evaluate
tokenizer-length eligibility for all six confirmatory revisions. It must not
import their weights, generate caches, run a forward pass, or score the
candidate. After the pulse, confirmatory inference is allowed only inside the
registered post-marker producer and verifier workers.

After the immutable design and snapshot receipts exist, build the three public
execution-reservation assets without NIST access, selection, model loading, or
inference:

```sh
"$RUNTIME_ROOT/bin/python" -I -B \
  blind_v1/package_execution_reservation.py \
  --design /external/design-registration.json \
  --snapshot /external/snapshot-registration.json \
  --snapshot-receipt /external/snapshot-publication-receipt.json \
  --reserved-at '<whole-second UTC inside the registered window>' \
  --output-directory /external/execution-reservation-assets
```

The packager immediately reopens and verifies all three output files against
the supplied frozen design and snapshot before it reports success. It also
derives the sole public attempt identity as
`20260821T180000Z-` plus the first 16 lowercase hexadecimal characters of
SHA-256 over canonical `execution-reservation.json` before `attemptId` and
`reservationContentSHA256` are added. The reported
`verification.attemptId` must equal the value in the reopened reservation;
an operator-supplied ID or any other timestamp prefix is invalid.

Publish exactly those three files under the signed annotated tag
`corelm-blind-crossmodel-v1-execution-reservation` and collect the canonical
receipt of kind `reservation`. Its verified RFC3161 `attestedAt` must
fall inside `[2026-08-20T18:00:00Z, 2026-08-21T17:45:00Z)`. A local timestamp,
a later upload, or a second public reservation cannot satisfy this gate. The
public record commits the execution and closeout obligation but is not local
`attempt-reservation.json`, an attempt marker, or a scientific result.

## Fail-closed production runbook

The following is the complete operational path from future-corpus collection
to the public runner. Replace angle-bracket values only with commitments from
the frozen design or canonical publication receipts. Every output directory
shown as `/external/new-*` must be absent and outside both source repositories.
Do not combine the three collector invocations into one unattended command.

Set the common inputs once. The two expected hashes are frozen-design inputs;
do not derive an expected hash from the same file being verified:

```sh
CORPUS_ROOT=/external/new-blind-v1-corpus
ASSET_ROOT=/absolute/path/to/six-confirmatory-model-assets
ASSET_MANIFEST=/external/exact-downloaded-design-assets/asset-source-manifest.json
ASSET_MANIFEST_SHA256='<frozen design asset-source-manifest SHA-256>'
CA_BUNDLE="$PWD/blind_v1/trust/transport-ca.pem"
CA_BUNDLE_SHA256='<frozen design transport CA SHA-256>'
```

Run crawl 1 once on or after `2026-08-18T06:00:00Z`, with an absent
`$CORPUS_ROOT`:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/collect_snapshot.py \
  --phase crawl-1 \
  --asset-manifest "$ASSET_MANIFEST" \
  --asset-manifest-sha256 "$ASSET_MANIFEST_SHA256" \
  --asset-root "$ASSET_ROOT" \
  --ca-bundle "$CA_BUNDLE" \
  --ca-bundle-sha256 "$CA_BUNDLE_SHA256" \
  --output-root "$CORPUS_ROOT"
```

Run crawl 2 once on or after `2026-08-19T06:00:00Z`, reusing that exact
completed root, then finalize it once:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/collect_snapshot.py \
  --phase crawl-2 \
  --asset-manifest "$ASSET_MANIFEST" \
  --asset-manifest-sha256 "$ASSET_MANIFEST_SHA256" \
  --asset-root "$ASSET_ROOT" \
  --ca-bundle "$CA_BUNDLE" \
  --ca-bundle-sha256 "$CA_BUNDLE_SHA256" \
  --output-root "$CORPUS_ROOT"

"$RUNTIME_ROOT/bin/python" -I -B blind_v1/collect_snapshot.py \
  --phase finalize \
  --asset-manifest "$ASSET_MANIFEST" \
  --asset-manifest-sha256 "$ASSET_MANIFEST_SHA256" \
  --asset-root "$ASSET_ROOT" \
  --ca-bundle "$CA_BUNDLE" \
  --ca-bundle-sha256 "$CA_BUNDLE_SHA256" \
  --output-root "$CORPUS_ROOT"
```

Require the final report to say `SNAPSHOT_READY_FOR_FREEZE`, then build
`snapshot-registration.json` exactly as specified in
[`COLLECTOR_AND_BEACON_API.md`](COLLECTOR_AND_BEACON_API.md). A failed or
partial crawl is not resumed in place: retain it as failure evidence, abandon
that prospective corpus, and apply the registered reschedule rule.

Package and independently reopen the exact five snapshot-release assets. The
tracked script bootstraps only its own exact checkout package, so both commands
retain isolated mode.

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/package_snapshot_release.py package \
  --corpus-root "$CORPUS_ROOT" \
  --snapshot-registration /external/snapshot-registration.json \
  --design-publication-receipt /external/design-publication-receipt.json \
  --output-root /external/new-snapshot-release-assets

"$RUNTIME_ROOT/bin/python" -I -B blind_v1/package_snapshot_release.py verify \
  --corpus-root "$CORPUS_ROOT" \
  --snapshot-registration /external/snapshot-registration.json \
  --design-publication-receipt /external/design-publication-receipt.json \
  --asset-root /external/new-snapshot-release-assets
```

Publish those five files under the signed annotated tag
`corelm-blind-crossmodel-v1-snapshot`, targeted directly at the frozen
`$IMPLEMENTATION_COMMIT`. Make the release immutable, download its assets into
a new exact directory, and collect its canonical receipt before
`2026-08-20T18:00:00Z`:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/collect_release_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --kind snapshot \
  --tag corelm-blind-crossmodel-v1-snapshot \
  --commit "$IMPLEMENTATION_COMMIT" \
  --tree "$IMPLEMENTATION_TREE" \
  --deadline 2026-08-20T18:00:00Z \
  --signature-type SSH \
  --key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --repo-path "$PWD" \
  --release-id '<numeric immutable snapshot release ID>' \
  --assets-dir /external/exact-downloaded-snapshot-assets \
  --github-cli /absolute/path/to/pinned-gh-2.97.0-macos-arm64 \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64 \
  --asset attribution=attribution.json \
  --asset corpus-bytes=corpus-bytes.zip \
  --asset design-publication-receipt=design-publication-receipt.json \
  --asset sha256-manifest=sha256-manifest.json \
  --asset snapshot-registration=snapshot-registration.json \
  --signature-failure-output /external/new-snapshot-signature-failure.json \
  --output /external/snapshot-publication-receipt.json
```

Create, publish, download, and attest the execution reservation exactly as in
the preceding section and [`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md). Only
after its canonical receipt exists, seal one private execution root. Every
argument is mandatory so the preparer can reopen every frozen publication and
source binding before copying anything:

```sh
PRIVATE_ROOT=/external/new-blind-v1-private
RESULT_ROOT="${PRIVATE_ROOT}.one-shot-result"
CODEC_ROOT=/absolute/path/to/exact-frozen-codec-checkout

"$RUNTIME_ROOT/bin/python" -I -B blind_v1/runner.py prepare \
  --design /external/exact-downloaded-design-assets/design-registration.json \
  --snapshot-registration /external/exact-downloaded-snapshot-assets/snapshot-registration.json \
  --corpus-root "$CORPUS_ROOT" \
  --asset-manifest /external/exact-downloaded-design-assets/asset-source-manifest.json \
  --asset-receipt /external/exact-downloaded-design-assets/full-asset-receipt.json \
  --asset-root "$ASSET_ROOT" \
  --runtime-manifest /external/exact-downloaded-design-assets/runtime-manifest.json \
  --runtime-root "$RUNTIME_ROOT" \
  --freeze-manifest /external/exact-downloaded-design-assets/freeze-manifest.json \
  --github-gate-receipt /external/exact-downloaded-design-assets/github-gate-receipt.json \
  --development-control-report /external/exact-downloaded-design-assets/development-control-report.json \
  --development-control-artifact-root /external/development-control \
  --development-control-archive-receipt /external/exact-downloaded-design-assets/development-control-archive-receipt.json \
  --development-control-archive-assets /external/exact-downloaded-development-assets \
  --sbom /external/exact-downloaded-design-assets/sbom.cdx.json \
  --design-sha256-manifest /external/exact-downloaded-design-assets/sha256-manifest.json \
  --design-publication-receipt /external/design-publication-receipt.json \
  --design-release-assets /external/exact-downloaded-design-assets \
  --snapshot-publication-receipt /external/snapshot-publication-receipt.json \
  --snapshot-release-assets /external/exact-downloaded-snapshot-assets \
  --reservation-publication-receipt /external/reservation-publication-receipt.json \
  --reservation-release-assets /external/exact-downloaded-reservation-assets \
  --signing-public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --nist-trust-manifest /external/frozen-nist-trust/manifest.json \
  --ca-bundle "$CA_BUNDLE" \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64 \
  --codec-root "$CODEC_ROOT" \
  --lab-root "$PWD" \
  --destination "$PRIVATE_ROOT"
```

Preparation performs no NIST fetch, selection, model inference, marker
creation, or attempt consumption. Require its terminal status
`PRIVATE_SNAPSHOT_SEALED`, keep `$PRIVATE_ROOT` immutable and
`$RESULT_ROOT` absent from every other process, and do not mutate any input
afterward.

At the registered post-pulse execution time, invoke the public outer runner
exactly once with the literal confirmation below. `$RESULT_ROOT` must still be
absent and must be the canonical sibling derived above:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/runner.py run-one-shot \
  --private-root "$PRIVATE_ROOT" \
  --result-root "$RESULT_ROOT" \
  --confirm-scientific-one-shot corelm-blind-crossmodel-v1
```

Never pass the hidden `--private-execution` or `--outer-authorization-fd`
options. The registered procedure requires the public outer runner to create
the one-use anonymous pipe, bind it to the outer/child process identities and
canonical roots, and start the private child. An invocation without that
conforming inherited handoff, a reused descriptor, mismatched root, second
marker, retry, or any execution after the hard deadline fails closed; it does
not authorize another scientific attempt.

The pipe handoff does not authenticate the parent implementation or attest
that the parent will continue enforcing the watchdog. A custom same-user
parent can start a conforming child, reproduce the canonical payload, and
mimic the handoff. The live parent/child, process-group, path, deadline, nonce,
and no-retry checks therefore detect accidental direct-CLI misuse and binding
mismatches only. Internal code and wire names containing `authorization` do
not upgrade those checks into an authenticated outer-runner identity claim.

The post-pulse scientific invocation must reopen the exact public assets and
receipt, then durably publish local `attempt-reservation.json` and
`attempt-marker.json` before fetching the one registered NIST pulse. It runs
the three selected revisions in beacon order and completes the separate fresh
real-model replay. Only a timely `PASS` supports the registered positive claim
for that exact selected sample. `FAIL_GATES` is a negative metric result;
`FAIL_EXECUTION` and `CONSUMED_INCOMPLETE` are unsuccessful consumed local
attempts that do not establish a negative codec metric and do not authorize a
retry. If no local attempt starts before the deadline, publish the registered
`NO_ATTEMPT_EXPIRED` closeout. All subsequent executions are labelled
replication or regression and never rewrite the terminal outcome.

For reproduction, compare the verified public reservation ID byte-for-byte
with `attemptId` in the local attempt reservation and marker, every scientific
worker authorization/job and raw evidence record, the producer result, the
independent replay/report, and the evidence-release manifest. Every suite-v1
schema fixes the same `20260821T180000Z-` prefix. A closeout instead exposes
the same value as `publicationBindings.reservedAttemptId`; for
`NO_ATTEMPT_EXPIRED` that name denotes the unconsumed public reservation and
does not assert that a local attempt existed.

These procedures remain author self-verification. A second implementation path,
signed release, CI run, RFC3161 timestamp, or DOI improves auditability but does
not become independent human review, operator blindness, peer review, or
independent replication.
