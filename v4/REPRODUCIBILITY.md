# Blind-v4 author-self-verified clean-clone reproducibility

This document covers development controls and provenance preparation only. It
does not authorize the scientific one-shot, collect the future corpus, fetch a
NIST pulse, or create an attempt marker.

The repository owner is the author, experiment operator, and release operator.
No independent human review, peer review, operator blindness, or independent
replication is claimed. “Independent verifier” below means a separately
implemented verification path inside the same author-controlled artifact, not
an external person or organization.

## Required capacity

- Python: exactly 3.12.10.
- Model/tokenizer assets: 1,916,375,741 bytes in the current manifest, including
  1,906,255,408 bytes of safetensors weights.
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
git -C lab fetch origin tag corelm-crossmodel-livewiki-v4-design
test "$(git -C lab rev-list -n 1 corelm-crossmodel-livewiki-v4-design)" = \
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
RUNTIME_ROOT="$PWD/v4/.runtime/linux"
./v4/bootstrap_runtime.sh \
  --platform linux \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$(command -v python3.12)"
"$RUNTIME_ROOT/bin/python" -I -B v4/run_zero_skip_tests.py
```

macOS Apple Silicon:

```sh
cd lab
RUNTIME_ROOT="$PWD/v4/.runtime/macos"
./v4/bootstrap_runtime.sh \
  --platform macos \
  --codec-root ../codec-source \
  --runtime "$RUNTIME_ROOT" \
  --python "$(command -v python3.12)"
"$RUNTIME_ROOT/bin/python" -I -B v4/run_zero_skip_tests.py
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

## Materialize and rehash every model byte

The model files retain their upstream licenses and are intentionally ignored by
Git.

```sh
python3 v4/fetch_assets.py \
  --destination v4/.assets \
  --include-development-dataset
mkdir -p v4/.working
python3 v4/create_asset_receipt.py \
  --asset-root v4/.assets \
  --output v4/.working/asset-receipt.json
```

The same standard-library downloader writes the byte-pinned real-data input to
`v4/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`. It verifies commit
`e173a1be1b442faf34e7d5a502189ad5d9d1e197`, the 1,386,858-byte length, and
SHA-256 `c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa`
before atomic no-overwrite publication. Corpus decoding uses the project's
strict standard-library CoNLL-U parser and needs no dataset framework.

`create_asset_receipt.py` rereads all 24 model files with no-follow checks and binds
their exact 1,916,375,741 bytes into a deterministic, path-independent receipt.
It performs no model import or inference. The tracked receipt
`v4/manifests/model-assets.full-rehash.json` must compare byte-for-byte equal to
the regenerated output; its file SHA-256 is
`0491df1d1352a0954d9f077ae5c4875896baacd14a4db7323ebb86f800b40eb4`.

## Create runtime inventory and SBOM

Run the manifest generator with the interpreter it is inventorying. The final
freeze must use `--require-clean-git`; the command below omits it only while the
development branch contains uncommitted implementation work.

Linux:

```sh
"$RUNTIME_ROOT/bin/python" -I -B v4/create_runtime_manifest.py \
  --runtime-root "$RUNTIME_ROOT" \
  --requirements-lock ../codec-source/.github/locks/pip-bootstrap.txt \
  --requirements-lock ../codec-source/.github/locks/real-llm-linux-cpu-py312.txt \
  --requirements-lock ../codec-source/.github/locks/torch-linux-cpu-py312.txt \
  --codec-root ../codec-source \
  --output v4/.working/runtime-manifest.json
```

For macOS replace the last two platform locks with:

```text
--requirements-lock ../codec-source/RealLLM/requirements.lock
```

Then generate the deterministic CycloneDX inventory:

```sh
"$RUNTIME_ROOT/bin/python" -I -B v4/create_sbom.py \
  --runtime-manifest v4/.working/runtime-manifest.json \
  --asset-receipt v4/.working/asset-receipt.json \
  --output v4/.working/cyclonedx-sbom.json
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
"$RUNTIME_ROOT/bin/python" -B -m v4.create_zenodo_deposit_manifest \
  --deposit-root /path/to/exact-payload-root \
  --plan /path/to/exact-plan.json \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output /path/outside-payload/zenodo-deposit-manifest.json

"$RUNTIME_ROOT/bin/python" -B -m v4.verify_zenodo_receipt \
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

```sh
"$RUNTIME_ROOT/bin/python" -I -B v4/freeze_manifest.py create \
  --runtime-manifest v4/.working/runtime-manifest.json \
  --asset-receipt v4/.working/asset-receipt.json \
  --transport-ca-bundle v4/trust/transport-ca.pem \
  --offline-trust-manifest v4/trust/nist/manifest.json \
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
  --output v4/.working/freeze-manifest.json
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

"$RUNTIME_ROOT/bin/python" -I -B v4/build_frozen_design.py \
  --expected-lab-commit "$IMPLEMENTATION_COMMIT" \
  --expected-lab-tree "$IMPLEMENTATION_TREE" \
  --expected-freeze-manifest-sha256 "$FREEZE_MANIFEST_SHA256" \
  --freeze-manifest /external/freeze-manifest.json \
  --runtime-manifest v4/.working/runtime-manifest.json \
  --asset-receipt v4/.working/asset-receipt.json \
  --transport-ca-bundle v4/trust/transport-ca.pem \
  --offline-trust-manifest v4/trust/nist/manifest.json \
  --github-gate-receipt /external/github-gate-receipt.json \
  --development-control-report /external/development-control-report.json \
  --development-control-artifact-root /external/development-control \
  --development-control-archive-receipt /external/development-control-archive-receipt.json \
  --development-control-archive-asset-root /external/downloaded-development-assets \
  --signing-public-key v4/signing/corelm-crossmodel-v4-signing.pub \
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
"$RUNTIME_ROOT/bin/python" -I -B v4/freeze_manifest.py verify \
  --manifest v4/.working/freeze-manifest.json \
  --runtime-manifest v4/.working/runtime-manifest.json \
  --asset-receipt v4/.working/asset-receipt.json \
  --transport-ca-bundle v4/trust/transport-ca.pem \
  --offline-trust-manifest v4/trust/nist/manifest.json \
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
"$RUNTIME_ROOT/bin/python" -I -B v4/package_design_release.py package \
  --frozen-design /path/to/frozen-design.json \
  --development-control-report /path/to/development-control-report.json \
  --development-control-archive-receipt /path/to/development-control-archive-receipt.json \
  --freeze-manifest v4/.working/freeze-manifest.json \
  --github-gate-receipt /path/to/github-gate-receipt.json \
  --linux-ci-artifact /path/to/downloaded-linux-artifact.zip \
  --macos-arm64-ci-artifact /path/to/downloaded-macos-artifact.zip \
  --asset-source-manifest v4/model-assets.draft.json \
  --full-asset-receipt v4/.working/asset-receipt.json \
  --runtime-manifest v4/.working/runtime-manifest.json \
  --sbom v4/.working/cyclonedx-sbom.json \
  --signing-public-key v4/signing/corelm-crossmodel-v4-signing.pub \
  --output-root /new/path/design-release-assets

"$RUNTIME_ROOT/bin/python" -I -B v4/package_design_release.py verify \
  --asset-root /new/path/design-release-assets \
  --signing-public-key v4/signing/corelm-crossmodel-v4-signing.pub
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
"$RUNTIME_ROOT/bin/python" -I -B v4/verify_design.py
"$RUNTIME_ROOT/bin/python" -I -B v4/preflight.py \
  --codec-root ../codec-source \
  --asset-root v4/.assets \
  --asset-receipt v4/.working/asset-receipt.json \
  --require-assets
```

The current draft is expected to report `executionReady=false`; treating that
fail-closed result as PASS is forbidden.

## Full real-data development control on macOS arm64

This is the single registered pre-freeze inference control. It uses all three
real pinned models and the exact UD English PUD r2.18 CoNLL-U source, runs
producer and independent real-model replay processes sequentially, invokes the
fixed VTL5 candidate, and writes only non-scientific readiness evidence. It never requests
NIST, reads the future corpus, creates attempt state, applies scientific
thresholds, or counts toward the scientific verdict. Linux CI is not a
substitute for this macOS arm64 control.

Run it only from the exact clean implementation commit after regenerating the
runtime manifest with `--require-clean-git`. The output path must be a new,
absent directory outside both repositories and outside every scientific
`.one-shot-result` path. Other applications may remain open; the fail-closed
host gate aborts before model loading whenever AC power, free-memory, or disk
requirements are not met.

```sh
cd /absolute/path/to/lab
test -z "$(git status --porcelain=v1 --untracked-files=all)"
IMPLEMENTATION_COMMIT="$(git rev-parse 'HEAD^{commit}')"
IMPLEMENTATION_TREE="$(git rev-parse 'HEAD^{tree}')"
CODEC_ROOT="$(cd ../codec-source && pwd -P)"
RUNTIME_ROOT="$PWD/v4/.runtime/macos"
RUNTIME_MANIFEST="$PWD/v4/.working/runtime-manifest.json"
DATASET="$PWD/v4/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu"
CONTROL_ROOT="/absolute/new/path/development-control"

PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B \
  v4/run_real_e2e_control.py \
  --asset-root "$PWD/v4/.assets" \
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

Reverify every artifact and build the three deterministic local archive
assets. This step does not merely rehash files: it independently parses all
1,000 CoNLL-U sentence blocks, reconstructs all 32 partitions and jobs, parses
every JSONL/VTL5 record, recomputes worker page metrics and replay digests, and
checks the consolidated streams byte-for-byte. The local 2,088-member evidence
set includes the exact corpus manifest/source,
`inputs/LICENSES/source-evidence.json`, `inputs/LICENSES/ASSET_LICENSES.md`, the
upstream README and license, and
`inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md`. It does not contain model
weights. The 24 model files are external private inputs whose exact paths,
sizes, and SHA-256 values are jointly bound by `development-plan.json`, the
pinned asset manifest, and the full-rehash receipt.

Inside this evidence set the receipt's canonical member path is
`inputs/model-assets.full-rehash.json`. Do not rename it to
`inputs/full-asset-receipt.json`; that path is not a development-control archive
member. The same receipt bytes are published separately in the design release
as the root asset `full-asset-receipt.json`.

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
  v4/package_development_control_release.py package \
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

> **Current v4 status (2026-08-04): active development draft.** No v4
> development-control or design release exists yet, and no v4 result counts
> toward a scientific verdict. V4 has a new suite identity and timeline and
> must repeat the complete real-model control on its exact implementation. The
> immutable v3 release remains a separate, transparent failed-freeze archive;
> none of its report, receipt, tag, or release identity can satisfy a v4 gate.
> The current NIST leaf also expires before the proposed v4 pulse, so the design
> cannot freeze until replacement trust is pinned and all dependent hashes are
> recomputed.

Before `2026-09-07T00:00:00Z`, the exact three v4 development-control files must
be published in an immutable
GitHub release named by the signed annotated tag
`corelm-crossmodel-livewiki-v4-development-control`. The tag must directly
target `$IMPLEMENTATION_COMMIT`. Then collect the canonical immutable-release
attested receipt; normal publication requires the verified RFC3161 `attestedAt`
to be strictly before the deadline. The collector archives the pinned GitHub
CLI result and immediately performs independent offline cryptographic
verification with the byte-pinned Cosign 3.0.6 executable and tracked
`v4/trust/github/trusted_root.json`. The release ID is an explicit input:

```sh
PYTHONHASHSEED=0 "$RUNTIME_ROOT/bin/python" -P -s -B \
  v4/collect_release_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --kind development-control \
  --tag corelm-crossmodel-livewiki-v4-development-control \
  --commit "$IMPLEMENTATION_COMMIT" \
  --tree "$IMPLEMENTATION_TREE" \
  --deadline 2026-09-07T00:00:00Z \
  --signature-type SSH \
  --key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --public-key v4/signing/corelm-crossmodel-v4-signing.pub \
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
