# Blind multi-model v3 — author self-verification

Status: **implementation draft — not frozen, not published, not
preregistered, and scientific one-shot not run**.

This directory is the fail-closed development contour for the proposed
`corelm-voidtoken-crossmodel-livewiki-v3-author-verified` experiment. It is intentionally
separate from the completed public-validation regression in the repository
root.

Governance is explicit: the repository owner is the author, experiment
operator, and release operator. V3 has no independent human review, peer
review, operator blindness, or independent replication. Its separate verifier
and real-model replay provide implementation-level separation inside the same
author-controlled project; they are not external validation. The GitHub gate is
exact-commit CI-only and must pass without skips on Linux x86-64 and macOS arm64.

The prospective claim is narrow: one candidate fixed before the corpus exists
must preserve behavior independently for three pinned model revisions not used
for candidate selection or tuning, on two NIST-selected samples of sixteen eligible future Wikipedia
creation revisions. A PASS would apply only to those exact models, thirty-two
selected revisions, dates, runtime, codec, and gates. It would not establish a
result for either complete language-edition corpus or prove transfer to every
LLM.

Before freeze, those revisions may run only one tracked development control
on the pinned UD English PUD r2.18 CoNLL-U source: the fixed full
producer-to-VTL5-to-independent-replay readiness check, which includes the
lossless cache-adapter invariant. It may compute diagnostics with the already
fixed candidate, but it may not change the candidate or protocol, use future
corpus/NIST data, or create attempt state. It never counts toward the verdict.
The upstream `test` split is reused only for this non-scientific development
control; it is not the prospective beacon-selected test corpus.

## Fixed high-level design

- Models: GPT-Neo-125M, SmolLM2-360M, and tiny_starcoder_py at the exact
  revisions in [`design-registration.draft.json`](design-registration.draft.json).
- Corpus: eligible page-creation revisions from the German, English, and
  French Wikipedias in `[2026-08-16T00:00:00Z,
  2026-08-30T00:00:00Z)`.
- Selection: two language editions, sixteen distinct pages from each, and
  model execution order are derived without modulo bias from the exact NIST
  pulse at `2026-09-02T18:00:00.000Z`. The normative selector accepts exact
  ledger bytes, strict-parses them, and requires their SHA-256 values to match
  the frozen snapshot before drawing any page.
- Candidate: group/transform size 128, zlib level 9, no sign transform, 9 bits
  for layers 0 and `floor(layerCount / 3)` and 8 bits for every other layer.
  This reproduces the old `{0, 8}` schedule at 24 layers while defining one
  architecture-neutral rule for 12, 20, and 32 layers. There is no calibration
  or architecture-specific retuning.
- Execution: CPU, two threads, FP32 model execution, canonical BF16 cache
  baseline, 383-token prefill and 128 teacher-forced decisions per page.
- Attempt sequencing: after preflight seals the private asset snapshot, a
  durable no-retry reservation is written and then the durable marker is
  written. Only the supervisor may then make one request to the exact NIST
  endpoint. It verifies and durably seals the pulse, disables its network,
  derives selection, and only then starts the inference child. The child is
  networkless from process creation. A crash after reservation is consumed and
  cannot be retried even if the marker was not completed.
- Verdict: all six model/corpus cells and all three model aggregates must pass;
  a negative model cannot be averaged away.

## Current safety and prior-observation boundary

No v3 scientific result exists. The earlier v2 contour is a superseded,
unfrozen draft, and no v2 scientific result exists. Its completed UD English
PUD real-model E2E is preserved as a prior non-scientific development
observation; it cannot satisfy the v3 freeze gate. V3 must repeat that full
producer-to-VTL5-to-real-model-replay control on its own exact commit without
changing the candidate, models, metrics, or gates in response to the prior
diagnostics.

The selector's committed known-answer vector
is a protocol-control fixture only and can never enter a result directory. The
design verifier performs no network access, model loading, inference, or corpus
collection. A single tracked control can load all three pinned real models on
the pinned UD English PUD bytes and checks lossless cache-adapter round trips,
the fixed candidate producer, VTL5 containers, and independent real-model
replay. Its outputs are non-scientific readiness diagnostics, never evidence
for the future-corpus one-shot claim, and may not be used to tune any
registered setting.

The control parses the exact CoNLL-U bytes with a strict standard-library
parser, extracts one unchanged `# text = ` value from each of 1,000 sentence
blocks, and partitions the joined text into 32 contiguous floor-boundary
slices. The upstream README, license, and metadata consistently declare CC BY-SA
3.0. The development archive therefore preserves the exact corpus source,
attribution, license URI, marked extraction/partition changes, and share-alike
handling for reversible/source-derived evidence. This records the upstream
declaration and is not an independent legal conclusion about ownership.

Run the current offline controls with:

```sh
/path/to/locked/python -I -B v3/run_zero_skip_tests.py
/path/to/locked/python -I -B v3/verify_design.py
/path/to/locked/python -I -B v3/preflight.py \
  --codec-root /path/to/exact/core-lm-benchmark
```

For a fresh checkout, exact locked runtime, full asset receipt, runtime byte
inventory, and CycloneDX SBOM, follow [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).
The Linux job proves clean locked-runtime and protocol portability only. It is
not a Linux replication of the macOS scientific result; no such post-evidence
replication is implemented or registered in this draft.

Materialize and verify only the 21 small configuration/tokenizer files with:

```sh
python3 v3/fetch_assets.py \
  --destination v3/.assets \
  --small-files-only \
  --include-development-dataset
```

The dataset option adds the exact 1,386,858-byte UD English PUD source at
`v3/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu` (SHA-256
`c80584f2bc2b31d5bada78a1136f9feec7ac49e5e18898db02dea434b5b8f0aa`).
It uses the upstream `test` split only for the non-scientific development
control and is decoded only by the strict standard-library CoNLL-U parser.
Omitting `--small-files-only` additionally downloads the three exact
`model.safetensors` files (1,906,255,408 bytes total). The standard-library
loader uses immutable revisions, HTTPS allowlists without environment proxies,
bounded reads, exclusive partial files, SHA-256/size checks, and atomic
no-overwrite publication. Asset materialization performs no model import or
inference and does not create scientific evidence or an attempt marker.

A successful full control produces exactly 2,088 manifested evidence artifacts.
Those artifacts contain no model weights: the 24 real-model files remain
external private inputs, while `development-plan.json`, the pinned asset
manifest, and the full-rehash receipt bind every external path, byte count, and
SHA-256. Package the 2,088 artifacts into the three canonical
development-control release assets. The deterministic ZIP must remain strictly
below the conservative 1,800,000,000-byte per-file cap. Publish the assets from
the signed annotated development tag and collect the canonical GitHub server
receipt before `2026-08-15T00:00:00Z`. Local files, an unsigned tag, or an
operator-entered timestamp do not satisfy the freeze gate.

The tracked receipt commits a complete local rehash of all 24 real files and
matches the three currently retained local rehash receipts byte-for-byte. The
tracked receipt is
[`manifests/model-assets.full-rehash.json`](manifests/model-assets.full-rehash.json)
(1,916,375,741 bytes; receipt file SHA-256
`a576fd188afd9ace4368c2bc30fd0bbf90492741efa342a847a5805147333d2b`).
It records a reproducibility control, not a scientific attempt, and it does not
redistribute the model bytes.

At the first registered not-before time, begin the durable two-day collection
in a path that does not yet exist with the locked runtime:

```sh
/path/to/locked/python v3/collect_snapshot.py \
  --phase crawl-1 \
  --asset-manifest v3/model-assets.draft.json \
  --asset-manifest-sha256 <frozen-asset-manifest-sha256> \
  --asset-root /path/to/verified-assets \
  --ca-bundle /path/to/frozen-ca-bundle.pem \
  --ca-bundle-sha256 <frozen-ca-bundle-sha256> \
  --output-root /new/path/livewiki-v3-snapshot
```

After the second not-before time, repeat the exact command and existing output
root with `--phase crawl-2`, then repeat it once more with `--phase finalize`.
Finalize fetches the union's immutable creation revisions and is the only phase
that can report freeze readiness. There is deliberately no single-command mode
that silently collapses the two registered crawl dates.

The collector rehashes every manifest asset, constructs the three tokenizers
only from verified owned `tokenizer.json` bytes, uses only the three registered
MediaWiki hosts through the pinned CA bundle, archives both complete crawls,
and independently replays all bytes and token commitments. It exits non-zero
unless all three ledgers contain at least 64 eligible revisions. This inventory
never runs a model or counts as scientific evidence.

The dependency-free selector/design subset can run with system Python. The
normative zero-skip command must use the benchmark's hash-locked runtime with
NumPy, Torch, Transformers, and `jsonschema`; it fails the job if any platform
condition or dependency would cause even one test to skip.

`verify_design.py --require-freezable` is deliberately fail-closed in this
development contour. Deleting blocker strings or inventing commit hashes cannot
make it pass. The implemented two-stage freeze validator re-opens concrete
runtime, asset, source, CI, CA, and NIST-trust inputs; it cannot waive a
missing exact-commit zero-skip CI observation, author-self-verification record,
or publication receipt. Public release creation,
snapshot collection, and the one-shot run remain separate irreversible stages.

`preflight.py` is read-only: it verifies the exact codec commit, tree, and files,
an optional no-symlink asset snapshot, power/memory state, and pristine result boundary.
It never downloads, imports a model, opens corpus data, or creates an attempt
marker. `--require-execution-ready` intentionally returns a non-zero status
until the complete frozen runtime, assets, AC power, memory floor, and design
requirements are satisfied.

## Implemented controls and remaining gates

The tracked implementation now includes canonical schemas, two-phase
MediaWiki collection/finalization, strict NIST response and certificate-chain
verification, immutable-byte model loading, page-token/vocabulary bindings,
the durable one-shot state machine, OS-level network sandboxing, process-group
RSS/deadline supervision, exact Git-object source sealing, independent
structural/arithmetic verification plus mandatory fresh real-model replay of
all token IDs, loss bits, top-1 IDs, and VTL5 inputs, and a post-attempt evidence
packager for positive and negative terminal classes. Dedicated offline packagers create and
re-open the exact design, snapshot, evidence, and non-verdict closeout release inventories; the
online receipt collector then binds the signed Git object and immutable GitHub
release to those exact bytes.

That implementation is not itself a freeze. The remaining P0 gates are an
exact clean implementation commit/tree, clean runtime manifest and SBOM,
release binding of the already-rehashed assets and tracked NIST trust material,
clean-clone macOS arm64 and Linux zero-skip CI on that exact commit, an explicit
author-self-verification record that disclaims independent human and peer
review,
release binding and fail-closed verification of both canonical platform CI ZIP
payloads against the gate receipt's structurally consistent archived
observation, explicit preservation of its
`DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_GITHUB_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`
boundary without claiming offline GitHub-origin attestation, GitHub registration
of the preregistered signing key, and a signed immutable design release plus
verifiable publication receipt before the deadline. The exact workflow bytes,
job names, runner labels, and guest architectures are now part of the design
registration. See
[`FREEZE_READINESS.md`](FREEZE_READINESS.md). If those gates cannot be proven in
time, the complete dependent corpus/NIST/attempt window moves under a new suite
identity; an unfinished protocol is never frozen.

The CI collector archives exactly four GitHub API responses: PR, workflow run,
all jobs, and artifacts. It never calls the reviews endpoint and carries no
reviewer, approval, or review-declaration requirement. This governance change
does not relax exact source identity, all-job success, zero skips, mandatory
platform ZIP verification, signed immutable releases, the real-data E2E, or
the scientific verifier.

The detailed normative draft is
[`design-registration.draft.json`](design-registration.draft.json). Earlier
design exploration remains only in local notes and Git history; a fresh clone
does not need an ignored file to understand or verify this contour.

The complete normative prose companion is [`PROTOCOL.md`](PROTOCOL.md). The
machine-readable artifact contracts are under [`schemas/`](schemas/). The
post-attempt archive contract and commands are in
[`EVIDENCE_RELEASE.md`](EVIDENCE_RELEASE.md).
The mutually exclusive no-attempt/late-publication closeout procedure is in
[`CLOSEOUT.md`](CLOSEOUT.md).
DOI reservation, Zenodo deposit, ORCID, citation, SBOM, and license archival
are specified in [`ARCHIVAL.md`](ARCHIVAL.md).
