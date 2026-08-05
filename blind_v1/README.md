# Core LM blind cross-model v1

Status: **development draft — not frozen, not preregistered, and not run**.

`blind_v1/` is the proposed confirmatory contour for
`corelm-blind-crossmodel-v1`. It is separate from the public-validation
regressions and the V2–V4 development contours. Nothing in this directory is a
scientific result until an exact design is published in a signed immutable
release, the pre-pulse execution intent is publicly reserved and timestamped,
the one permitted local attempt reaches a terminal state, and the complete
evidence release verifies.

The project uses `AUTHOR_SELF_VERIFICATION`. Ivan Tyshchenko is the author,
experiment operator, and release operator. The separate verifier and fresh
real-model replay are implementation-level separation inside the same
author-controlled artifact. They are not independent human review, peer
review, operator blindness, independent validation, or independent
replication.

## Exact claim under test

The fixed VoidToken candidate is tested on:

- three exact model revisions selected without replacement by a future NIST
  pulse from a frozen six-revision confirmatory pool;
- two language editions selected from the frozen German, English, and French
  Wikipedia ledgers;
- sixteen future page-creation revisions selected from each chosen ledger;
- the frozen macOS arm64 CPU runtime and the registered complete-container,
  delta-NLL, top-1, and structural-replay gates.

A `PASS` supports only this exact selected sample: three revisions, thirty-two
pages, the frozen corpus snapshot, candidate, runtime, codec, baseline, and
metrics. The descriptive Student-t and Wilson quantities are fixed gates; they
are not population confidence claims because pages are not guaranteed IID and
token decisions within a page are dependent.

A `PASS` does **not** establish performance for the other three pool members,
an architecture family, a complete Wikipedia edition, all LLMs, all text, or a
different CPU/OS/runtime. It is not a claim about weight compression,
free-running generation quality, latency, throughput, energy, or state of the
art.

## Confirmatory model pool

The exact pool is frozen by repository, revision, every required asset size,
and SHA-256. NIST selects exactly three entries without replacement; all three
selected entries are mandatory and run in the selected order. A load error,
unsupported cache shape, resource failure, or missing asset is
`FAIL_EXECUTION`, never grounds for substituting another pool member.

| Key | Exact repository revision | Architecture |
|---|---|---|
| `pythia-160m` | `EleutherAI/pythia-160m@50f5173d932e8e61f858120bcb800b97af589f46` | GPT-NeoX MHA |
| `pythia-70m` | `EleutherAI/pythia-70m@a39f36b100fe8a5377810d56c3f4789b9c53ac42` | GPT-NeoX MHA |
| `smollm-135m` | `HuggingFaceTB/SmolLM-135M@1d461723eec654e65efdc40cf49301c89c0c92f4` | Llama GQA |
| `smollm-360m` | `HuggingFaceTB/SmolLM-360M@59f7ef243ee09a72cbc14cb054393a3e3b771d41` | Llama GQA |
| `gpt2-124m` | `openai-community/gpt2@607a30d783dfa663caf39e06633721c8d4cfcd7e` | GPT-2 MHA |
| `distilgpt2-82m` | `distilbert/distilgpt2@2290a62682d06624634c1f46a6ad5be0f47f38aa` | GPT-2 MHA |

The author's frozen prior-observation disclosure states that none of these
exact revisions has previously undergone a model forward pass, candidate
scoring, or candidate comparison in this project. Public artifacts make that
declaration auditable but cannot prove the absence of an undisclosed run. The
prohibition applies to the entire six-model pool because the selected three are
unknown until the future pulse. Before the pulse, pool assets may only be downloaded,
byte-counted, hashed, strict-parsed as configuration/tokenizer data, checked at
the safetensors-header level, and used for tokenizer-length eligibility.

Broad GPT-2, GPT-NeoX/Pythia, and Llama architecture families have been
observed previously. The fixed candidate and the `2.0 / 0.01 / 0.99`
thresholds also predate this suite. The complete lineage, including the
negative Pythia-410M observation, is disclosed in
[`prior-observations.json`](prior-observations.json). Therefore this is an
exact-revision holdout, not an architecture-blind experiment.

## Development controls do not screen the pool

The real-data pre-freeze E2E uses only previously observed pilot revisions that
are excluded from the confirmatory pool: GPT-Neo-125M, SmolLM2-360M, and Tiny
StarCoder. It runs the producer, VTL5 codec, and independent real-model replay
on the pinned UD English PUD r2.18 bytes. Its outputs are non-scientific
readiness diagnostics and must state:

```text
countsTowardScientificVerdict=false
usedForCandidateSelectionOrTuning=false
futureCorpusUsed=false
nistUsed=false
scientificAttemptStateCreated=false
```

No development control may import confirmatory-pool weights, execute a forward
pass on a pool model, inspect a future selected record with a model, or alter
the candidate, thresholds, pool, eligibility rule, runtime, or dates. A needed
change creates a new suite identity and moves the complete future timeline.

Synthetic, generated, toy, and mocked inputs remain confined to isolated unit,
parser, security, and protocol-control tests. Their outputs cannot enter a
scientific or development real-model result directory.

## Irreversible experiment sequence

1. Publish the signed immutable design and its canonical receipt before the
   design deadline.
2. Collect the prospective corpus exactly as registered, publish the signed
   immutable snapshot, and seal the private content-addressed execution input.
3. Complete all deterministic design, snapshot, asset, and reservation-package
   preflight checks without model inference.
4. Build the three canonical public execution-reservation assets, including
   `execution-reservation.json`, and publish them under the preregistered signed
   immutable tag `corelm-blind-crossmodel-v1-execution-reservation`. Its
   verified RFC3161 `attestedAt` must be within the registered publication
   window and strictly earlier than the target NIST pulse. This is a public
   execution-and-publication commitment, not local scientific attempt state.
5. At or after the registered target timestamp, reopen the exact public
   execution-reservation release and receipt and repeat the immediate
   fail-closed host/runtime/private-snapshot gates. Then durably create the
   local `attempt-reservation.json` and `attempt-marker.json`. Only after both
   local transitions may the supervisor fetch and verify the exact registered
   pulse, derive selection, and start the networkless macOS workers. No
   confirmatory forward pass is permitted before the pulse or outside these
   post-marker workers. The marker and live NIST start observation must be in
   `[2026-08-21T18:00:00Z, 2026-08-21T18:15:00Z)`; completion must be strictly
   before `2026-08-22T18:00:00Z`.
6. Run all three selected models, consolidate evidence, and require the fresh
   independent real-model replay before a gate verdict can be written.
7. Publish every terminal class and all surviving bytes. Every later execution
   is separately identified regression or replication evidence.

The outer-runner anonymous-pipe handoff binds the live parent/child,
process-group, canonical paths, deadline, poll interval, nonce, and no-retry
value. It is not parent-implementation authentication or watchdog attestation:
a custom parent controlled by the same user can construct a conforming
handoff. The public outer runner remains mandatory procedure, while this local
mechanism is only an accidental-misuse and value-binding guard.

NIST supplies publicly verifiable future randomness for committed choices. It
does not prove that the operator was blind, that no hidden run occurred, or
that the experiment is independently administered. The public pre-pulse
execution reservation makes the obligation to execute once or publish the
registered closeout auditable before the pulse. It does not cryptographically
prevent undisclosed conduct or upgrade the governance boundary beyond author
self-verification.

That reservation deterministically fixes the sole public `attemptId`; the
local marker, worker capability, and evidence must reuse it. This prevents a
second copied root or VM from becoming a differently identified official
attempt, but it cannot reveal undisclosed computation by the machine owner.

Once public, the pulse can be fetched and the deterministic selection can be
derived outside the registered runner. Local code cannot prove that no hidden
fetch, selection, or run occurred; the protocol therefore makes no operator-
blindness claim.

Likewise, crawler not-before times admit multiple technically valid corpus
roots. The signed snapshot release fixes the chosen bytes before the pulse,
but local code cannot prove there was no snapshot shopping and the release is
not an externally witnessed first-crawl proof.

## Terminal meaning

- `PASS`: all six model×corpus cells, all three selected-model aggregate gates,
  structural replay, and independent replay pass.
- `FAIL_GATES`: the complete execution is valid, but at least one registered
  metric gate fails.
- `FAIL_EXECUTION`: the consumed attempt cannot complete validly because of a
  crash, deadline, resource, integrity, asset, runtime, sandbox, or verifier
  failure.
- `CONSUMED_INCOMPLETE`: a local durable `attempt-reservation.json` exists but
  no canonical terminal outcome can be completed from the surviving state.

A valid public execution reservation followed by no local attempt before the
hard deadline requires the registered `NO_ATTEMPT_EXPIRED` closeout. It is not
a PASS, a retry permission, or a terminal attempt state.

Only `PASS` supports the confirmatory claim. `FAIL_EXECUTION` and
`CONSUMED_INCOMPLETE` do not prove that the codec fails its behavioral margins,
but the confirmatory experiment is unsuccessful and cannot be rerun under the
same identity. They must not be omitted, converted into a neutral unpublished
event, or replaced by a later green regression.

## Platform boundary

The primary numerical experiment and its bit-exact fresh replay run only on the
frozen macOS arm64 CPU runtime. Linux x86-64 and macOS arm64 CI must both pass
on the exact implementation commit with zero skips, but those CI jobs establish
source, build, schema, packaging, and verifier portability—not a second
scientific attempt and not cross-platform bit identity.

A Linux user can rebuild the locked Linux runtime, verify source and release
identities, replay selection and artifact structure, and run registered
CI/portability controls that perform no confirmatory inference. The registered
real-model pilot E2E and primary numerical one-shot are macOS arm64 only. A
Linux real-model run is forbidden before the primary terminal outcome; a later
run requires a separately preregistered replication or regression identity and
cannot rescue or modify that outcome.

## Development commands

From an exact clean checkout and locked Python 3.12.10 runtime:

```sh
/path/to/locked/python -I -B blind_v1/run_zero_skip_tests.py
/path/to/locked/python -I -B blind_v1/verify_design.py
/path/to/locked/python -I -B blind_v1/preflight.py \
  --codec-root /path/to/exact/core-lm-benchmark
```

Materializing assets performs no inference and creates no attempt state:

```sh
python3 blind_v1/fetch_assets.py \
  --manifest blind_v1/model-assets.draft.json \
  --destination blind_v1/.assets \
  --small-files-only \
  --include-development-dataset
```

Do not run the scientific runner from a draft checkout.
`verify_design.py --require-freezable` and
`preflight.py --require-execution-ready` must remain
fail-closed until every immutable input, receipt, trust binding, public
execution-reservation control, and exact-commit gate exists.

## Documentation map

- [`PROTOCOL.md`](PROTOCOL.md): complete normative procedure and claim meaning.
- [`FREEZE_READINESS.md`](FREEZE_READINESS.md): fail-closed P0 checklist.
- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md): clean-clone and runtime procedure.
- [`COLLECTOR_AND_BEACON_API.md`](COLLECTOR_AND_BEACON_API.md): corpus and NIST
  transport contract.
- [`EVIDENCE_RELEASE.md`](EVIDENCE_RELEASE.md): positive and negative evidence
  packaging.
- [`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md): signed immutable-release
  receipts, including the pre-pulse public execution reservation.
- [`CLOSEOUT.md`](CLOSEOUT.md): no-attempt and late-publication classifications.
- [`ARCHIVAL.md`](ARCHIVAL.md): DOI, Zenodo, ORCID, SBOM, citation, and rights
  archive.

Until all P0 gates have immutable evidence, the only valid lifecycle state is
`DRAFT_NOT_PREREGISTERED`, `readyToFreeze=false`, and
`countsTowardScientificVerdict=false`.
