# Core LM blind cross-model v1

Status: **development draft — not frozen, not preregistered, and not run**.

Lifecycle outcome: the `2026-08-08T12:00:00Z` decision checkpoint elapsed
while mandatory P0 inputs, the exact-commit CI receipt, and the immutable
design release were still absent. Under the registered reschedule policy,
`corelm-blind-crossmodel-v1` is permanently non-freezable and must not be
published as a preregistration. Any successor must use a new suite ID and move
the complete dependent corpus, snapshot, NIST, attempt, evidence, and closeout
timeline together. The draft remains public only as an auditable development
record; no model, corpus, NIST, reservation, or scientific attempt was opened.

`blind_v1/` is the archived, unexecuted confirmatory design contour for
`corelm-blind-crossmodel-v1`. It is separate from the public-validation
regressions and the V2–V4 development contours. Nothing in this directory is a
scientific result, and no later action can turn this suite identity into one.
The procedure below is retained only as the counterfactual record of what would
have been required had every gate completed before the checkpoint. It is not a
runbook and does not authorize freeze, publication, corpus collection, asset
materialization, NIST access, reservation, or execution.

The project uses `AUTHOR_SELF_VERIFICATION`. Ivan Tyshchenko is the author,
experiment operator, and release operator. The separate verifier and fresh
real-model replay are implementation-level separation inside the same
author-controlled artifact. They are not independent human review, peer
review, operator blindness, independent validation, or independent
replication.

## Archived claim that was never tested

The draft would have tested the fixed VoidToken candidate on:

- three exact model revisions selected without replacement by a future NIST
  pulse from a frozen six-revision confirmatory pool;
- two language editions selected from the frozen German, English, and French
  Wikipedia ledgers;
- sixteen future page-creation revisions selected from each chosen ledger;
- the frozen macOS arm64 CPU runtime and the registered complete-container,
  delta-NLL, top-1, and structural-replay gates.

A hypothetical valid `PASS` would have supported only this exact selected
sample: three revisions, thirty-two
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

The archived draft fixed the intended pool by repository, revision, every
required asset size, and SHA-256. A timely immutable design release would have
frozen those bytes before NIST selected exactly three entries without
replacement. That release never existed, so these are historical proposed
bindings only and must not be used for a V1 selection or run.

| Key | Exact repository revision | Architecture |
|---|---|---|
| `pythia-160m` | `EleutherAI/pythia-160m@50f5173d932e8e61f858120bcb800b97af589f46` | GPT-NeoX MHA |
| `pythia-70m` | `EleutherAI/pythia-70m@a39f36b100fe8a5377810d56c3f4789b9c53ac42` | GPT-NeoX MHA |
| `smollm-135m` | `HuggingFaceTB/SmolLM-135M@1d461723eec654e65efdc40cf49301c89c0c92f4` | Llama GQA |
| `smollm-360m` | `HuggingFaceTB/SmolLM-360M@59f7ef243ee09a72cbc14cb054393a3e3b771d41` | Llama GQA |
| `gpt2-124m` | `openai-community/gpt2@607a30d783dfa663caf39e06633721c8d4cfcd7e` | GPT-2 MHA |
| `distilgpt2-82m` | `distilbert/distilgpt2@2290a62682d06624634c1f46a6ad5be0f47f38aa` | GPT-2 MHA |

The current draft's prior-observation disclosure states that none of these
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

## Archived development-control design

The proposed real-data pre-freeze E2E would have used only previously observed
pilot revisions excluded from the confirmatory pool: GPT-Neo-125M,
SmolLM2-360M, and Tiny StarCoder. It would have run the producer, VTL5 codec,
and independent real-model replay
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

## Archived counterfactual experiment sequence — non-executable

The following seven steps record the procedure that would have applied only
after a valid pre-checkpoint freeze. Because that prerequisite failed, every
step is permanently unauthorized for `corelm-blind-crossmodel-v1`.

1. The operator would have published the signed immutable design and its
   canonical receipt before the
   design deadline.
2. The operator would have collected the prospective corpus exactly as
   registered, published the signed immutable snapshot, and sealed the private
   content-addressed execution input.
3. The operator would have completed all deterministic design, snapshot,
   asset, and reservation-package preflight checks without model inference.
4. The operator would have built the three canonical public
   execution-reservation assets, including `execution-reservation.json`, and
   published them under the preregistered signed
   immutable tag `corelm-blind-crossmodel-v1-execution-reservation`. Its
   verified RFC3161 `attestedAt` must be within the registered publication
   window and strictly earlier than the target NIST pulse. This is a public
   execution-and-publication commitment, not local scientific attempt state.
5. At or after the registered target timestamp, the supervisor would have
   reopened the exact public
   execution-reservation release and receipt and repeat the immediate
   fail-closed host/runtime/private-snapshot gates. Then durably create the
   local `attempt-reservation.json` and `attempt-marker.json`. Only after both
   local transitions may the supervisor fetch and verify the exact registered
   pulse, derive selection, and start the networkless macOS workers. No
   confirmatory forward pass is permitted before the pulse or outside these
   post-marker workers. The marker and live NIST start observation must be in
   `[2026-08-21T18:00:00Z, 2026-08-21T18:15:00Z)`; completion must be strictly
   before `2026-08-22T18:00:00Z`.
6. It would have run all three selected models, consolidated evidence, and
   required the fresh independent real-model replay before a gate verdict
   could be written.
7. The operator would have published every terminal class and all surviving
   bytes. No such V1 execution or publication is now permitted.

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

## Archived platform boundary

The proposed primary numerical experiment and its bit-exact fresh replay would
have run only on a frozen macOS arm64 CPU runtime. Linux x86-64 and macOS arm64
CI would both have had to pass
on the exact implementation commit with zero skips, but those CI jobs establish
source, build, schema, packaging, and verifier portability—not a second
scientific attempt and not cross-platform bit identity.

The Linux and macOS provisions remain historical audit material. They do not
authorize rebuilding V1 scientific inputs or running V1 inference. A successor
must publish its own suite identity, platform contract, preregistration, and
fully rescheduled timeline.

## Permitted offline historical-audit commands

From an exact clean checkout and locked Python 3.12.10 runtime:

```sh
/path/to/locked/python -I -B blind_v1/run_zero_skip_tests.py
/path/to/locked/python -I -B blind_v1/verify_design.py
```

These commands inspect tracked bytes and fixtures only. Do not materialize V1
assets, collect its corpus, access its target NIST pulse, package a V1 freeze,
prepare a V1 private snapshot, or invoke either runner command.
`verify_design.py --require-freezable` must fail permanently with
`CHECKPOINT_MISSED_TERMINAL_DRAFT`; old blockers are not a completion queue.

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

The only valid lifecycle state is permanently
`CHECKPOINT_MISSED_TERMINAL_DRAFT` with `DRAFT_NOT_PREREGISTERED`,
`readyToFreeze=false`, `freezeAllowed=false`, `publicationAllowed=false`,
`scientificExecutionAllowed=false`, `successorSuiteIdRequired=true`, and
`countsTowardScientificVerdict=false`.
