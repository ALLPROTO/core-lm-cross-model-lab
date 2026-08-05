# Blind cross-model v1 freeze-readiness gate

This checklist is subordinate to [`PROTOCOL.md`](PROTOCOL.md). It cannot
change a registered identity, date, model, corpus rule, metric, platform, or
failure class. A checked box is evidence only when the cited immutable bytes
and receipts exist; prose assertions and locally edited status fields do not
satisfy a gate.

The suite uses `AUTHOR_SELF_VERIFICATION`. The repository owner is the author,
experiment operator, and release operator. No independent human review, peer
review, operator blindness, independent validation, or independent replication
is required or claimed. These are immutable design fields.

## P0 before the design release

- [ ] One exact clean lab commit/tree contains the complete normative protocol,
  schemas, prior-observation record, collector, selector, NIST verifier,
  runner, durable state machine, public execution-reservation control, source
  sealer, evidence packager, closeout verifier, and independent software replay.
- [ ] The codec commit/tree, candidate rule, complete-container byte scope,
  BF16 cache baseline, thresholds, teacher-forced evaluation, and all runtime
  locks are fixed. No confirmatory-pool observation was used to choose them.
- [ ] [`prior-observations.json`](prior-observations.json) is schema-valid and
  completely discloses candidate and threshold lineage, all previously run
  revisions, the negative Pythia result, and the broad architecture-family
  overlap with the confirmatory pool.
- [ ] The six confirmatory revisions are pinned by repository commit, every
  required path, byte count, SHA-256, tokenizer vocabulary, architecture, layer
  count, KV geometry, and the separately hashed exact model-card evidence in
  [`../LICENSES/blind-v1-model-card-evidence.json`](../LICENSES/blind-v1-model-card-evidence.json).
  The frozen design and freeze manifest bind that evidence, and the archival
  verifier cross-checks it against all six frozen model identities. None is an
  exact revision listed as previously run.
- [ ] No forward pass, cache production, candidate encoding, candidate metric,
  or behavioral probe has been performed on any of the six confirmatory
  revisions. Allowed pre-pulse operations are limited to download, byte count,
  SHA-256, strict configuration/tokenizer parsing, tokenizer-length
  eligibility, and safetensors-header validation.
- [ ] The real-data development E2E runs only on the three previously observed
  pilot revisions excluded from the confirmatory pool. It uses the exact pinned
  UD English PUD r2.18 bytes and completes producer → VTL5 → independent fresh
  real-model replay on the exact implementation and locked macOS arm64 runtime.
  Its report states `countsTowardScientificVerdict=false`,
  `usedForCandidateSelectionOrTuning=false`, `futureCorpusUsed=false`,
  `nistUsed=false`, and `scientificAttemptStateCreated=false`.
- [ ] The pilot E2E report, logs, source corpus, rights evidence, every token and
  container record, and external pilot-asset receipt are archived without
  changing any scientific parameter in response. A failed pilot control is
  preserved; it is not rewritten as PASS.
- [ ] The pilot development receipt and the six-model confirmatory-pool receipt
  are distinct and unambiguous. The pilot archive cannot satisfy the
  confirmatory-pool asset gate, and confirmatory weights are never imported by
  the pilot control.
- [ ] Every confirmatory asset is fully rehashed locally with no-follow reads.
  The frozen design binds the complete pool manifest and receipt even though
  only three revisions will later be selected.
- [ ] A clean runtime manifest and CycloneDX SBOM bind the exact lab and codec
  trees, interpreter, lock files, runtime bytes, pilot-control inputs, and
  confirmatory-pool receipt without secrets or mutable paths.
- [ ] The tracked NIST leaf, intermediate, and root form the exact registered
  production chain and are valid at the target pulse. The live production
  profile, signature reconstruction, output construction, exact timestamp,
  hostname, transport CA, offline manifest digest, and separately pinned root
  digest all verify before freeze. Fixture trust cannot satisfy this gate.
- [ ] The signed immutable design release and its canonical receipt bind every
  normative Markdown/JSON/schema/code hash, source commit/tree, model pool,
  prior observations, selection rule, dates, runtime, SBOM, trust material,
  signing public key, CI evidence, and public execution-reservation release plan.
- [ ] The marker and live NIST start observation are both restricted to the
  half-open fifteen-minute window beginning at the target pulse; completion
  remains restricted by the separate hard deadline.
- [ ] The design explicitly states that NIST supplies selection randomness but
  does not prove operator blindness, absence of hidden runs, or independent
  administration; the pulse and deterministic selection can be derived
  outside the registered runner, and local code cannot prove otherwise.

## P0 exact-commit CI and platform boundary

- [ ] Linux x86-64 and macOS arm64 clean-clone jobs execute the exact registered
  workflow bytes on the exact implementation commit and both finish success
  with zero skipped or cancelled jobs.
- [ ] The CI collector archives exactly the registered PR, workflow-run, jobs,
  and artifact API observations. Its evidence boundary says GitHub did not sign
  those API responses and offline replay proves structural consistency only.
- [ ] The exact Linux and macOS Actions ZIP bytes are included separately in
  the design release and match their receipt digests, job identities, runtime
  locks, source tree, zero-skip logs, and known-answer cryptographic reports.
- [ ] The frozen design identifies macOS arm64 CPU as the sole primary
  scientific numeric runtime. Linux CI is a source/build/schema/packaging and
  verifier-portability gate, not a Linux scientific attempt or bit-exact
  replication.
- [ ] No Linux real-model result can contribute to, replace, average with, or
  rescue the primary macOS terminal outcome. Linux real-model inference is
  forbidden before that terminal outcome; any later inference requires a
  separately preregistered replication/regression identity.
- [ ] The author signs the exact self-verification declaration. No bot, Codex
  agent, second author-controlled account, self-review, or CI result is labeled
  independent human review or peer review.

## P0 after design publication and before the pulse

- [ ] The prospective page interval begins only after the verified design
  publication time. Both registered MediaWiki crawls and finalization preserve
  exact request URIs, headers, response bodies, creation-revision records,
  canonical ledgers, token commitments, and attribution.
- [ ] Every language ledger meets the preregistered minimum. If one does not,
  the suite expires without changing languages, eligibility, page count, or
  using an alternate corpus under the same identity.
- [ ] The snapshot registration commits the complete three-ledger pool and the
  six-model tokenizer commitments before selection. The signed immutable
  snapshot release and separate receipt have verified `attestedAt` strictly
  before the snapshot deadline and target pulse.
- [ ] The design discloses that crawler not-before times admit multiple valid
  corpus roots: the signed snapshot fixes chosen bytes before the pulse but is
  neither proof against snapshot shopping nor an externally witnessed first
  crawl.
- [ ] The private content-addressed snapshot seals the frozen design and
  receipts, all six confirmatory model assets, complete corpus snapshot, exact
  Git object graphs, runtime, CA, and NIST trust bytes without symlinks.
- [ ] The canonical `execution-reservation.json` binds the exact frozen design,
  snapshot and snapshot receipt, codec/lab identities, candidate digest, all
  six confirmatory revisions, target pulse, one-shot window, hard deadline,
  `retryPermitted=false`, and the obligation to publish terminal evidence or
  closeout. It derives no selection, loads no model, and states
  `countsTowardScientificVerdict=false`.
- [ ] Exactly three canonical assets are published under the signed annotated
  tag `corelm-blind-crossmodel-v1-execution-reservation`: the execution
  reservation, snapshot publication receipt, and SHA-256 manifest. The
  canonical release receipt verifies their complete inventory and immutable
  server attestation.
- [ ] The verified RFC3161 `attestedAt` is within
  `[2026-08-20T18:00:00Z, 2026-08-21T17:45:00Z)` and therefore precedes the
  target pulse. Failure or late publication leaves the confirmatory claim
  unsupported; a local timestamp, backdated field, later release, different
  pulse, or reused corpus cannot repair it.
- [ ] The public execution reservation is an auditable intent and outcome
  obligation, not `attempt-reservation.json`, an attempt marker, operator
  blindness, or evidence that local execution has begun. It permits no second
  public reservation under the same suite identity.

## P0 one-shot execution

- [ ] No forward pass or candidate scoring on any confirmatory-pool revision
  occurs before the target pulse. This includes unselected pool members and
  records whose later selection can be inferred from the public pulse.
- [ ] After the pulse, confirmatory inference remains forbidden outside the
  registered post-marker workers. The scientific invocation first verifies the
  exact public execution-reservation assets and canonical release receipt.
- [ ] All deterministic host checks complete before local attempt state: exact
  macOS arm64 runtime, AC power, memory, disk, source, sandbox backend, pristine
  result boundary, private-snapshot identity, and dependency import probes.
  They perform no model forward pass and do not derive selection.
- [ ] The design and public runbook state that the anonymous-pipe handoff binds
  live parent/child, process-group, path, deadline, poll, nonce, and no-retry
  values only. It does not authenticate the parent implementation or attest
  watchdog behavior, and a custom same-user parent can reproduce it. No wire
  identifier containing `authorization` is presented as stronger evidence.
- [ ] The state machine then durably publishes the local
  `attempt-reservation.json` and `attempt-marker.json` before selection is
  resolved or selected corpus/model bytes are opened by an inference path.
  Once local reservation state exists, interruption cannot authorize another
  local attempt.
- [ ] Only the supervisor makes the one exact registered NIST request. It
  accepts no `latest`, `nearest`, redirect, proxy, alternate host, alternate
  beacon, extra request, or fallback pulse.
- [ ] The supervisor verifies and durably seals the exact raw pulse, certificate
  chain, signature, timestamp, and output construction before applying the
  frozen rejection-sampling rule.
- [ ] NIST selects two language ledgers, sixteen pages from each, and three
  model revisions from the six-model pool without replacement. The selected
  model order is mandatory. No model, page, corpus, or order substitution is
  permitted after selection.
- [ ] Each producer and the later independent verifier is networkless from
  process creation, loads one selected model at a time from verified owned
  bytes, and remains within the fixed RSS and hard-deadline controls.
- [ ] The independent verifier retokenizes frozen corpus bytes, regenerates the
  canonical BF16 baseline, independently decodes VTL5 containers, recomputes
  every loss bit pattern and top-1 ID, and byte-matches the producer result
  before `PASS` or `FAIL_GATES` can be written.

## Terminal semantics and evidence

- [ ] `PASS` requires all six selected model×corpus cells, all three selected
  model aggregates, every structural gate, and the complete independent replay.
  A negative model or corpus is never averaged away.
- [ ] `FAIL_GATES` records a complete valid execution with at least one failed
  scientific metric gate.
- [ ] `FAIL_EXECUTION` records a consumed attempt invalidated by resource,
  deadline, crash, runtime, asset, integrity, sandbox, or verifier failure.
- [ ] `CONSUMED_INCOMPLETE` preserves local attempt-reservation, marker, and
  pending-transition bytes when no canonical terminal result can be completed.
- [ ] A valid public execution reservation with no local attempt before the hard
  deadline is closed out as `NO_ATTEMPT_EXPIRED`; it is not a terminal attempt
  state, PASS, or retry authorization.
- [ ] Only `PASS` supports the preregistered exact-sample claim. Every other
  terminal or closeout class means the confirmatory experiment did not provide
  that support. Execution failure is not evidence that the codec violated its
  metric margins, but it is not neutral, retryable, or omittable.
- [ ] Every consumed state is packaged and published, including partial and
  negative evidence. Missing artifacts are reported as absent; placeholders are
  never fabricated and a later regression never replaces the one-shot outcome.
- [ ] The evidence package preserves the public execution-reservation assets
  and receipt, durable local state, raw NIST exchange and chain, selection,
  complete corpus bytes and attribution, environment, source trees, asset
  receipts, token IDs and loss bits, top-1 IDs, VTL5 containers, byte
  accounting, logs, resource receipts, result, independent-verifier report,
  and SHA-256 manifest.
- [ ] The signed immutable evidence release and its separate receipt satisfy the
  registered publication deadline. A late release is
  `LATE_PUBLICATION_INVALID`, never a retroactive PASS.

## Whole-window rescheduling rule

If any pre-publication P0 gate is unproven at the decision checkpoint, do not
freeze the draft. A replacement receives a new suite ID, exact implementation
commit/tree, model-pool commitment, design release, and complete future
timeline. Move together:

1. design deadline;
2. future corpus interval and both crawl times;
3. snapshot deadline;
4. public execution-reservation publication window;
5. NIST pulse;
6. marker/execution window and hard deadline;
7. evidence and closeout deadlines.

Never reuse a corpus snapshot or pulse that became observable before the
replacement design. Never change one date in isolation or freeze an unfinished
protocol.

`CITATION.cff`, ORCID, DOI/Zenodo metadata, SBOM, `LICENSES/`, and
`NOTICE.md` remain required for archival publication, but they cannot replace
any scientific-evidence gate above.

Until every applicable box has immutable evidence, the only valid lifecycle
state is `DRAFT_NOT_PREREGISTERED`, `readyToFreeze=false`, and
`countsTowardScientificVerdict=false`.
