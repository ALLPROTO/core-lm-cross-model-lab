# Core LM blind cross-model v1 — normative protocol draft

Status: **DRAFT — not frozen, not published, not preregistered, and not run**.

This tracked file is the complete normative prose companion to
`design-registration.draft.json`. It must not be represented as scientific
evidence. The frozen author disclosure states that the confirmatory model pool
contains six exact revisions that have not undergone a forward pass, cache
production, candidate scoring, or candidate comparison in this project. The
public record makes the statement auditable but cannot prove the absence of an
undisclosed run. The prohibition applies to the whole
pool before the target NIST pulse because the three selected revisions are not
known in advance.

Before the pulse, pool assets may only be downloaded, byte-counted, hashed,
strict-parsed as configuration/tokenizer data, checked at the safetensors
header level, and used for tokenizer-length eligibility. The real-data
development E2E uses only previously observed pilot revisions excluded from
the confirmatory pool. It exercises producer → VTL5 → independent fresh
real-model replay on the byte-pinned UD English PUD r2.18 source, but it cannot
screen a confirmatory model or count toward the scientific verdict.

This document becomes a preregistration only when the fail-closed freeze
validator binds it into a signed immutable public design release after every
author-self-verification, exact-commit CI, pilot E2E, signing, packaging, and
verifier gate is implemented and verifiable. The later public execution reservation is a
separate pre-pulse lifecycle gate: it must use the already frozen design and
cannot repair an incomplete design freeze.

All earlier candidate, threshold, corpus, and model observations—including the
negative Pythia-410M result and the V4 pilot-model E2E—are development lineage,
not blind-v1 evidence. Their exact identities and roles are disclosed in
`prior-observations.json`. Broad GPT-2, GPT-NeoX/Pythia, and Llama families have
therefore been observed even though none of the six confirmatory revisions has
been run. This is an exact-revision holdout, not an architecture-blind claim.
No V2, V3, V4, legacy-root report, tag, receipt, release, or source identity can
satisfy a blind-v1 gate.

## Normative authority and meaning of “blind”

The frozen design JSON, canonical schemas, this protocol, and the exact frozen
implementation form one contract; none may silently override another. For
overlapping requirements, the frozen design is authoritative for enumerated
identities, fixed values, dates, and gates; the schemas are authoritative for
serialized structure and types; and this protocol is authoritative for
procedure, cross-artifact semantics, and claim interpretation. The frozen
code is subordinate implementation of that contract. Any incompatible overlap
is a P0 contradiction that invalidates freeze or execution rather than a choice
of whichever source is more convenient.

In this suite, “blind” means a **prospective beacon-selected exact-revision and
future-record holdout**. Eligible corpus revisions are created after design
publication, and a future NIST pulse selects two corpora, thirty-two pages, and
three exact model revisions from the frozen six-revision pool. NIST supplies
future randomness for choices already committed by public bytes; it does not
prove operator blindness, absence of hidden execution, independent
administration, or authoritative experiment time.

The target pulse is public, so the author can fetch it and derive the complete
deterministic selection outside the registered runner once it exists. The
tracked state machine and evidence can make a registered run auditable, but
local code cannot prove that no hidden fetch, selection, or run occurred. This
is a normative residual author-control limitation, and operator blindness is
not claimed.

The registered crawler not-before times also permit more than one technically
valid corpus root. Local code cannot prove that the author did not collect and
compare multiple valid roots before choosing one. The signed snapshot release
fixes the chosen bytes before the pulse, but it is not an externally witnessed
proof that those bytes came from the first eligible crawl; no first-crawl or
snapshot-shopping-resistance claim is made.

No pool-model forward pass or candidate scoring is permitted before the target
pulse. After the pulse, confirmatory-model inference remains forbidden except
inside the registered post-marker workers. No selected-record inference is
permitted before the durable marker.
The exact no-retry public execution reservation must additionally receive a
verified RFC3161 `attestedAt` strictly before the pulse. It records the
obligation to execute once or publish the registered closeout; it does not
create local attempt state or cryptographically prevent undisclosed conduct.
Stronger operator blindness requires an external witness or attested execution
environment fixed before design publication.

## Governance and verification boundary

This suite uses `AUTHOR_SELF_VERIFICATION`. The repository owner is also the
author, experiment operator, and release operator. No independent human review
is required or claimed; no peer review, operator blindness, or independent
replication is claimed. The separate verifier process, independent decoding,
and fresh real-model replay are implementation-level separation inside the
same author-controlled project, not human or organizational independence.

The GitHub gate is exact-commit CI-only. It archives four API observations
(pull request, workflow run, all jobs, and artifacts), never calls the reviews
endpoint, and contains no reviewer identity, approval state, or review
declaration. Removing human review does not waive any exact-commit, clean-clone,
zero-skip, platform-artifact, real-data E2E, signed-release, publication-receipt,
or independent-verifier requirement.

## Claim under test

The suite tests whether one VoidToken candidate, fixed before the confirmatory
pool or future corpus is scored, meets every registered gate on three exact
model revisions and thirty-two future Wikipedia creation revisions selected by
the registered NIST pulse. There are six exact model×corpus cells; every cell
and all three selected-model aggregates are mandatory.

This is an exact-sample claim. A `PASS` applies only to the selected three
revisions, selected thirty-two pages, frozen corpus snapshot, dates, primary
macOS arm64 runtime, codec, BF16 cache baseline, and metrics. The fixed
Student-t and Wilson values are descriptive gates, not IID population
confidence claims. A `PASS` does not establish performance for the three
unselected pool revisions, an architecture family, a complete language
edition, all Wikipedia, all LLMs, all text, another OS/runtime, weight
compression, free-running generation, latency, throughput, or state of the
art.

Proposed suite ID:

```text
corelm-blind-crossmodel-v1
```

## Confirmatory model pool and pilot controls

The beacon selects exactly three revisions without replacement from the table
below. All three selected revisions are mandatory and run in selection order;
a failing or unavailable model is never replaced by an unselected pool member.
Pickle weights, `trust_remote_code`, mmap, path-based model parsing, and
`from_pretrained` are forbidden in the scientific worker.

| Key | Exact revision | Architecture | Layers / KV heads | `model.safetensors` bytes | Expected SHA-256 |
|---|---|---|---:|---:|---|
| `pythia-160m` | `EleutherAI/pythia-160m@50f5173d932e8e61f858120bcb800b97af589f46` | GPT-NeoX MHA | 12 / 12 | 374,998,696 | `29d2e457a664e41c12c735f20a36dc0956a665f614a54ce5db21a32e75965270` |
| `pythia-70m` | `EleutherAI/pythia-70m@a39f36b100fe8a5377810d56c3f4789b9c53ac42` | GPT-NeoX MHA | 6 / 8 | 166,029,852 | `ebfa4e2f18696ebd83716a0d39fe2c025f2ff8483f72a83ca59c475692fc9d15` |
| `smollm-135m` | `HuggingFaceTB/SmolLM-135M@1d461723eec654e65efdc40cf49301c89c0c92f4` | Llama GQA | 30 / 3 | 538,090,408 | `c7a387d6fe81ca6dd304aeb809bda3932ff1bbef3ca41c9484502f2f448dc093` |
| `smollm-360m` | `HuggingFaceTB/SmolLM-360M@59f7ef243ee09a72cbc14cb054393a3e3b771d41` | Llama GQA | 32 / 5 | 1,447,317,080 | `e91f05d8506ee5efbd8c0fbfc1799c49af2b2f2cce824bc2d801d5af2a716cc2` |
| `gpt2-124m` | `openai-community/gpt2@607a30d783dfa663caf39e06633721c8d4cfcd7e` | GPT-2 MHA | 12 / 12 | 548,105,171 | `248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707` |
| `distilgpt2-82m` | `distilbert/distilgpt2@2290a62682d06624634c1f46a6ad5be0f47f38aa` | GPT-2 MHA | 6 / 12 | 352,824,413 | `e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b` |

Every required file, not only the weight, is committed by path, byte count,
SHA-256, source repository, and exact revision. Full pool bytes are sealed
before the public execution reservation even though only three models will be selected.
Asset materialization and rehashing perform no model import or inference.
The separate
[`../LICENSES/blind-v1-model-card-evidence.json`](../LICENSES/blind-v1-model-card-evidence.json)
commits all six exact-revision README bytes and their declared license IDs. It
is bound by the design and freeze manifest and reverified from the Zenodo
`LICENSES` archive against the ordered frozen `models` array. No standalone
`LICENSE*` or `NOTICE*` file exists in any of the six exact revision trees, so
none is claimed or fabricated.

The single real-data development E2E instead uses the previously observed,
excluded pilot revisions GPT-Neo-125M, SmolLM2-360M, and Tiny StarCoder on the
pinned UD English PUD r2.18 bytes. It verifies the lossless adapter invariant,
fixed candidate producer, VTL5 serialization/decoding, and independent replay
without screening the confirmatory pool. Its report must state
`countsTowardScientificVerdict=false`,
`usedForCandidateSelectionOrTuning=false`, `futureCorpusUsed=false`,
`nistUsed=false`, and `scientificAttemptStateCreated=false`.

Only this non-scientific pilot E2E may wait for transient host-memory
recovery: the tracked policy fixes a 300-second total window and two-second
polling while retaining the registered 50% floor. Invalid configuration,
unparseable inspection output, and every non-memory failure are not retried.
The prospective scientific one-shot has no such wait and fails immediately at
its separate pre-marker host gate.

The full pilot E2E is an implementation freeze-readiness gate, not a
confirmatory-model gate. Its canonical report and logs are archived before
freeze; scientific PASS/FAIL thresholds are not applied. A negative diagnostic
is preserved, and no outcome may justify changing the candidate, confirmatory
pool, protocol, runtime, or dates under the same suite identity. The control
uses a strict standard-library CoNLL-U
parser: it requires 1,000 source-order sentence blocks with one `# sent_id = `
and one `# text = ` value, joins the unchanged text values with two LF bytes,
and creates 32 contiguous floor-boundary partitions. Its source is
`inputs/corpus/en_pud-ud-test.conllu`, copied from the exact fetch path
`blind_v1/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`.

The pilot control's complete 2,088-artifact evidence set carries the corpus manifest, source bytes,
`inputs/LICENSES/source-evidence.json`, `inputs/LICENSES/ASSET_LICENSES.md`,
the exact upstream README and license, and
`inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md`. The pinned upstream metadata,
README, and license consistently declare CC BY-SA 3.0. Publication must retain
attribution, identify the license and URI, mark the extraction/partition
changes, apply share-alike-compatible terms to reversible/source-derived
evidence, and add no effective restrictions. This is a byte-verifiable record
of upstream declarations, not an independent ownership or chain-of-title
conclusion.

The 2,088-member pilot set and its deterministic release ZIP intentionally contain
no model weights. The 24 pilot-model files remain external private inputs; the
sealed plan, pinned model-asset manifest, and complete local rehash receipt bind
their exact paths, byte counts, and SHA-256 values. Within this evidence set,
the receipt's only canonical member path is
`inputs/development-model-assets.full-rehash.json`;
`inputs/full-asset-receipt.json` is forbidden here. This pilot receipt cannot
substitute for the separately frozen six-model confirmatory-pool manifest and
full receipt. The packager and verifier
require the pilot ZIP to remain strictly below
1,800,000,000 bytes and reject missing, extra, duplicate, or accidentally
embedded model members.

The packager and archive verifier re-open those rights bytes and every artifact
before emitting the three release assets. The signed annotated development tag,
immutable release, and canonical immutable-release attested receipt must bind
those exact assets with `attestedAt` strictly before the design deadline;
manually assembled archives, local timestamps, and GitHub API timestamps do
not satisfy the freeze gate.

The exact pilot identities and all earlier outcomes remain disclosed in
`prior-observations.json`; they are not members of the confirmatory pool.

## Two-stage future-corpus freeze

The tracked NIST leaf expires at `2026-09-04T23:59:59Z`, after the proposed
`2026-08-21T18:00:00.000Z` pulse. Calendar validity alone is insufficient: the
complete production leaf/intermediate/root chain, exact certificate ID,
signature reconstruction, output construction, hostname, transport CA,
offline manifest digest, and separately pinned root digest must all verify on
the exact freeze candidate. This suite remains `DRAFT_NOT_PREREGISTERED` until
those checks pass and every resulting commitment is propagated through the
design, schemas, freeze manifest, and tests. Trust cannot change after design
freeze or after the pulse is observed.

The design registration must be published as an immutable GitHub release under
the proposed tag `corelm-blind-crossmodel-v1-design` strictly before
`2026-08-09T00:00:00Z`. The signed annotated tag must target the exact
author-self-verified and CI-successful implementation commit/tree recorded in
`labSource`; a separate
later publication commit is forbidden. The canonical frozen design JSON and
freeze manifest are constructed outside that Git tree and uploaded as immutable
release assets. The signed tag and release must bind the exact implementation
commit/tree, canonical frozen design bytes, runtime manifest, full asset
receipt, SBOM, CI artifacts, CI-only gate, author-self-verification boundary,
and every normative source hash. A
canonical publication receipt is collected only after that release exists and
separately binds the tag object, signature verification, GitHub API response
observations, complete asset inventory, and the verified GitHub
immutable-release attestation; it cannot be an asset of the same release it
observes. At collection, pinned GitHub CLI 2.97.0 obtains and verifies the
immutable-release bundle online. Pinned Cosign 3.0.6 then verifies that archived
bundle offline against `blind_v1/trust/github/trusted_root.json`; the independent
verifier repeats the same DSSE, X.509-chain, exact-SAN, selected-asset-digest,
and RFC3161 signature/chain checks and separately replays every signed subject.
The `attestedAt` value is decoded from the raw signed RFC3161 timestamp and must
equal the semantic verification result before the verifier requires it to be
strictly earlier than `2026-08-09T00:00:00Z`; `published_at`, HTTP `Date`, and
local time are not evidence of the freeze. The GitHub bundle has no Rekor entry
or certificate SCT, so the registered Cosign operation uses
`--private-infrastructure --insecure-ignore-sct`: it makes no transparency-log
or SCT claim but does not disable DSSE, X.509, asset-digest, or RFC3161
verification. This is distinct from the CI-only API receipt below, whose
archived response replay remains structural consistency evidence only.

The frozen design and freeze manifest must state
`verificationMode=AUTHOR_SELF_VERIFICATION`,
`independentHumanReviewPerformed=false`, `peerReviewPerformed=false`,
`operatorBlindnessClaimed=false`, and
`independentReplicationClaimed=false`. A GitHub account action, self-review, or
second author-controlled account cannot upgrade these boundaries.

The implementation gate is itself preregistered. The tracked workflow is
`.github/workflows/blind-v1-development-controls.yml`: exactly 13,962 bytes with
SHA-256
`6c0b54bc4c318a2b55069852e07ae3355686ffb49a72c3ca4542396cf5375e87`.
The design, schema, collector, tests, and release evidence all bind those exact
tracked bytes; copied prose, an operator override, or a self-consistent wrong
digest cannot satisfy this gate.
Each lab-source checkout must explicitly use
`${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}`
so a pull-request gate executes the exact head commit rather than GitHub's
synthetic merge ref, while push and manual runs execute `github.sha`.
It must run the exact jobs `Linux x86-64 locked runtime` on `ubuntu-24.04`
with guest assertions `Linux/x86_64`, and `macOS arm64 clean clone` on
`macos-15` with guest assertions `Darwin/arm64`. Every returned job must be
completed/success with zero skipped or cancelled jobs on the exact frozen
head commit. The collector obtains these responses directly from GitHub over
hostname-checked TLS. Because GitHub does not sign the response headers or
bodies and no independently verifiable TLS transcript is archived, the receipt
must declare
`evidenceBoundary=DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_GITHUB_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`.
Offline verification establishes only canonical structure and consistency of
the archived observation, not GitHub origin or authoritative server time. The
GitHub gate receipt archives API state and artifact metadata, not artifact
bytes; its `artifactBytesArchived=false` boundary is also normative.
The exact downloaded Actions ZIP bytes are nevertheless mandatory design-release
assets named `linux-ci-artifact.zip` and `macos-arm64-ci-artifact.zip`. Their
SHA-256 values must equal the matching Linux/macOS `artifactSHA256` commitments
in the gate receipt, whose names bind the same run ID and positive run attempt.
Each bounded, flat ZIP must contain exactly the platform-specific preflight,
runtime manifest, zero-skip log, design-check, and real release-attestation
cryptographic known-answer-result filenames emitted by the tracked workflow.
Verification occurs in memory without extraction and rejects
ZIP64, prefixes/trailers, encryption, special files, nested or extra names,
oversized expansion, a platform mismatch in any report, a runtime/source or
lock-set mismatch, a workflow digest mismatch, a known-answer mismatch, and
any skipped/failed test log.
The macOS CI runtime must contain the exact registered 173-byte
`pip-bootstrap.txt` commitment and 55,781-byte `requirements.lock` commitment;
the Linux runtime must contain that same exact bootstrap commitment plus the
two Linux lock records named by the registered workflow and sealed by the exact
codec commit/tree.
These bytes supplement but cannot replace the exact API receipt; the receipt
metadata likewise cannot replace the bytes or independently authenticate the
origin of its archived API responses offline.

These Linux and macOS jobs are cross-platform source, build, schema,
packaging, and verifier-portability controls. They are not scientific attempts
and do not establish cross-platform numerical identity. The registered primary
one-shot and bit-exact fresh real-model replay run only on the frozen macOS
arm64 CPU runtime. A Linux real-model run may occur only under a separately
preregistered post-outcome replication or regression identity; it cannot
contribute to, replace, average with, rescue, or change the primary macOS
terminal outcome.

Eligible pages are creation revisions timestamped in the half-open interval:

```text
[2026-08-10T00:00:00Z, 2026-08-18T00:00:00Z)
```

The three fixed sources, in this canonical order, are:

```text
0 de.wikipedia.org
1 en.wikipedia.org
2 fr.wikipedia.org
```

After the interval closes, each source is enumerated with the official
[MediaWiki RecentChanges API](https://www.mediawiki.org/wiki/API%3ARecentChanges):

```text
action=query
list=recentchanges
rcstart=2026-08-10T00:00:00Z
rcend=2026-08-18T00:00:00Z
rcdir=newer
rctype=new
rcnamespace=0
rcshow=!bot|!redirect
rcprop=title|ids|timestamp|redirect|sha1|user|userid
rclimit=max
format=json
formatversion=2
```

Two complete crawls are required, the first beginning no earlier than
`2026-08-18T06:00:00Z` and the second no earlier than
`2026-08-19T06:00:00Z`. Each crawl follows `rccontinue` until exhaustion. The
exact request URI, HTTPS response headers, and raw response body for every page
of both crawls are archived. The pinned CA bundle is part of the runtime
manifest, and the HTTPS `Date` header must not precede the crawl's not-before
time.

The ledger is explicitly the union of those two archived snapshots, not a
claim to contain every page created during the interval. The collector
deduplicates by revision ID, filters `start <= timestamp < end`, requires
`old_revid=0`, and sorts by `(timestamp, revid)`. Entries inserted after the
second crawl are outside the defined snapshot. The creation revision is then
fetched strictly by `revid` through the official
[Revisions API](https://www.mediawiki.org/wiki/API%3ARevisions), never by the
page's current title. The title returned by RecentChanges at creation time is
the canonical corpus-input title. The Revisions API page title is independently
strict-UTF-8 validated and recorded only as the inventory provenance field
`revisionAPICurrentTitle`; a later page move neither excludes the revision nor
changes its scientific bytes. Deleted `badrevids` responses have no current
title. History attribution uses the page-identity URL
`https://<project>/w/index.php?curid=<pageid>&action=history`, so it remains
stable across moves.

A candidate is eligible only when all of these conditions hold:

- namespace is 0 and the revision is the page-creation revision;
- the change is neither bot-created nor a redirect;
- the main slot has `contentmodel=wikitext`;
- user, content, and SHA-1 are present and non-hidden, content is non-empty,
  and its API SHA-1 matches;
- `title + "\n\n" + raw_wikitext`, without Unicode normalization or added
  special tokens, produces at least 512 tokens under every pinned tokenizer.

The JSON decoder must accept only valid UTF-8 and reject duplicate keys,
non-scalar strings, lone surrogates, and any title or content that cannot be
strictly re-encoded as UTF-8. No Unicode normalization is permitted. Define:

```text
titleBytes   = UTF8_STRICT(decoded RecentChanges creation title)
contentBytes = UTF8_STRICT(decoded main-slot content)
inputBytes   = titleBytes || 0x0a 0x0a || contentBytes
inputText    = UTF8_STRICT_DECODE(inputBytes)
```

Each archived corpus record has this exact binary serialization. Lengths and
integers are unsigned 64-bit big-endian values:

```text
ASCII("CORELM-BLIND-CROSSMODEL-V1-RECORD\0") ||
len(projectBytes) || projectBytes ||
pageid || revid || userid ||
len(timestampBytes) || timestampBytes ||
len(usernameBytes) || usernameBytes ||
len(titleBytes) || titleBytes ||
len(contentBytes) || contentBytes
```

Canonical-record byte eligibility is inclusive and fixed before collection:
`len(recordBytes) <= 8,388,608`. The exact boundary is eligible; a canonical
record of 8,388,609 bytes is inventory-only with
`canonical-record-exceeds-8388608-bytes`, receives no record commitment, and
cannot enter a ledger or beacon selection. The snapshot verifier independently
reconstructs the canonical record from the archived Revisions response and
reapplies this byte test; it does not trust the inventory's eligibility flag.

`projectBytes` is the canonical ASCII hostname, while timestamp and username
are the exact decoded API strings re-encoded with strict UTF-8. The ledger
records the record-byte count and SHA-256, all identity fields, MediaWiki SHA-1,
revision/permalink/history URLs, author attribution, and the applicable project
license URL. The mutable Revisions API current title remains inventory-only and
is deliberately absent from the canonical ledger and record bytes.

Revision response bundles are durable units containing exactly
`request-uri.txt`, `response-headers.bin`, and `response-body.bin`. A complete
bundle is fsynced and atomically published before its record is written. On
restart, every already committed bundle is replayed byte-for-byte without a
network request; exact existing records, ledgers, and the corpus manifest are
reused, while any mismatch, symlink, special file, or extra path fails closed.
A fully written but not yet renamed `.partial` bundle is validated and promoted
without network access. An incomplete `.partial` bundle is not deleted or
refetched over: finalization stops before transport, and the operator must
discard that prospective corpus and apply the preregistered reschedule rule.
The two RecentChanges crawl stages remain non-resumable in place. Once the
corpus manifest exists, `finalize_snapshot` performs a complete zero-network
replay and requires the exact committed tree.

For each tokenizer, `inputText` is encoded with `add_special_tokens=false`.
Token IDs must be integers in `[0, vocab_size)` and at most `2^32-1`. The hash
serialization is `uint64le(token_count)` followed by ordered `uint32le` token
IDs. The ledger commits both the complete serialized stream SHA-256 and the
SHA-256 of the same serialization restricted to the first 512 IDs. This
inventory phase may tokenize text, but it must not import model weights, the
codec, or compute logits.

Each language ledger must contain at least 64 eligible revisions. If any
ledger has fewer than 64, the suite expires without changing languages, dates,
or eligibility rules. The immutable snapshot release uses the proposed tag
`corelm-blind-crossmodel-v1-snapshot`. Its signed annotated tag MUST target
the same exact frozen `labSource.commit`/`labSource.tree` as the design release;
a post-freeze snapshot-publication commit is forbidden. To avoid a cryptographically
impossible self-reference, the canonical snapshot registration is created
*before* publication. It binds the already-existing design publication-receipt
SHA-256, the planned signed tag and deadline, all canonical ledgers, source and
full-asset receipts, raw API responses, corpus records, attribution/license
manifest, and token commitments; it contains no future snapshot commit, tree,
release ID, or `attestedAt`. A separate signed snapshot publication receipt
then binds the registration bytes, annotated tag object, verified signature,
commit/tree, immutable release ID, complete asset set, and GitHub
immutable-release attestation. The verifier requires RFC3161 `attestedAt`
strictly earlier than `2026-08-20T18:00:00Z`. The exact pre-publication snapshot-registration bytes
are `S` in the later selection rule.

## Pre-pulse public execution reservation

After the design and snapshot receipts exist and the complete six-model pool
and three-ledger snapshot are sealed, the offline reservation packager creates
exactly three canonical release assets:

- `execution-reservation.json`;
- `snapshot-publication-receipt.json`;
- `sha256-manifest.json`.

The execution reservation binds the exact frozen design, snapshot and snapshot
receipt, codec/lab commit and tree, candidate digest, all six confirmatory
revisions, target pulse, post-pulse execution window, hard deadline,
`retryPermitted: false`, and the obligation to publish terminal evidence or the
registered closeout. It has `countsTowardScientificVerdict: false`, derives no
selection, loads no model, and is distinct from the later local
`attempt-reservation.json` and `attempt-marker.json`.

The reservation also fixes the only public `attemptId`. Its prefix is the
compact target timestamp `20260821T180000Z-`; its suffix is the first 16
lowercase hexadecimal characters of SHA-256 over the canonical reservation
object before `attemptId` and `reservationContentSHA256` are added. The runner,
worker capability, local marker, independent verifier, evidence package, and
closeout must all preserve that exact identity. Copies of a private root or VM
therefore cannot create a second *official* attempt identity, although this
still cannot prove that the machine owner performed no hidden computation.

These assets may be published only in the registered half-open window
`[2026-08-20T18:00:00Z, 2026-08-21T17:45:00Z)` under the signed annotated tag
`corelm-blind-crossmodel-v1-execution-reservation`. A separate canonical receipt
of kind `reservation` binds the tag object and signature, frozen
implementation commit/tree, release ID, complete three-asset inventory, and
verified immutable-release attestation. Its signed RFC3161 `attestedAt` must be
inside that window and therefore strictly earlier than the target pulse.

If no valid receipt exists in that window, the registered confirmatory claim is
unsupported; a local timestamp, backdated JSON field, later release, alternate
pulse, or reused corpus cannot repair it. Once the public reservation exists,
there is no replacement reservation under this suite identity. Failure to
create local attempt state before the hard deadline requires the registered
`NO_ATTEMPT_EXPIRED` closeout rather than a retry.

The public execution reservation makes the decision and outcome obligation
auditable before the pulse. It does not prove that the author never copied
inputs or ran unregistered code, and it is not upgraded to operator blindness
or independent administration.

## NIST one-shot selection

The exact future pulse is:

```text
2026-08-21T18:00:00.000Z
Unix milliseconds: 1787335200000
https://beacon.nist.gov/beacon/2.0/pulse/time/1787335200000
```

The registered production pulse profile is the current exact Beacon wire
profile observed and independently signature-verified before freeze:
`version="2.0"`, `cipherSuite=0`, `period=60000` milliseconds, and top-level
`statusCode=0`. A signed pulse with status 1, 2, or 3 fails before selection;
the suite does not reinterpret a new or delayed chain as normal. The old
official chain-1 known-answer vector uses the historical string
`version="Version 2.0"` and the signed start-of-chain `statusCode=1`; those
values are accepted together only behind the explicit fixture-only trust path
and can never validate the production pulse.

The exact tracked `trust/nist/spec/beacon-2.0.xsd` bytes define wire
serialization when their version 2.0.0 annotations conflict with draft NISTIR
prose. The tracked XSD uses unsigned 32-bit big-endian length prefixes,
SHA-512 of leaf DER for `certificateId`, and
`SHA-512(unsigned-pulse-bytes || raw-signature-bytes)` for `outputValue`.

`nearest`, `latest`, alternate-beacon, and fallback behavior are forbidden.
The certificate, signature, timestamp, and NIST output construction must all
verify before selection. The design release binds the exact TLS transport
CA-bundle SHA-256, both candidate and frozen offline NIST trust-manifest
SHA-256 values, and the
allowed trust-anchor DER SHA-256 list. The latter two commitments are
independent: the manifest hash freezes the complete chain bytes while the root
pin prevents a self-consistent manifest from substituting an author-controlled
root. The registered list contains only DigiCert Global Root G2 DER SHA-256
`cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f`.
The manifest contains exact certificate IDs, DER/PEM byte hashes, and chain
hashes; the verifier may not trust a certificate merely because it arrived
with the pulse. All three commitments are populated in this draft. On
2026-08-03 the same owned
bytes verified a live exact-time NIST response, its RSA signature, certificate
chain, and output construction; that development control is not the future
registered pulse and does not count as an attempt or scientific result.

The tracked candidate manifest is exactly 1,933 bytes with SHA-256
`cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`.
The only permitted promotion changes its status to
`FROZEN_OFFLINE_TRUST_BUNDLE`, producing exactly 1,930 canonical bytes with
SHA-256
`5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`.
Both verifier implementations must accept the candidate before promotion and
the frozen output afterwards. The frozen verifier also restores the candidate
status and requires those normalized bytes to equal the exact tracked
candidate; a merely policy-compatible frozen bundle is rejected. Calendar
validity, a valid chain, hostname verification, and a valid signature do not
establish non-revocation: this suite explicitly performs no OCSP or CRL check
and retains that residual risk.

The draft design keeps both identities immutable:
`candidateOfflineTrustBundleSHA256=cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`
and
`frozenOfflineTrustBundleSHA256=5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`.
In draft lifecycle `trustBundleStatus` is candidate and the active
`offlineTrustBundleSHA256` equals the candidate hash. Frozen-design
construction may change only that status to frozen and the active hash to the
precommitted frozen hash; the two identity fields remain unchanged.

Let `S` be the exact committed bytes of `snapshot-registration.json`, and let
`R` be the 64 output bytes decoded from the NIST `outputValue`. The fixed domain
is the ASCII byte string including its terminal NUL:

```text
corelm-blind-crossmodel-v1/select\0
```

For each draw, the rejection `counter` starts at zero and increments by one
only after a rejection:

```text
H = SHA-512(
    domain ||
    uint64be(len(S)) || S ||
    R ||
    uint64be(drawIndex) ||
    uint64be(counter)
)
```

For a current pool of size `n`, interpret `H` as an unsigned 512-bit big-endian
integer `x`, set `limit = 2^512 - (2^512 mod n)`, reject while `x >= limit`, and
select `x mod n`. Remove every accepted item before the next draw.

Draws are globally indexed in this exact order:

1. draw 0: corpus A from `[de, en, fr]`;
2. draw 1: corpus B from the remaining list in its original order;
3. draws 2-17: 16 revisions from corpus A's timestamp/revision-sorted ledger;
4. draws 18-33: 16 revisions from corpus B's timestamp/revision-sorted ledger;
5. draw 34: model A from the six-entry table-order pool;
6. draw 35: model B from the remaining pool in original table order;
7. draw 36: model C from the remaining pool in original table order.

Accepted models are removed after each draw, so the selected revisions are
distinct. Their draw order is their mandatory execution order. The other three
pool revisions are not executed and no selected failure permits substitution.

The eventual freeze must include known-answer selection vectors before the
pulse exists.

## Frozen candidate and execution

The candidate is a layer-count extension of the previously published,
Qwen-derived configuration 32. The rule and the inherited `2.0 / 0.01 / 0.99`
thresholds were fixed before any confirmatory-pool forward pass and before any
future page exists; they were not estimated from this suite:

```text
groupSize=128
transformBlockSize=128
codeCompression=zlib-9
scaleCompression=zlib-9
signMode=none
bitsByLayer[layer]=9 when layer is 0 or floor(layerCount / 3), otherwise 8
```

The rule reproduces the already published 24-layer schedule `{0, 8}` and is
applied mechanically to every layer count in the six-model pool. The freeze
binds the canonical rule digest and all six exact derived arrays/configuration
digests. Prior architecture-family observations and threshold lineage remain
part of the frozen disclosure; this rule is not represented as
architecture-blind.

No calibration, sensitivity ranking, padding, layer remapping, or post-result
parameter change is allowed. Each selected page contributes its first 512
tokenizer-native tokens:

```text
383-token prefill
128 teacher-forced predictions
FP32 model execution
FP32 -> BF16 -> FP32 canonical cache baseline
eager attention
CPU, two threads, one model resident at a time
complete VTL5 container byte accounting
```

Every block must first pass exact direct-cache versus flatten/rebuild logits
and exact decoded-container structural replay. Deterministic algorithms must be
enabled fail-closed; the runtime fixes Python and dependency builds, CPU device,
two intra-op threads, one inter-op thread, environment variables, seeds, eager
attention, and model-evaluation mode. An unsupported nondeterministic operation
is `FAIL_EXECUTION`, not grounds for a tolerance or a substituted model.

Every scientific subprocess executes the exact absolute launcher reported by
the active locked virtual environment. The launcher spelling is preserved even
when it is a symlink to the base interpreter: resolving that symlink before
`exec` would bypass the adjacent `pyvenv.cfg` and silently discard the locked
site-packages. Before any marker, a disposable child under the same closed
environment must import `jsonschema`, NumPy, Safetensors, Tokenizers, Torch, and
Transformers and report the exact registered versions, runtime prefix, base
prefix, executable, hash seed, and startup flags. A base-interpreter fallback,
foreign launcher, missing import, version difference, relative path, or changed
startup state is a pre-attempt failure. These facts come from two linked
disposable probes: the first proves the hash/startup state, and the second runs
under the registered macOS network-denial wrapper and proves the venv and
dependency imports.

A terminal `PASS` or `FAIL_GATES` additionally requires the independent
real-model replay in `blind_v1/independent_model_replay.py`. That module imports none
of the producer's `model_worker`, `evidence`, or `protocol` modules. In
`selection.modelExecutionOrder` it loads one model at a time from freshly
rehashed frozen bytes, reconstructs each selected corpus record independently,
retokenizes it, regenerates the FP32 -> BF16 -> FP32 baseline cache, decodes the
archived VTL5 containers with its own decoder, and requires every container
`inputSha256` to equal the regenerated baseline layer. It then recomputes all
12,288 target losses and top-1 IDs and compares the first 512 token IDs, target
IDs, binary32 loss bits, and top-1 IDs exactly. Missing coverage, a single bit
or ID difference, an invalid container mapping, a resource/deadline failure, or
use of a tolerance is `FAIL_EXECUTION`.

The page-level backend seam exists only for fast unit/adversarial fixtures.
The production entry point exposes no backend injection, its canonical summary
requires `fixtureBackendUsed: false`, and fixture output can never count toward
the scientific verdict. Production replay is CPU-only, networkless from child
process creation, deterministic, and sequential under the same 4 GiB sampled
process-group RSS watchdog and hard deadline as a producer worker. RSS is
observed every 250 ms and once more after process exit is detected; every
observed sample contributes to the reported peak. This is not a kernel RLIMIT,
and a peak confined between observations can remain unseen. Any observed
aggregate above 4 GiB is `FAIL_EXECUTION`.

Before an attempt, all six confirmatory model revisions and the complete
three-edition corpus snapshot are copied without symlinks into a new private
content-addressed directory. Only the three later selected revisions may be
loaded by scientific workers. Lab and codec source bytes are exported directly
from the exact Git
commit object graphs rather than copied from their worktrees. Their manifests
carry the raw commit object and every blob identity, allowing an offline
verifier to reconstruct the root trees without `.git`. Every other regular
file is opened with no-follow semantics, hashed after the copy, and bound by
one snapshot-manifest digest. The child receives only this snapshot and has no
network access.

Filesystem verification is not the load boundary. After the marker is durable,
each registered producer or independent-verifier model evaluation performs one
no-follow read of each selected corpus/model asset into an anonymous immutable
byte buffer, computes the registered SHA-256 over those same bytes, and parses
or loads only that buffer. A producer first completes its exact model load and
releases every model-asset byte buffer. Only then does it read and verify one
selected canonical corpus record, evaluate that page, and release its record
and derived input bytes before opening the next record. It never retains the 32
selected records as an aggregate; at most one canonical record, itself bounded
to 8,388,608 bytes, is retained by a producer. The verifier's second read is
intentional and normative: it is a separate implementation replay, not reuse of
producer objects or declared values. Filesystem-path model parsing, mmap, and
`from_pretrained` are forbidden. Safetensors are loaded from verified bytes into
owned tensors; config and tokenizer JSON are decoded from verified bytes. Thus
later replacement of a path cannot silently change either inference: it causes
a digest failure. A sampled resource-bound violation is `FAIL_EXECUTION`.

The normative weight load order is
`verified-owned-bytes->deserialize-owned-state->destroy-weight-bytes->construct-fp32-model->strict-copy`.
At most two weight-payload representations may coexist, and the verified raw
weight bytes must be destroyed before FP32 model construction. The static
`staticWorstCaseWeightStorageOverlapBytes` value is exactly `2,894,634,160`;
it bounds only the conservative overlap of the weight file, decoded state, and
FP32 weight storage for the largest registered model. It is not a bound on
complete worker RSS: runtime/model metadata, allocator overhead, tokenizer,
activations, and evidence buffers are outside that arithmetic. The former
three-payload lower bound `4,341,886,040` is retained only as a superseded
comparison. The separate sampled 4 GiB process-group RSS watchdog remains the
whole-process resource gate and supplies headroom/measurement independent of
this static storage calculation.

Preflight may verify and copy all frozen assets without resolving the future
selection. The post-pulse scientific invocation must first reopen and
byte-verify the exact public execution-reservation assets and canonical release
receipt specified above. It rejects a missing, late, replaced, or second public
reservation, but it does not recreate that public record inside the local state
machine.

During the registered post-pulse execution window, the runner first reuses the
exact public reservation `attemptId` and durably
publishes the local `attempt-reservation.json`, committing the attempt identity
and every frozen input binding with `retryPermitted: false`, and then durably
publishes `attempt-marker.json`. Both local transitions use an exclusive pending
inode, file `fsync`, no-overwrite hard-link publication, directory `fsync`,
pending-name removal, and a final directory `fsync`; normal publication never
exposes a partial final JSON file. The local reservation and marker precede
selected corpus resolution/open, confirmatory-model load, or NIST fetch. No
confirmatory-model forward pass is permitted before the pulse or between the
pulse and these registered post-marker workers.

The registered operator procedure exposes the public `run-one-shot` entrypoint
as its sole supported execution path. It validates the canonical result-root
path and sealed snapshot, creates
an anonymous pipe, starts one new-session child, and sends a one-use canonical
handoff payload binding the private/result roots, parent and child PIDs,
process group, hard deadline, poll interval, fresh nonce, and
`retryPermitted: false`.
The private child consumes and closes that pipe, requires the descriptor to be
a FIFO, and verifies every binding against its live parent/session identity
before entering the irreversible state machine. Direct use of the hidden
`--private-execution` or `--outer-authorization-fd` flags is forbidden and
an invocation without the conforming inherited handoff fails closed; those
flags are internal handoff details, not operator controls.

This handoff is a topology and value-binding check, not parent-code
authentication or watchdog attestation. It establishes that the payload came
through an inherited pipe from the live parent identified in that payload and
that the child/process-group/path/deadline values match. It does not
authenticate the parent implementation or prove that the parent will enforce
the watchdog after the handoff. A custom parent controlled by the same user
can start the child and construct a conforming payload. The
internal wire identifiers containing `authorization` and the status
`OUTER_SUPERVISION_AUTHORIZED` mean only that these handoff bindings passed;
they are not an authenticated parent-implementation identity claim. The
registered procedure requires the public entrypoint and watchdog, but the
local pipe mechanism cannot prove that requirement against a malicious or
modified same-user parent.

After the marker is durable, only the supervisor may make one HTTP/1.1 GET
transaction to the exact registered NIST pulse endpoint. System DNS may return
multiple addresses, and `socket.create_connection` may try only those addresses
for that hostname within the one 30-second total timeout. Redirects, proxies,
alternate hosts or endpoints, a second GET, and application-level retry or
fallback are forbidden. The supervisor verifies
the registered timestamp, trust chain, signature, and output construction,
writes and fsyncs the exact response and verification record, then installs a
Python audit/socket denial before deriving the selection from those sealed
bytes. This is a trusted-control-flow guard, not permanent OS capability
removal: the supervisor process could launch an unregistered subprocess that
does not inherit the Python monkeypatch. The frozen exact-commit code launches
only the registered workers and verifier after this point, and each such child
is placed under the macOS deny-network sandbox before Python starts. The
protocol therefore does not claim that a malicious or modified supervisor is
capability-confined.

The supervisor starts every inference child only after the scoped socket guard
is installed. Each producer worker and the later independent verifier is
OS-sandboxed networkless from process creation and receives the selection,
sealed pulse record, and private content-addressed snapshot through canonical
no-follow paths. Producer workers remain one-model-per-process; the verifier is
a separate process that loads and releases the three models sequentially. No
registered child can fetch, redirect, fall back, or substitute an asset. There
is no retry after any attempt.

The exact post-selection order is also frozen. The supervisor launches the
three producer workers in the NIST-derived model order, consolidates their
evidence, publishes the canonical producer result, and then publishes the
producer evidence manifest. It next launches the separate networkless
independent verifier. That verifier must complete the fresh real-model replay
and byte-match the independently recomputed result before the supervisor may
publish a terminal `PASS` or `FAIL_GATES`. A missing, late, killed, or
mismatching verifier becomes `FAIL_EXECUTION`; the terminal outcome can never
jump directly from producer inference to a gate verdict.

The execution-and-publication obligation is already public, but local attempt
state begins with the durable `attempt-reservation.json`. Neither that local
reservation nor the scientific marker may be created before
`2026-08-21T18:00:00Z`, exactly the registered target-pulse timestamp. The
runner must durably create both local transitions, including the marker, before
its first pulse request or selection derivation. The marker and live NIST start
observation must both fall in the half-open interval
`[2026-08-21T18:00:00Z, 2026-08-21T18:15:00Z)`; equality with the upper bound
is invalid. This prevents the author from waiting beyond the registered
fifteen-minute start window after the pulse becomes visible. The hard
completion deadline remains `2026-08-22T18:00:00Z`. After the irreversible
marker, the HTTPS `Date` observed from NIST over the live, hostname-verified
pinned-TLS connection must independently fall inside the registered start
window or the attempt fails. This is a TLS-authenticated live
observation: the NIST pulse signature does not cover the HTTP `Date`, and the
archived header bytes are not a publicly verifiable time attestation. Completion
time still uses host UTC plus process monotonic durations and has no external
completion-time attestation; the protocol makes both limitations explicit. If
the supervisor detects the hard execution deadline while the child is active, it
terminates the process group and durably writes a `FAIL_EXECUTION` outcome. A
local attempt reservation with a missing, partial, or noncanonical
marker/outcome is instead
`CONSUMED_INCOMPLETE`. `PASS` and
`FAIL_GATES` are valid only when their durable `completedAt` is strictly before
the hard deadline; a computation or independent verification that crosses the
boundary is recorded as `FAIL_EXECUTION`, even if its late metrics would pass.

Publication validity is a separate clock. Every consumed attempt state,
including failure or local reservation/marker-only interruption, must be packaged
and published under the registered
signed evidence tag with GitHub immutable-release `attestedAt` strictly before
`2026-08-26T18:00:00Z`. The evidence annotated tag MUST also target the exact
frozen `labSource.commit`/`labSource.tree`; evidence bytes are release assets,
not a later source commit. A package first published at or after that evidence
deadline is classified by the public closeout verifier as
`LATE_PUBLICATION_INVALID`, never as PASS or FAIL_GATES. If neither a local
attempt reservation nor a marker was created before the hard execution
deadline, a separately signed closeout may
classify the specifically audited result root and host as
`NO_ATTEMPT_EXPIRED`; absence on one observed host is not proof that no attempt
exists anywhere. Either closeout classification must be packaged under the
preregistered signed annotated tag
`corelm-blind-crossmodel-v1-closeout` and published as an immutable release
strictly before `2026-08-30T18:00:00Z`. The closeout release contains exactly
the canonical statement, a canonical basis bundle, the closeout-verifier
report, and a SHA-256 manifest. It never counts as scientific evidence and
never modifies an attempt terminal outcome.

The closeout annotated tag MUST target the exact frozen
`labSource.commit`/`labSource.tree`; the four release roles and filenames are
fixed by the canonical receipt schema. Composed verification requires
`classifiedAt <= report.verifiedAt <= GitHub attestedAt`. A closeout built
from a later implementation tree, reordered time evidence, or renamed asset is
invalid even when its individual signatures verify.

For `NO_ATTEMPT_EXPIRED`, that basis bundle contains the exact bounded-host
environment bytes, no-follow empty-root observation, and audit report; hashes
without the referenced bytes or exact audit implementation are insufficient.
For `LATE_PUBLICATION_INVALID`,
the bundle contains the unchanged late evidence receipt and its exact external
release-asset inventory, while verification also requires those immutable
evidence asset bytes.

## Verdict

There are six cells: three models by two selected corpora. Each cell contains
16 distinct pages and 2,048 teacher-forced decisions. Every cell must pass all
of these gates independently:

```text
complete-container compression ratio versus BF16 >= 2.0
Delta NLL <= 0.01 nat/token
top-1 agreement >= 0.99
structural replay = true for every block and container
```

Cell arithmetic is fixed, never a mean of per-block ratios:

```text
compression = sum(integer dense BF16 bytes) / sum(integer container bytes)
Delta NLL   = math.fsum(candidate_token_loss - baseline_token_loss
                        in canonical page/token order) / 2048
top-1       = integer exact-match count / 2048
```

The evidence retains every target ID, baseline/candidate target loss as its
exact IEEE-754 binary32 bit pattern, baseline/candidate top-1 ID, integer byte
count, and container digest. The independent verifier recomputes all cell
values with pinned CPython 3.12.10 binary64 arithmetic and `math.fsum` in the
stated order.

For each model, the aggregate over all 32 selected pages must additionally pass
the following exact gates. Let `n=32`, `z=1.6448536269514715`, and
`t=1.6955187825458675` (one-sided 95% Student t critical value with `df=31`).
For the canonical list of 32 block values, the pinned runtime uses
`statistics.fmean`, `statistics.stdev` (sample standard deviation), and
`math.sqrt`:

```text
deltaUpper = fmean(blockDelta) + t * stdev(blockDelta) / sqrt(32)
top1Lower  = fmean(blockTop1) - t * stdev(blockTop1) / sqrt(32)

p = total exact matches / 4096
wilsonLower = (
    p + z*z/(2*4096)
    - z*sqrt(p*(1-p)/4096 + z*z/(4*4096*4096))
) / (1 + z*z/4096)

deltaUpper <= 0.01
top1Lower >= 0.99
wilsonLower >= 0.99
```

Suite PASS requires all six cells and all three descriptive model-level
aggregate gates to pass. A failure cannot be averaged away by another model or
corpus.

- scientific metric failure: `FAIL_GATES`;
- crash, missing asset/corpus, deadline, or integrity failure:
  `FAIL_EXECUTION`;
- durable attempt reservation with no canonical terminal outcome:
  `CONSUMED_INCOMPLETE`; raw pending/partial state bytes remain forensic
  evidence and never authorize a retry.

Only a valid, timely `PASS` supports the registered positive exact-sample
claim. `FAIL_GATES` is a valid negative metric result for that sample.
`FAIL_EXECUTION` and `CONSUMED_INCOMPLETE` do not establish a negative codec
metric, but they are unsuccessful consumed attempts—not neutral omissions and
not grounds for repair or retry. Any terminal or closeout class other than a
valid `PASS` leaves the positive confirmatory claim unsupported.

`LATE_PUBLICATION_INVALID` and `NO_ATTEMPT_EXPIRED` are public experiment
closeout classifications, not attempt terminal states. They are emitted only
by the separate closeout verifier and never written into `terminal-outcome.json`.
For a late release, the canonical evidence receipt is archived unchanged. The
ordinary release verifier must reject it; only the explicit closeout verifier
may accept the inverse relation `attestedAt >= evidence deadline`. No deadline
is rewritten and no late publication becomes a valid evidence release.

All later executions are regression-only.

The Wilson and Student-t quantities are fixed descriptive gates, not valid
population confidence claims: the 32 pages are not guaranteed IID, token
decisions within a page are dependent, and language editions may differ.

## Publication and implementation boundary

The canonical JSON Schema Draft 2020-12 contracts are tracked under
`blind_v1/schemas/`:

- `design.schema.json` covers the design registration;
- `snapshot.schema.json` covers the immutable future-corpus snapshot;
- `execution-reservation.schema.json` covers the pre-pulse public execution and
  publication commitment, without creating local scientific attempt state;
- `execution-reservation-release-manifest.schema.json` covers its exact
  three-asset immutable-release inventory;
- `attempt.schema.json` covers the durable `STARTED` marker and its exact
  design, snapshot, runtime, model-asset, corpus, codec, lab-source, and
  private-snapshot commitments;
- `attempt-reservation.schema.json` covers the durable local pre-marker
  reservation that consumes the one allowed local attempt before any
  scientific child starts;
- `result.schema.json` covers the independently recomputed six cells, three
  model aggregates, and suite verdict;
- `outcome.schema.json` covers the immutable local terminal outcome and binds
  the result, evidence manifest, and independent verifier;
- `release-receipt.schema.json` covers signed annotated development-control,
  design, snapshot, execution-reservation, evidence, and closeout tags; the design-wide
  `EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE` source policy, exact commit/tree
  and raw Git objects; immutable GitHub release identity, API timestamp
  observations, verified immutable-release attestation, and every required
  asset digest;
- `ci-artifact-verification.schema.json` covers the exact-commit Linux x86-64
  and macOS arm64 zero-skip artifact inventories and their workflow binding;
- `github-gate-receipt.schema.json` covers the exact PR head commit, successful
  CI run and jobs, four-response collection boundary, and the two downloaded CI
  artifact digests; it contains no human-review record;
- `nist-trust-bundle.schema.json` covers the candidate/frozen offline NIST
  certificate inventory, exact wire profile, singleton rotation policy, root
  pins, and declared no-revocation-check boundary;
- `prior-observations.schema.json` covers the immutable disclosure of prior
  model-family, exact-revision, candidate, threshold, and negative-result
  observations that define the holdout boundary;
- `development-control-report.schema.json` covers the untuned three-pilot-model
  real development run and implementation-level independent replay result;
- `development-control-archive-manifest.schema.json` covers the exact real
  corpus, rights evidence, runtime, model assets, logs, and replay bytes in the
  signed development-control release;
- `freeze-manifest.schema.json` covers the two-stage source, runtime, asset,
  author-self-verification/CI, development-control, signing-key, and
  release-receipt freeze
  bindings;
- `evidence-release-manifest.schema.json` covers the post-attempt package for
  PASS, gate failure, execution failure, or local reservation/marker-only
  interruption;
- `private-snapshot-manifest.schema.json` covers every pre-attempt input,
  including exact Git-source manifests and both model-asset commitments;
- `raw-token-evidence.schema.json` covers one teacher-forced prediction record,
  including exact binary32 loss bits;
- `page-token-evidence.schema.json` binds each page's exact first 512 token IDs,
  vocabulary size, ledger commitment, and prediction target offset;
- `container-evidence.schema.json` covers one complete VTL5 container and its
  structural replay result;
- `independent-model-replay.schema.json` covers the canonical real-model replay
  summary, its per-model byte/evidence commitments, exact comparison claims,
  execution mode, fixed record counts, and self-digest;
- `experiment-closeout.schema.json` covers the two non-verdict public closeout
  branches, exact basis/publication bindings, and preregistered signed closeout
  release plan;
- `closeout-basis.schema.json` covers the exact embedded no-attempt support
  documents or unchanged late receipt plus external evidence asset inventory;
- `zenodo-deposit-manifest.schema.json` covers the exact archival superset,
  GitHub release and CI bindings, file roles, rights declarations, and reserved
  production DOI identity;
- `zenodo-deposit-receipt.schema.json` covers the published production record,
  exact deposited checksums, captured read-only API responses, rights replay,
  and the explicit TLS/offline evidence boundary.

Every normative JSON producer/verifier must reject non-finite numbers,
duplicate keys, invalid UTF-8, lone surrogates, missing fields, and additional
fields. Evidence manifests bind the exact bytes and SHA-256 of every included
record. Schema validity is necessary but not sufficient: the independent
verifier must also recompute all cross-record counts, ordering, identities,
digests, arithmetic, and state transitions.

The independent verifier recomputes selection, ledger/token bindings, VTL5
structural replay, evidence coverage, every metric, gate, and terminal binding.
It verifies exact worker jobs, source trees, assets, summaries, logs, and
process-supervision receipts. Before any terminal gate verdict, its separate
real-model replay also independently retokenizes the frozen corpus bytes,
regenerates the canonical baseline cache from the frozen weights, reconstructs
the candidate only from archived VTL5 bytes, and exactly recomputes every loss
bit pattern and top-1 ID. The replay summary and self-digest are nested in the
canonical independent-verifier report; the terminal outcome binds that complete
report file.

This closes the declared-loss/top-1 gap within the registered implementation,
but it is not a cryptographic proof or trusted-execution attestation. Exact
floating-point replay is normative on the one-shot host and frozen runtime.
An archival run on a different CPU, OS, numerical kernel, or dependency build
must report any bit mismatch as a failed reproduction; it may not silently add
a tolerance and still claim the one-shot verdict. Any execution after the
canonical terminal outcome is replication/regression only.

The exclusive pending-inode, no-overwrite hard-link publication protocol for
the canonical result root, attempt reservation, marker, and terminal outcome
prevents accidental in-place retries and preserves interrupted pending bytes;
it does not use or claim a file lock. These local controls cannot
cryptographically prove compliance with the pre-marker conduct rule or
prove that the machine owner never copied the corpus/private snapshot and
performed an undisclosed execution. The public preregistration, immutable bytes,
no-retry software, complete failure publication, and public immutable artifacts
make such misconduct more auditable; they do not make this an operator-blind,
independently reviewed, or independently replicated experiment and do not
eliminate the general limitation of self-administered local experiments. Any
claim requiring stronger one-shot, peer-review, operator-blind, or independent
replication assurance must add the corresponding external control before
freeze, not after observing the result.

The durable `attempt-reservation.json`, `attempt-marker.json`,
`private-snapshot-manifest.json`,
`nist/verification.json`, `selection.json`, `result.json`, independent-verifier
report, and terminal outcome use sorted compact canonical JSON followed by
exactly one LF. `reservationContentSHA256` and `markerContentSHA256` are each
the corresponding record's self-digest over its canonical payload with that
self-digest field omitted and without the terminal LF.
`attemptMarkerFileSHA256` in the terminal outcome and verifier report is the
SHA-256 of the complete marker file including its self-digest and terminal LF.
Other self-digests and complete-file commitments are named separately and must
not be substituted for one another. `nist/response-body.json` preserves the exact bytes
received from NIST and is never normalized. The pre-verifier producer evidence
manifest must cover the attempt reservation, attempt marker, private snapshot
manifest, fixed NIST request/headers/body and verification files, selection,
raw-token and container JSONL files, and every referenced VTL5 container. By
construction it cannot self-include the later verifier report, verifier
log/receipt, terminal outcome, or producer result. The terminal outcome
separately binds the producer result and complete independent-verifier report,
while the post-attempt evidence-release manifest binds the entire final attempt
tree including those later files. The producer result must byte-match the
independently recomputed canonical result.

The tracked `blind_v1/` contour must contain the design registration, model manifest,
corpus collector, snapshot registration and three ledgers, freeze validator,
public execution-reservation packager/verifier, one-shot runner, independent
verifier, schemas, known-answer vectors, tests, and documentation for the
external result root. The locked runtime manifest
cannot live in the same source tree whose bytes it binds: the immutable design
release and sealed private snapshot must include it as a separate external
artifact. Its digest must be bound into registration, attempt, outcome, and
verification records, together with the private snapshot-manifest digest. The
runner must use a supervised child process, hard deadline, memory watchdog,
process-group termination, and vocabulary-bound checks for all recorded token
IDs.

The corpus release must preserve attribution for every creation revision and
the applicable Wikipedia license information. Excluding MediaWiki revisions
with the `bot` flag does not prove that an author is human and does not exclude
AI-generated text; the suite makes neither claim.

If any P0 design gate remains unproven at the registered checkpoint
`2026-08-08T12:00:00Z`, this suite must remain an unfrozen draft. A replacement
uses a new suite ID and moves the complete dependent timeline together: design
deadline, corpus interval, both crawls, snapshot release, NIST target, one-shot
window, evidence deadline, and closeout deadline. It receives a new commit/tree,
author self-verification record, green exact-commit CI, freeze manifest, signed
tag, and release receipt. Moving one date alone,
reusing a corpus or pulse that became observable before the replacement design,
or freezing an incomplete protocol is forbidden. The operational checklist is
[`FREEZE_READINESS.md`](FREEZE_READINESS.md).

Before publication, the author must complete and archive the zero-skip tests and
fail-closed verification of the canonical schemas, four-response GitHub CI
collector, API pagination edge cases, model cache adapters, selection vectors,
confidence arithmetic, and state-machine failure paths on one exact commit.
This is author self-verification, not independent human review or peer review.
Until that evidence and an immutable public freeze exist, this document is only
a plan.
