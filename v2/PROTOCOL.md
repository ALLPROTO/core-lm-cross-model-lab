# Cross-model live-corpus v2 — normative protocol draft

Status: **DRAFT — not frozen, not published, not preregistered, and not run**.

This tracked file is the complete normative prose companion to
`design-registration.draft.json`. It must not be represented as scientific
evidence. Before freeze, the exact model revisions may be exercised only by
the single tracked full producer-to-VTL5-to-independent-replay control on the
byte-pinned UD English PUD r2.18 CoNLL-U source. It includes the lossless
cache-adapter invariant. The upstream `test` split is reused only for this
non-scientific development control and is not the prospective scientific test
corpus. Its report is diagnostic, uses the already fixed candidate without
tuning, and has `countsTowardScientificVerdict=false`. No
eligible future-corpus collection, NIST selection, or one-shot state may be
used by that control. This document
becomes a preregistration only when a reviewed freeze validator binds it into a
signed, immutable public design release.

## Normative authority and meaning of “blind”

The frozen design JSON, canonical schemas, this protocol, and the reviewed
implementation form one contract; none may silently override another. For
overlapping requirements, the frozen design is authoritative for enumerated
identities, fixed values, dates, and gates; the schemas are authoritative for
serialized structure and types; and this protocol is authoritative for
procedure, cross-artifact semantics, and claim interpretation. The reviewed
code is subordinate implementation of that contract. Any incompatible overlap
is a P0 contradiction that invalidates freeze or execution rather than a choice
of whichever source is more convenient.

In this suite, “blind” means only a **prospective beacon-selected holdout**:
eligible corpus revisions are created after design publication and the future
NIST pulse selects the corpus/page identities and model order. It does not mean
that the operator is blinded to the public corpus, and it is not cryptographic
proof that the operator never inspected, scored, copied, or privately executed
eligible records. Candidate inference, candidate scoring, and tuning on any
future-corpus record are normatively forbidden before the durable attempt
marker. Proving stronger operator blindness requires an external witness or an
attested execution environment fixed before freeze.

## Claim under test

The suite tests whether one fixed VoidToken candidate transfers prospectively
to three pinned causal language models on two beacon-selected samples. Each
sample contains sixteen eligible page-creation revisions from one selected
language edition and contains pages created only after the design freeze. A
PASS would be evidence only for these exact three model revisions, thirty-two
selected revisions, dates, runtime, codec, and metrics. It would not establish
performance on either complete language-edition corpus, all Wikipedia, all
LLMs, or all text.

Proposed suite ID:

```text
corelm-voidtoken-crossmodel-livewiki-v2
```

## Required models

All three models are mandatory. The beacon changes only their execution order;
it cannot select a convenient subset. Loading pickle weights or enabling
`trust_remote_code` is forbidden.

These revisions are holdouts from candidate selection and tuning, not from all
execution. Before design freeze, one tracked control may run on the pinned UD
English PUD r2.18 bytes: the complete producer-to-VTL5-to-independent-replay
readiness check using the exact fixed candidate and runtime. It includes the
lossless adapter invariant and may compute diagnostic candidate metrics, but
its outcome must not change any candidate setting, gate, model, runtime, or
protocol field; any such change requires a new suite identity and new future
timeline. The control forbids future-corpus bytes, NIST selection, attempt
reservation/marker state, and scientific result roots. Its report must state
`countsTowardScientificVerdict=false` and
`usedForCandidateSelectionOrTuning=false`.

The full development E2E control is a freeze-readiness gate, not a model gate:
all three producer processes, VTL5 serialization/decoding, and the independent
real-model replay must complete on the exact implementation and locked runtime,
and its canonical report/log hashes must be archived before freeze. Scientific
PASS/FAIL thresholds are not applied to that report. A negative diagnostic is
preserved, and no outcome may justify changing the candidate or protocol under
the same suite identity. The control uses a strict standard-library CoNLL-U
parser: it requires 1,000 source-order sentence blocks with one `# sent_id = `
and one `# text = ` value, joins the unchanged text values with two LF bytes,
and creates 32 contiguous floor-boundary partitions. Its source is
`inputs/corpus/en_pud-ud-test.conllu`, copied from the exact fetch path
`v2/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`.

The complete 2,088-artifact evidence set carries the corpus manifest, source bytes,
`inputs/LICENSES/source-evidence.json`, `inputs/LICENSES/ASSET_LICENSES.md`,
the exact upstream README and license, and
`inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md`. The pinned upstream metadata,
README, and license consistently declare CC BY-SA 3.0. Publication must retain
attribution, identify the license and URI, mark the extraction/partition
changes, apply share-alike-compatible terms to reversible/source-derived
evidence, and add no effective restrictions. This is a byte-verifiable record
of upstream declarations, not an independent ownership or chain-of-title
conclusion.

The 2,088-member set and its deterministic release ZIP intentionally contain
no model weights. The 24 real-model files remain external private inputs; the
sealed plan, pinned model-asset manifest, and complete local rehash receipt bind
their exact paths, byte counts, and SHA-256 values. The packager and verifier
both require the ZIP to remain strictly below 1,800,000,000 bytes and reject
missing, extra, duplicate, or accidentally embedded model members.

The packager and archive verifier re-open those rights bytes and every artifact
before emitting the three release assets. The signed annotated development tag,
immutable release, and canonical immutable-release attested receipt must bind
those exact assets with `attestedAt` strictly before the design deadline;
manually assembled archives, local timestamps, and GitHub API timestamps do
not satisfy the freeze gate.

| Model | Revision | Architecture | Layers / KV heads | Combined K+V width | `model.safetensors` bytes | Expected SHA-256 |
|---|---|---|---:|---:|---:|---|
| `EleutherAI/gpt-neo-125m` | `21def0189f5705e2521767faed922f1f15e7d7db` | GPT-Neo mixed global/local MHA | 12 / 12 | 1,536 | 525,979,192 | `52738cbfb54e25a232598242f60ef19ee193d36090b98fe649b10c02724b3521` |
| `HuggingFaceTB/SmolLM2-360M` | `f8027fd0eaeea54caa13c31d31b9fdc459c38b49` | Llama GQA | 32 / 5 | 640 | 723,674,912 | `7aaff6661428bed033abba9522bec81938678642cca3181fe752b6ca9e1e540f` |
| `bigcode/tiny_starcoder_py` | `8547527bef0bc927268c1653cce6948c5c242dd1` | GPTBigCode MQA | 20 / 1 | 128 | 656,601,304 | `15fa942f055b618d5ca6283f5c27278a475ff12e53dc704b9658ffd5160d4021` |

The immutable model pages are
[GPT-Neo](https://huggingface.co/EleutherAI/gpt-neo-125m/tree/21def0189f5705e2521767faed922f1f15e7d7db),
[SmolLM2](https://huggingface.co/HuggingFaceTB/SmolLM2-360M/tree/f8027fd0eaeea54caa13c31d31b9fdc459c38b49),
and [Tiny StarCoder](https://huggingface.co/bigcode/tiny_starcoder_py/tree/8547527bef0bc927268c1653cce6948c5c242dd1).
Every runtime asset, not only the weight file, must be committed by byte count
and SHA-256 in the eventual model manifest.

## Two-stage future-corpus freeze

The design registration must be published as an immutable GitHub release under
the proposed tag `corelm-crossmodel-livewiki-v2-design` strictly before
`2026-08-09T00:00:00Z`. The signed annotated tag must target the exact reviewed
and CI-approved implementation commit/tree recorded in `labSource`; a separate
later publication commit is forbidden. The canonical frozen design JSON and
freeze manifest are constructed outside that Git tree and uploaded as immutable
release assets. The signed tag and release must bind the exact implementation
commit/tree, canonical frozen design bytes, runtime manifest, full asset
receipt, SBOM, CI artifacts, review gate, and every normative source hash. A
canonical publication receipt is collected only after that release exists and
separately binds the tag object, signature verification, GitHub API response
observations, complete asset inventory, and the verified GitHub
immutable-release attestation; it cannot be an asset of the same release it
observes. At collection, pinned GitHub CLI 2.97.0 obtains and verifies the
immutable-release bundle online. Pinned Cosign 3.0.6 then verifies that archived
bundle offline against `v2/trust/github/trusted_root.json`; the independent
verifier repeats the same DSSE, X.509-chain, exact-SAN, selected-asset-digest,
and RFC3161 signature/chain checks and separately replays every signed subject.
The `attestedAt` value is decoded from the raw signed RFC3161 timestamp and must
equal the semantic verification result before the verifier requires it to be
strictly earlier than `2026-08-09T00:00:00Z`; `published_at`, HTTP `Date`, and
local time are not evidence of the freeze. The GitHub bundle has no Rekor entry
or certificate SCT, so the registered Cosign operation uses
`--private-infrastructure --insecure-ignore-sct`: it makes no transparency-log
or SCT claim but does not disable DSSE, X.509, asset-digest, or RFC3161
verification. This is distinct from the review/CI API receipt below, whose
archived response replay remains structural consistency evidence only. Eligible
pages are creation revisions timestamped
in the half-open interval:

The exact-commit `APPROVED` review must carry byte-for-byte the tracked
`REQUIRED_REVIEW_DECLARATION` from `github_gate_receipt.py`; an approval state
without that declaration does not satisfy the gate. GitHub `User` type and
account authentication establish only the statement made by that account.
They do not establish real-world identity, employer, organizational membership,
or undisclosed conflicts; any stronger claim needs a separately archived signed
identity/conflict declaration and cannot replace the exact-commit review.

The implementation gate is itself preregistered. The tracked workflow is
`.github/workflows/v2-development-controls.yml`, exactly 12,487 bytes with
SHA-256
`b9215fec0922fd8462ba5e8de83d6406a7e8fbd1f0c05adff05d0b406da92dbb`.
Each lab-source checkout must explicitly use
`${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}`
so a pull-request gate executes the reviewed head commit rather than GitHub's
synthetic merge ref, while push and manual runs execute `github.sha`.
It must run the exact jobs `Linux x86-64 locked runtime` on `ubuntu-24.04`
with guest assertions `Linux/x86_64`, and `macOS arm64 clean clone` on
`macos-15` with guest assertions `Darwin/arm64`. Every returned job must be
completed/success with zero skipped or cancelled jobs on the exact reviewed
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

These Linux and macOS jobs are cross-platform development/packaging controls,
not a post-evidence replication claim. The registered scientific one-shot and
bit-exact real-model replay run on the frozen macOS arm64 runtime. No Linux
post-evidence real-model replication is implemented or preregistered in this
suite; adding one later is a separately identified regression protocol.

```text
[2026-08-10T00:00:00Z, 2026-08-24T00:00:00Z)
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
rcend=2026-08-24T00:00:00Z
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
`2026-08-24T06:00:00Z` and the second no earlier than
`2026-08-25T06:00:00Z`. Each crawl follows `rccontinue` until exhaustion. The
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
ASCII("CORELM-LIVEWIKI-V2-RECORD\0") ||
len(projectBytes) || projectBytes ||
pageid || revid || userid ||
len(timestampBytes) || timestampBytes ||
len(usernameBytes) || usernameBytes ||
len(titleBytes) || titleBytes ||
len(contentBytes) || contentBytes
```

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
`corelm-crossmodel-livewiki-v2-snapshot`. Its signed annotated tag MUST target
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
strictly earlier than `2026-08-26T18:00:00Z`. The exact pre-publication snapshot-registration bytes
are `S` in the later selection rule.

## NIST one-shot selection

The exact future pulse is:

```text
2026-08-27T18:00:00.000Z
Unix milliseconds: 1787853600000
https://beacon.nist.gov/beacon/2.0/pulse/time/1787853600000
```

The registered production pulse profile is the current exact Beacon wire
profile observed and independently signature-verified before freeze:
`version="2.0"`, `cipherSuite=0`, and `period=60000` milliseconds. The old
official chain-1 known-answer vector uses the historical string
`version="Version 2.0"`; that value is accepted only behind the explicit
fixture-only trust path and can never validate the production pulse.

`nearest`, `latest`, alternate-beacon, and fallback behavior are forbidden.
The certificate, signature, timestamp, and NIST output construction must all
verify before selection. The design release binds both the exact TLS transport
CA-bundle SHA-256, the exact offline NIST trust-manifest SHA-256, and the
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

Let `S` be the exact committed bytes of `snapshot_registration.json`, and let
`R` be the 64 output bytes decoded from the NIST `outputValue`. The fixed domain
is the ASCII byte string including its terminal NUL:

```text
corelm-voidtoken-crossmodel-livewiki-v2/select\0
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
5. draw 34: first model from the table-order model list;
6. draw 35: second model from the remaining table-order list; the sole
   remaining model is appended without another hash draw.

The eventual freeze must include known-answer selection vectors before the
pulse exists.

## Frozen candidate and execution

The candidate is a layer-count extension of configuration 32, fixed before any
future page exists:

```text
groupSize=128
transformBlockSize=128
codeCompression=zlib-9
scaleCompression=zlib-9
signMode=none
bitsByLayer[layer]=9 when layer is 0 or floor(layerCount / 3), otherwise 8
```

The rule reproduces the already published 24-layer schedule `{0, 8}` but is
fixed without model-specific calibration for the registered 12-, 20-, and
32-layer architectures. The freeze binds the canonical rule digest and the
three exact derived arrays/configuration digests.

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
real-model replay in `v2/independent_model_replay.py`. That module imports none
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
process creation, deterministic, and sequential under the same 4 GiB RSS
watchdog and hard deadline as a producer worker.

Before an attempt, all three models and the complete three-edition corpus
snapshot are copied without symlinks into a new private content-addressed
directory. Lab and codec source bytes are exported directly from the exact Git
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
or loads only that buffer. The verifier's second read is intentional and
normative: it is a separate implementation replay, not reuse of producer
objects or declared values. Filesystem-path model parsing, mmap, and
`from_pretrained` are forbidden. Safetensors are loaded from verified bytes into
owned tensors; config and tokenizer JSON are decoded from verified bytes. Thus
later replacement of a path cannot silently change either inference: it causes
a digest failure. Failure to retain enough memory is `FAIL_EXECUTION`.

Preflight may verify and copy all frozen assets, without resolving the future
selection. The runner first durably publishes canonical
`attempt-reservation.json`, committing the attempt identity and every frozen
input binding with `retryPermitted: false`, and then publishes
`attempt-marker.json`. Both transitions use an exclusive pending inode, file
`fsync`, no-overwrite hard-link publication, directory `fsync`, pending-name
removal, and a final directory `fsync`; normal publication never exposes a
partial final JSON file. The reservation and marker precede any selected corpus
resolution/open, model load, or NIST fetch. After the marker is durable, only the supervisor may
make one HTTPS request, to the exact registered NIST pulse endpoint. Redirects,
proxies, alternate hosts, additional requests, and fallback pulses are
forbidden. The supervisor verifies the registered timestamp, trust chain,
signature, and output construction, writes and fsyncs the exact response and
verification record, then installs a Python audit/socket denial before deriving
the selection from those sealed bytes. This is a trusted-control-flow guard,
not permanent OS capability removal: the supervisor process could launch an
unregistered subprocess that does not inherit the Python monkeypatch. The
reviewed code launches only the registered workers and verifier after this
point, and each such child is placed under the macOS deny-network sandbox
before Python starts. The protocol therefore does not claim that a malicious
or modified supervisor is capability-confined.

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

The one-shot may not start before `2026-08-28T18:00:00Z`, twenty-four hours
after the target pulse, so the only permitted request is a historical exact-time
lookup rather than a timing race. The hard execution deadline is
`2026-08-29T18:00:00Z`. Marker creation first uses the host UTC clock; after
the irreversible marker, the HTTPS `Date` observed from NIST over the live,
hostname-verified pinned-TLS connection must independently fall inside that
same half-open window or the attempt fails. This is a TLS-authenticated live
observation: the NIST pulse signature does not cover the HTTP `Date`, and the
archived header bytes are not a publicly verifiable time attestation. Completion
time still uses host UTC plus process monotonic durations and has no external
completion-time attestation; the protocol makes both limitations explicit. If
the supervisor detects the hard execution deadline while the child is active, it
terminates the process group and durably writes a `FAIL_EXECUTION` outcome. A
reservation with a missing, partial, or noncanonical marker/outcome is instead
`CONSUMED_INCOMPLETE`. `PASS` and
`FAIL_GATES` are valid only when their durable `completedAt` is strictly before
the hard deadline; a computation or independent verification that crosses the
boundary is recorded as `FAIL_EXECUTION`, even if its late metrics would pass.

Publication validity is a separate clock. Every consumed attempt state,
including failure or reservation/marker-only interruption, must be packaged
and published under the registered
signed evidence tag with GitHub immutable-release `attestedAt` strictly before
`2026-09-01T18:00:00Z`. The evidence annotated tag MUST also target the exact
frozen `labSource.commit`/`labSource.tree`; evidence bytes are release assets,
not a later source commit. A package first published at or after that evidence
deadline is classified by the public closeout verifier as
`LATE_PUBLICATION_INVALID`, never as PASS or FAIL_GATES. If neither a
reservation nor a marker was created before the hard execution deadline, a separately signed closeout may
classify the specifically audited result root and host as
`NO_ATTEMPT_EXPIRED`; absence on one observed host is not proof that no attempt
exists anywhere. Either closeout classification must be packaged under the
preregistered signed annotated tag
`corelm-crossmodel-livewiki-v2-closeout` and published as an immutable release
strictly before `2026-09-08T18:00:00Z`. The closeout release contains exactly
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

Suite PASS requires all six cells and all three model-level confidence sets to
pass. A failure cannot be averaged away by another model or corpus.

- scientific metric failure: `FAIL_GATES`;
- crash, missing asset/corpus, deadline, or integrity failure:
  `FAIL_EXECUTION`;
- durable attempt reservation with no canonical terminal outcome:
  `CONSUMED_INCOMPLETE`; raw pending/partial state bytes remain forensic
  evidence and never authorize a retry.

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
`v2/schemas/`:

- `design.schema.json` covers the design registration;
- `snapshot.schema.json` covers the immutable future-corpus snapshot;
- `attempt.schema.json` covers the durable `STARTED` marker and its exact
  design, snapshot, runtime, model-asset, corpus, codec, lab-source, and
  private-snapshot commitments;
- `attempt-reservation.schema.json` covers the durable pre-marker reservation
  that consumes the one allowed attempt before any scientific child starts;
- `result.schema.json` covers the independently recomputed six cells, three
  model aggregates, and suite verdict;
- `outcome.schema.json` covers the immutable local terminal outcome and binds
  the result, evidence manifest, and independent verifier;
- `release-receipt.schema.json` covers signed annotated design, snapshot,
  evidence, and closeout tags; the design-wide
  `EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE` source policy, exact commit/tree
  and raw Git objects; immutable GitHub release identity, API timestamp
  observations, verified immutable-release attestation, and every required
  asset digest;
- `ci-artifact-verification.schema.json` covers the exact-commit Linux x86-64
  and macOS arm64 zero-skip artifact inventories and their workflow binding;
- `github-gate-receipt.schema.json` covers the exact review commit, independent
  approval, successful jobs, and the two downloaded CI artifact digests;
- `development-control-report.schema.json` covers the untuned three-model real
  development run and independent replay result;
- `development-control-archive-manifest.schema.json` covers the exact real
  corpus, rights evidence, runtime, model assets, logs, and replay bytes in the
  signed development-control release;
- `freeze-manifest.schema.json` covers the two-stage source, runtime, asset,
  review/CI, development-control, signing-key, and release-receipt freeze
  bindings;
- `evidence-release-manifest.schema.json` covers the post-attempt package for
  PASS, gate failure, execution failure, or reservation/marker-only
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

A local file lock and canonical result path prevent accidental retries but
cannot cryptographically prove compliance with the pre-marker conduct rule or
prove that the machine owner never copied the corpus/private snapshot and
performed an undisclosed execution. The public preregistration, immutable bytes,
no-retry software, complete failure publication, and an independent observer
make such misconduct more auditable; they do not make this an operator-blind
experiment or eliminate the general limitation of self-administered local
experiments. Any claim requiring stronger one-shot or operator-blind assurance
must add an external witness or attested execution environment before freeze,
not after observing the result.

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

The tracked `v2/` contour must contain the design registration, model manifest,
corpus collector, snapshot registration and three ledgers, freeze validator,
one-shot runner, independent verifier, schemas, known-answer vectors, tests,
and documentation for the external result root. The locked runtime manifest
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
review, green CI, freeze manifest, signed tag, and release receipt. Moving one date alone,
reusing a corpus or pulse that became observable before the replacement design,
or freezing an incomplete protocol is forbidden. The operational checklist is
[`FREEZE_READINESS.md`](FREEZE_READINESS.md).

Before publication, this draft still requires independent review of the
canonical JSON schemas, API pagination edge cases, model cache adapters,
selection test vectors, confidence arithmetic, and state-machine failure
paths. Until those reviews and an immutable public freeze exist, this document
is only a plan.
