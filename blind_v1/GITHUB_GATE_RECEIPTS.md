# Archived GitHub exact-commit CI gate receipts

The blind-v1 GitHub gate is **CI-only**. It is not a human-review gate and it does
not claim peer review, independent human validation, operator blindness, or
independent replication. The repository owner is the author, experiment
operator, and release operator. This governance mode is
`AUTHOR_SELF_VERIFICATION`.

`collect_github_gate_receipt.py` replaces operator-entered CI claims with
canonical responses collected directly from GitHub over hostname-checked TLS.
`github_gate_receipt.py` replays those exact archived bytes offline. GitHub does
not sign REST response bodies or headers, and the receipt does not preserve an
independently verifiable TLS transcript. Offline success therefore proves only
canonical structure and internal consistency, not GitHub origin or
authoritative server time. The tracked JSON contract is
`schemas/github-gate-receipt.schema.json`.

The blind-v1 collector and schema must contain no reviewer identity, review approval
state, review declaration, conflict statement, or reviews API response. They
must contain the separate canonical author self-declaration and its explicit
`NO_INDEPENDENT_HUMAN_REVIEW` claim boundary. The PR is used only to bind its
exact head commit to the repository. A self-review or a second author-controlled
account is not accepted as a substitute for independent review because blind-v1 makes
no independent-review claim at all.

## What a passing structural verification establishes

Every receipt must declare the machine-readable boundary
`DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_GITHUB_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`.
The collector verifies TLS during the live request. The offline verifier checks
that the archived bytes consistently encode all of the following claims:

- the pull request belongs to the exact `OWNER/REPO` and its archived head is
  the exact 40-hex implementation commit;
- the exact Actions run reports the registered workflow name and path, exact
  head SHA, `completed`, and `success`;
- every job returned by `filter=all` belongs to that run/head and is
  `completed/success`; skipped, cancelled, neutral, failed, or incomplete jobs
  fail closed;
- the exact `Linux x86-64 locked runtime` job uses the registered Ubuntu runner
  label and reports `Linux/x86_64` from inside the guest;
- the exact `macOS arm64 clean clone` job uses the registered macOS runner label
  and reports `Darwin/arm64` from inside the guest;
- jobs and artifacts each fit in one unpaginated 100-result response; any
  pagination ambiguity or mismatched `total_count` fails;
- the four server `Date` values are monotonic and span no more than the
  registered collection window;
- every response is HTTP 200 JSON with one nonempty request ID and the exact
  registered GitHub API version;
- Actions artifact metadata binds the exact run attempt, names, expiration
  state, byte counts, and API-supplied `sha256:` digests.

The receipt explicitly records `artifactBytesArchived: false`. The raw Linux
and macOS Actions ZIP bytes remain separate mandatory design-release assets.

The design, schema, collector, tests, and this document bind the exact tracked
`.github/workflows/blind-v1-development-controls.yml`: 13,962 bytes with SHA-256
`6c0b54bc4c318a2b55069852e07ae3355686ffb49a72c3ca4542396cf5375e87`.
No prose value or operator-entered override may repair a mismatch.

## Collection

Use a read-only token only if anonymous API limits are insufficient. The flag
names an environment variable; never put its value in arguments:

```sh
export CORELM_GITHUB_READ_TOKEN='read-only token'

python3 -I -B blind_v1/collect_github_gate_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --pull-request '<pull-request-number>' \
  --implementation-commit '<exact-40-hex-implementation-commit>' \
  --workflow-run-id '<numeric-run-id>' \
  --workflow-name 'Author-verified blind-v1 development controls' \
  --workflow-path '.github/workflows/blind-v1-development-controls.yml' \
  --token-env CORELM_GITHUB_READ_TOKEN \
  --output /absolute/path/to/github-ci-gate-receipt.json
```

The normative blind-v1 CLI must not accept a reviewer-related argument. If the
tracked implementation still requires one, blind-v1 is not freeze-ready and the CLI,
schema, verifier, fixtures, and tests must be corrected on a new exact commit.

The collector connects directly to `api.github.com:443` with system CA trust,
hostname checking, TLS 1.2+, and HTTP/1.1. It never consults proxy environment
variables, follows no redirect, and has no retry path. It makes exactly four
requests, in this order:

1. `/pulls/{pr}`
2. `/actions/runs/{runId}`
3. `/actions/runs/{runId}/jobs?filter=all&per_page=100&page=1`
4. `/actions/runs/{runId}/artifacts?per_page=100&page=1`

There is no request to a pull-request reviews endpoint. An implementation that
makes a fifth GitHub request, accepts a review response, or derives scientific
status from an approval record violates this protocol.

The exact wire response headers and decoded JSON entity bytes are embedded with
byte counts and SHA-256. The token is neither printed nor stored, and collection
aborts if it appears in response bytes. The complete canonical receipt is
passed immediately to the offline verifier. Only after structural verification
succeeds is the output created with no-follow, exclusive, durable semantics.
Existing output is rejected before any request.

## Exact scientific boundary

GitHub REST does **not** provide signed responses or one transactionally
consistent snapshot across the PR, workflow-run, jobs, and artifacts endpoints.
The live collector checks TLS and records the states and `Date` values it
receives inside one bounded window. Offline replay proves only that the archived
bytes, derived fields, digests, and recorded window are structurally
consistent. It does not prove GitHub origin, authoritative server time,
simultaneity, or that the PR/head/run remained unchanged afterward.

GitHub Actions job labels are scheduler metadata, not measurements of the CPU.
The guest platform reports, runtime manifests, zero-skip logs, preflight output,
design checks, and cryptographic known-answer results inside the downloaded
artifacts are therefore mandatory. The offline design packager hashes each raw
ZIP against the receipt, verifies the exact flat member inventory, and rejects
unsafe, extra, nested, encrypted, ZIP64, prefixed/trailed, oversized, foreign,
or mismatched archives without extracting them.

These controls establish repeatable exact-commit CI evidence under author
self-verification. They do not establish independent human review, peer review,
operator blindness, or independent replication. The separate verifier and
fresh real-model replay are implementation-level checks executed within the
same author-controlled project; the word “independent” in those component names
must not be interpreted as human or organizational independence.

## Freeze-manifest integration

The freeze manifest must commit the CI receipt file SHA-256 and its exact
`evidenceBoundary`, then derive the PR, implementation commit, workflow run,
job, platform, and artifact identities only from the structurally verified
receipt. Parallel CLI-entered status, conclusion, job inventory, platform
result, artifact digest, or timestamp strings are not authority. The CI receipt
and both exact platform ZIPs are required immutable design-release assets.

The author-self-verification policy must also be serialized in the frozen
design and freeze manifest, including at least:

```text
verificationMode=AUTHOR_SELF_VERIFICATION
independentHumanReviewPerformed=false
peerReviewPerformed=false
operatorBlindnessClaimed=false
independentReplicationClaimed=false
```

Absence of a human approval is intentional in blind-v1; absence or failure of any
exact-commit CI, zero-skip, artifact, signing, release, E2E, or verifier gate is
still a freeze failure.
