# Archived GitHub review and Actions gate receipts

`collect_github_gate_receipt.py` replaces operator-entered review and CI claims
with canonical responses collected directly from GitHub over hostname-checked
TLS. `github_gate_receipt.py` replays those exact archived bytes offline. GitHub
does not sign REST response bodies or headers, and the receipt does not preserve
an independently verifiable TLS transcript. Offline success therefore proves
only canonical structure and internal consistency, not GitHub origin. The
tracked JSON contract is `schemas/github-gate-receipt.schema.json`.

## What a passing structural verification establishes

Every receipt must declare the machine-readable boundary
`DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_GITHUB_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`.
The collector verifies TLS during the live request. The offline verifier checks
that the archived bytes consistently encode all of the following claims; it
cannot independently authenticate who produced those bytes.

The verifier requires all of the following:

- the pull request belongs to the exact `OWNER/REPO` and its archived head is
  the exact 40-hex implementation commit;
- the selected reviewer login is not the repository-owner login, is a GitHub
  `User` rather than a bot/organization, and its latest substantive review is
  `APPROVED` on that exact commit with this exact review body:

  > I independently reviewed the normative protocol, canonical schemas,
  > fail-closed implementation, zero-skip tests, and evidence plan on this
  > exact commit. I have no undisclosed conflict of interest with the
  > repository owner. I found no unresolved P0 blocker and approve freeze
  > publication.
- no reviewer's latest substantive state is `CHANGES_REQUESTED`, and no later
  `CHANGES_REQUESTED` or `DISMISSED` record follows the selected approval;
- the exact Actions run reports the expected workflow name and tracked path,
  exact head SHA, `completed`, and `success`;
- the frozen registration separately commits the tracked workflow's exact
  12,487 bytes and SHA-256
  `b9215fec0922fd8462ba5e8de83d6406a7e8fbd1f0c05adff05d0b406da92dbb`;
- every job returned by `filter=all` is on the same run/head and is
  `completed/success`; `skipped`, `cancelled`, neutral, failed, and incomplete
  jobs all fail;
- the exact `Linux x86-64 locked runtime` job has the `ubuntu-24.04` scheduler
  label and the exact `macOS arm64 clean clone` job has the `macos-15`
  scheduler label; the tracked macOS job separately requires `uname -m` to
  equal `arm64`;
- reviews, jobs, and artifacts each fit in one unpaginated 100-result response;
  any `Link` header or mismatched `total_count` fails rather than silently
  omitting a page;
- the five server `Date` values are monotonic and span no more than 120 seconds;
- every response is HTTP 200 JSON with one nonempty request ID and the exact
  selected GitHub API version.

The receipt also binds nonexpired Actions artifact metadata and each
API-supplied `sha256:` digest.  It explicitly records
`artifactBytesArchived: false`.

## Collection

Use a read-only token only if anonymous API limits are insufficient.  The flag
names an environment variable; never put its value in arguments:

```sh
export CORELM_GITHUB_READ_TOKEN='read-only token'

python3 -I -B v2/collect_github_gate_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --pull-request 19 \
  --implementation-commit '<exact-40-hex-reviewed-commit>' \
  --reviewer '<canonical-independent-login>' \
  --workflow-run-id '<numeric-run-id>' \
  --workflow-name 'Blind v2 development controls' \
  --workflow-path '.github/workflows/v2-development-controls.yml' \
  --token-env CORELM_GITHUB_READ_TOKEN \
  --output /absolute/path/to/github-gate-receipt.json
```

The collector connects directly to `api.github.com:443` with system CA trust,
hostname checking, TLS 1.2+, and HTTP/1.1.  It never consults proxy environment
variables, follows no redirect, and has no retry path.  It makes one request to
each exact endpoint, in this order:

1. `/pulls/{pr}`
2. `/actions/runs/{runId}`
3. `/actions/runs/{runId}/jobs?filter=all&per_page=100&page=1`
4. `/actions/runs/{runId}/artifacts?per_page=100&page=1`
5. `/pulls/{pr}/reviews?per_page=100&page=1`

The exact wire response headers and decoded JSON entity bytes are embedded with
byte counts and SHA-256. The token is neither printed nor stored, and collection
aborts if it is echoed in response bytes. The complete canonical receipt,
including the required `evidenceBoundary`, is passed immediately to the offline
verifier. Only after that structural check succeeds is the output created with
no-follow, exclusive, durable semantics. Existing output is rejected before any
request.

## Exact scientific boundary

GitHub REST does **not** provide signed responses or one transactionally
consistent snapshot across the PR, review, workflow-run, jobs, and artifacts
endpoints. The live collector checks TLS and records the states and `Date`
values it receives inside one bounded window. Offline, the receipt proves only
that its archived bytes, derived fields, digests, and recorded window are
structurally consistent. It does not independently prove GitHub origin, an
authoritative server time, simultaneity, or that no review/head/run changed
after the final response. Freeze must treat collection as the live observation,
use it immediately, and publish its hash/time; a later state requires a new
receipt, never mutation of this one.

GitHub Actions job labels are scheduler/controller metadata. They are not a
measurement of the CPU that executed the job. The registered standard runner is
`macos-15`; its tracked job fails unless the guest itself reports `arm64`. A
scientific hardware claim additionally needs the job's archived `uname -m`,
OS/environment report, and artifact bytes in the release evidence. Standard
GitHub log and artifact-download REST endpoints
return redirects to temporary external URLs.  Following those URLs would
violate this collector's no-redirect and `api.github.com`-only policy, so this
receipt does not pretend to archive logs or artifact bytes.

Consequently, the exact downloaded platform ZIP payloads are mandatory design
release assets under the canonical filenames `linux-ci-artifact.zip` and
`macos-arm64-ci-artifact.zip`. The offline design packager hashes each raw ZIP
against the matching Actions digest/name/run commitment, verifies the exact
five flat platform filenames, and validates preflight/runtime/design-check
platform identity, the registered workflow digest, one successful zero-skip
log, and the exact real cryptographic release-attestation known-answer result.
Unsafe, extra, nested, encrypted, ZIP64, prefixed/trailed, or
oversized archives fail closed and are never extracted. These later bytes do
not change or repair the API receipt; and the API receipt cannot stand in for
their bytes.

Likewise, `filter=all` structurally verifies that every job contained in the
archived response was successful. It cannot prove offline that GitHub produced
that response or that a conditionally omitted job should have existed. The tracked
workflow file and its preregistered job/matrix inventory must be reviewed on the
same implementation commit.

The login inequality `reviewer != repository owner`, `User` type, and exact
declaration prove only what the authenticated account stated in that review.
They do not establish a person's employer, organizational membership,
conflicts of interest, or real-world identity.  If those stronger claims are
needed, archive a separately signed identity/conflict declaration as an
additional release asset; it cannot replace the exact-commit GitHub review.

## Freeze-manifest integration API

The integration point is:

```python
from v2.github_gate_receipt import verify_github_gate_receipt

verified = verify_github_gate_receipt(
    raw_receipt,
    expected_repository="ALLPROTO/core-lm-cross-model-lab",
    expected_pull_request_number=19,
    expected_implementation_commit="...",
    expected_reviewer_login="...",
    expected_workflow_run_id=30123456789,
    expected_workflow_name="Blind v2 development controls",
    expected_workflow_path=".github/workflows/v2-development-controls.yml",
)
```

The freeze manifest should commit `verified.receipt_sha256` and
`verified.evidence_boundary`, and use the returned
PR/commit/reviewer/review/run/workflow/job identities as the structurally
verified content of the archived observation. It must not accept
parallel CLI-entered review state, conclusion, job status, platform result, or
timestamps as authority.  The receipt itself must be a required immutable
design-release asset before freeze.
