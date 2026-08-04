# Canonical signed GitHub release receipts for v4

`collect_release_receipt.py` is the online collector for the offline contract in
`release_receipt.py` and `schemas/release-receipt.schema.json`. A successful
`corelm-github-release-receipt-v2` combines two separately delimited records:
four direct-TLS GitHub API observations and one GitHub immutable-release
attestation. The collector first invokes exactly the pinned GitHub CLI below;
`gh release verify --format json` obtains and verifies the release bundle online
and its complete output is archived. It then invokes an independently pinned
Cosign 3.0.6 binary with no network access against the archived bundle, the
SHA-256 of one deterministically selected release asset, and the tracked GitHub
trusted root.
The offline verifier repeats that Cosign operation and also replays every signed
subject, signer identity, release, asset, commit, and timestamp binding.
This cryptographic claim applies to the immutable-release attestation. The four
separate GitHub API captures remain direct-TLS observations whose offline replay
establishes structural consistency, not a GitHub response signature or an
independent server-time attestation.

Release attestation verifies publication bytes and time; it does not supply
independent human review, peer review, operator blindness, or independent
replication. V4 remains `AUTHOR_SELF_VERIFICATION`, with the repository owner
also acting as author, experiment operator, and release operator.

## Preconditions

The release must already exist and be GitHub-immutable, non-draft, and
non-prerelease.  Its annotated tag must target the exact expected commit.  The
expected commit, tree, deadline, SSH signing-key fingerprint, and public key
are inputs, not values learned from GitHub. SSH is the only accepted tag
signature type.

For every v4 development-control, design, snapshot, evidence, and closeout
release, the expected commit and tree are exactly the author-self-verified,
zero-skip-CI implementation
identity (and, after freeze, `labSource.commit` and `labSource.tree` from the
canonical frozen design). The normative source policy is
`EXACT_FROZEN_DESIGN_LAB_SOURCE_COMMIT_TREE`; a later publication, packaging,
DOI, evidence, or closeout commit is not an admissible substitute.

The numeric immutable release ID is also an explicit input.  This is necessary
because the canonical verifier requires `GET /releases/{id}`.  Discovering the
ID through another API request would add an unarchived fifth request.  Obtain it
from the release URL/API metadata before starting the canonical collection.

Prepare a directory containing exactly the required release assets.  Bind each
role to one portable filename with `--asset ROLE=NAME`.  The role set comes
directly from `REQUIRED_ASSET_ROLES`; it differs for `development-control`,
`design`, `snapshot`, `evidence`, and `closeout` releases. Symlinks, extra
files, missing files, duplicate names, and files that change while being read
are rejected.

`--public-key` is one canonical Ed25519 OpenSSH public-key record terminated by
exactly one LF. Blank lines, a second record, CR, NUL, another key algorithm,
or non-canonical base64 are rejected. The collector SHA-256 hashes the exact
public-key bytes and binds that commitment into the receipt.

Both collection and offline verification require the system executable
`/usr/bin/ssh-keygen`. There is no PATH lookup, alternative verifier, or
signature-format fallback. If that path is absent, is not a regular executable,
or changes during verification, the operation fails closed before a successful
receipt can be created or accepted.

The collector additionally requires an explicit absolute path to a regular
executable through `--github-cli`; it never performs a PATH lookup. The file at
that caller-chosen path must be the preregistered GitHub CLI 2.97.0 macOS-arm64 binary
(`38,857,376` bytes, SHA-256
`0d17dddf96bcc1dc50f3420a064d593d64016b0be16286a6c26121f2a5cb8316`).
The collector checks its bytes and identity before and after online
verification, runs it with an isolated configuration, and archives its exact
successful output.

Collection and offline audit also require one exact Cosign 3.0.6 executable,
passed explicitly with `--cosign`; no PATH lookup or downloaded trust is
allowed. The supported pinned variants are:

| Host | Bytes | SHA-256 | Distribution |
| --- | ---: | --- | --- |
| macOS arm64 | 134,320,242 | `5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084` | `https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-darwin-arm64` |
| Linux x86-64 | 135,178,161 | `c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74` | `https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64` |

Both variants must report version `v3.0.6`, Git commit
`f1ad3ee952313be5d74a49d67ba0aa8d0d5e351f`, build date
`2026-04-06T21:39:58Z`, Go `go1.25.7`, and the registered platform. The
trusted root is the tracked regular file
`v4/trust/github/trusted_root.json` (`28,886` bytes, SHA-256
`26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485`).
The verifier byte-checks and privately copies both executable and root before
use, and runs with isolated home and cache directories.

For a normal publication, `attestedAt` is decoded from the raw signed RFC3161
timestamp, cryptographically verified, and required to equal the semantic
verification result before it is compared with the registered deadline. It
must be strictly before that deadline; neither a local clock nor an API
`published_at`/`Date` observation is the normative deadline boundary.

Before production use on each supported host, run the tracked, non-synthetic
real GitHub release-attestation known-answer vector with that host's exact
binary. On the registered Mac:

```sh
python3 -I -B \
  v4/tests/integration_release_attestation_crypto_known_answer.py \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64
```

The canonical result must state `KNOWN_ANSWER_PASS`, `synthetic=false`, and
`networkUsed=false`, and bind the expected real release bundle, selected asset,
RFC3161 `attestedAt`, Cosign binary, and tracked root hashes. The Linux control
uses the same command with the byte-pinned Linux x86-64 binary path.

## Production command

Run from the exact clean repository clone.  Example role bindings are shown for
a design release. The two CI ZIP filenames are canonical; all bindings must
match the actual release:

```sh
# If authentication is required, set CORELM_GITHUB_TOKEN out of band to a
# read-only token. Omit --token-env below for an unauthenticated public request.

python3 -I -B v4/collect_release_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --kind design \
  --tag '<signed-annotated-tag>' \
  --commit '<40-lowercase-hex-commit>' \
  --tree '<40-lowercase-hex-tree>' \
  --deadline '2026-09-07T00:00:00Z' \
  --signature-type SSH \
  --key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --public-key v4/signing/corelm-crossmodel-v4-signing.pub \
  --repo-path /absolute/path/to/clean-clone \
  --release-id '<numeric-release-id>' \
  --assets-dir /absolute/path/to/exact-downloaded-assets \
  --github-cli /absolute/path/to/pinned-gh-2.97.0-macos-arm64 \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64 \
  --asset asset-source-manifest=asset-source-manifest.json \
  --asset design-registration=design-registration.json \
  --asset development-control-report=development-control-report.json \
  --asset development-control-archive-receipt=development-control-archive-receipt.json \
  --asset freeze-manifest=freeze-manifest.json \
  --asset full-asset-receipt=full-asset-receipt.json \
  --asset github-gate-receipt=github-gate-receipt.json \
  --asset linux-ci-artifact=linux-ci-artifact.zip \
  --asset macos-arm64-ci-artifact=macos-arm64-ci-artifact.zip \
  --asset runtime-manifest=runtime-manifest.json \
  --asset sbom=sbom.cdx.json \
  --asset sha256-manifest=sha256-manifest.json \
  --token-env CORELM_GITHUB_TOKEN \
  --signature-failure-output /absolute/path/to/design-signature-failure.json \
  --output /absolute/path/to/design-publication-receipt.json
```

For a design release, generate this directory with
`package_design_release.py`; do not assemble it manually. It requires both raw
Actions downloads under the two canonical ZIP filenames and revalidates their
GitHub digest/name/run bindings plus their internal platform, runtime, workflow,
and zero-skip evidence. The public key is verified separately and must not be
copied into the asset directory.

```sh
python3 -I -B v4/package_design_release.py package \
  --frozen-design /absolute/path/to/design-registration.json \
  --development-control-report /absolute/path/to/development-control-report.json \
  --development-control-archive-receipt /absolute/path/to/development-control-archive-receipt.json \
  --freeze-manifest /absolute/path/to/freeze-manifest.json \
  --github-gate-receipt /absolute/path/to/github-gate-receipt.json \
  --linux-ci-artifact /absolute/path/to/downloaded-linux-artifact.zip \
  --macos-arm64-ci-artifact /absolute/path/to/downloaded-macos-artifact.zip \
  --asset-source-manifest v4/model-assets.draft.json \
  --full-asset-receipt /absolute/path/to/full-asset-receipt.json \
  --runtime-manifest /absolute/path/to/runtime-manifest.json \
  --sbom /absolute/path/to/sbom.cdx.json \
  --signing-public-key v4/signing/corelm-crossmodel-v4-signing.pub \
  --output-root /absolute/path/to/new-design-release-assets
```

The earlier `development-control` release contains exactly
`development-control-report.json`, `development-control-artifacts.zip`, and
`sha256-manifest.json`. Generate it only with
`package_development_control_release.py`; the complete copy/paste sequence is
in [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md). Its signed annotated tag is
`corelm-crossmodel-livewiki-v4-development-control`; its GitHub immutable-release
attestation must have `attestedAt` strictly before `2026-09-07T00:00:00Z`.

Its ZIP contains exactly 2,088 manifested artifacts, including the pinned UD
English PUD r2.18 source, corpus manifest, upstream README and license,
attribution notice, source-evidence file, and rights matrix. The archive
manifest records CC BY-SA 3.0 for the corpus and reversible/source-derived
evidence, preserves attribution and the license URI, marks changes, and retains
share-alike compatibility without added restrictions. The packager and archive
verifier re-open those exact bytes. This records consistent upstream
declarations and is not an independent ownership conclusion. The signed tag,
immutable release, and this canonical attested receipt remain mandatory; local
packaging by itself does not satisfy the P0 gate.

Do not put the token value on the command line.  `--token-env` names an
environment variable; the value is held only in memory.  The collector does not
copy the ambient environment to Git, does not consult proxy variables, and
aborts if GitHub echoes the token in any archived response bytes.

## Fixed request and verification behavior

The collector sends exactly one direct TLS HTTP/1.1 request, without retries or
redirects, to each endpoint in this order:

1. `GET /repos/{owner}/{repo}/git/commits/{expectedCommit}`
2. `GET /repos/{owner}/{repo}/releases/{expectedReleaseId}`
3. `GET /repos/{owner}/{repo}/git/tags/{localAnnotatedTagOID}`
4. `GET /repos/{owner}/{repo}/git/ref/tags/{expectedTag}`

Only `https://api.github.com:443` is allowed.  The system CA trust store,
hostname verification, TLS 1.2 or later, `Accept-Encoding: identity`, a bounded
body, and a bounded total read deadline are enforced.  The exact wire response
header block and the exact decoded JSON entity bytes are archived.  `Date`,
`X-GitHub-Request-Id`, and `X-GitHub-Api-Version-Selected` must each occur once.
Both the four server `Date` values and the four local `capturedAt` values must be
monotonic in canonical request order, and each complete capture span is bounded
to 300 seconds. Those TLS-authenticated API observations establish bounded
collection chronology only; they are not a GitHub cryptographic time attestation
and do not determine whether the release met its deadline.

Before network collection, Git reads the exact raw annotated-tag and commit
payloads from the local object database.  `git verify-tag --raw` runs against a
fresh HOME/config/trust directory.  The Git version, combined transcript, exit
status, expected fingerprint, public-key SHA-256, tag OID, target commit, and
verification time form the signature record.  A nonzero exit or fingerprint
mismatch raises `SignatureVerificationError`; its `.record` contains a
`status: FAILED` diagnostic and no canonical receipt is written.  It must never
be relabeled `VERIFIED`.  When `--signature-failure-output` is supplied, that
diagnostic (including transcript, tool version, exit code, fingerprint, and
public-key commitment) is durably archived to the exclusive sidecar path.

Finally, every local asset is re-hashed with no-follow file descriptors.  The
collector constructs canonical JSON and `contentSHA256`, calls
`verify_release_receipt(...)` immediately on the complete bytes and assets, and
only then creates `--output` with exclusive/no-follow semantics.  An existing
output is rejected before Git or network activity; it is never overwritten.

The same collection performs exactly one pinned `gh release verify TAG -R
REPOSITORY --format json` invocation. Its online verification must succeed and
its archived output must bind the exact GitHub repository, release ID, tag,
commit, complete asset-name/SHA-256 set, GitHub release signer policy, and one
GitHub RFC3161 timestamp.

For the required annotated tags, the first signed release subject carries the
SHA-1 object ID of the annotated tag itself, not the peeled target commit. The
semantic replay therefore requires that signed subject to equal the locally
rehash-verified tag object OID. The separately verified signed tag payload then
binds that object to the exact target commit and tree. Treating the release
subject SHA-1 as the peeled commit is valid only for a lightweight tag and is
rejected by this protocol.

Immediately afterward, the collector selects the lexicographically first
ASCII asset name, byte-verifies private copies of Cosign and the tracked root,
byte-verifies a private copy of the selected local asset against its expected
SHA-256, and runs this exact argument sequence with an isolated environment
(the two path placeholders are the verifier's private copies):

```sh
'<private-byte-verified-cosign>' verify-blob-attestation \
  --bundle '<private-canonical-archived-release-bundle>' \
  --trusted-root '<private-byte-verified-github-trusted-root>' \
  --certificate-identity https://dotcom.releases.github.com \
  --certificate-oidc-issuer-regexp '.*' \
  --type https://in-toto.io/attestation/release/v0.2 \
  --use-signed-timestamps \
  --private-infrastructure \
  --insecure-ignore-sct \
  --check-claims=true \
  --digest '<exact-selected-release-asset-sha256>' \
  --digestAlg sha256
```

Success is exactly exit status zero, empty stdout, and `Verified OK` followed
by one LF on stderr. Cosign verifies the DSSE signature, X.509 certificate
chain, exact certificate SAN, RFC3161 timestamp signature and chain, predicate
type, and selected asset digest. The semantic verifier then checks every signed
subject against the complete local asset inventory. The receipt binds the
Cosign binary identity, trusted-root digest, selected asset, bundle digest,
RFC3161 `attestedAt`, and transcript. Normal receipts require `attestedAt <
deadline`; the explicit late-closeout path alone requires `attestedAt >=
deadline`.

Digest mode is mandatory rather than an optimization. Cosign 3.0.6 limits a
blob input to 128 MiB, while a valid immutable release may contain a larger
selected asset. The collector still opens, copies, and SHA-256 verifies the
complete local asset before invoking Cosign. Passing that verified digest makes
Cosign check the same in-toto subject without weakening the local byte binding
or the subsequent complete subject-name/digest replay.

The real known-answer integration also performs a negative digest control with
the same pinned Cosign binary and genuine signed bundle. A locally valid digest
that is absent from the signed in-toto subjects must fail. This keeps
`--check-claims=true` executable rather than relying on its current default.

### Prior v3 development-control verifier incident on 2026-08-04

The immutable non-scientific development-control release with database ID
`365071220` correctly binds signed annotated tag object
`13a1a15bc9ecd4bc203ba8d93036764282abe32d`, implementation commit
`36a63b114a3c6979d8363565d5bb7ff9183bbfe2`, and exactly the three registered
assets. GitHub's release attestation is valid and has signed RFC3161 time
`2026-08-04T18:26:40Z`.

The original independent verifier nevertheless failed closed because it passed
the 523,227,575-byte `development-control-artifacts.zip` to Cosign as a blob;
Cosign rejected it above its 134,217,728-byte layer limit. No canonical receipt
or signature-failure sidecar was created, and the immutable tag and release were
not modified. This release is retained as a transparent non-scientific
failed-freeze archive. The digest-mode change is a post-release regression fix;
it must not be used to relabel the original source identity as freeze-complete.
The full replay then exposed a second original defect: it expected the release
subject SHA-1 to equal the peeled commit, whereas GitHub correctly signed the
required annotated tag object OID. That binding is fixed and regression-tested
only in later commits; it does not change the failed-freeze classification.

Those identifiers belong only to v3. V4 has no development-control receipt or
release yet. It must execute and package a fresh three-model control on the
exact v4 commit, publish the v4 tag and assets, and collect a new receipt. The
v3 incident is retained here solely as a regression requirement and cannot be
mechanically relabeled as v4 evidence.

GitHub release bundles currently contain the signed RFC3161 timestamp but no
Rekor entry or certificate SCT. Therefore `--private-infrastructure` and
`--insecure-ignore-sct` are intentional, registered boundary flags: they do
not disable DSSE, X.509-chain, exact-SAN, asset-digest, or RFC3161 verification.
They do mean that the receipt makes **no** transparency-log inclusion, SCT, or
public-log non-equivocation claim. The issuer regexp adds no issuer restriction;
the exact GitHub release SAN and the tracked certificate roots remain enforced.

## Offline audit

Archive the receipt, the exact public-key file, and the exact asset directory.
An auditor invokes `verify_release_receipt` with the preregistered repository,
kind, tag, commit, tree, deadline, SSH fingerprint, public-key SHA-256, and a
`PinnedCosignReleaseAttestationVerifier` constructed from the exact supported
host binary. The verifier performs no network request and independently reruns
the archived raw tag signature through `/usr/bin/ssh-keygen -Y verify` under
the fixed `git` namespace and frozen `allowed_signers` policy. It reopens every
release asset, repeats the pinned Cosign digest operation against the archived
bundle and tracked root, validates the archived cryptographic-verification
record, derives `attestedAt` from the signed RFC3161 bytes, and cross-checks the
fresh result against the semantic replay and deadline relation. No ambient
Cosign trust or archived success assertion can substitute for that operation.
The transparency boundary above remains unchanged during offline audit.
