# Blind-v2 freeze readiness gate

This checklist is subordinate to [`PROTOCOL.md`](PROTOCOL.md) and does not
change any registered date, model, corpus, metric, or failure rule.  It exists
to make the transition from a development draft to an immutable public design
auditable.  A checked box is evidence only when the cited immutable artifact
is available; prose assertions and locally edited status fields never satisfy
a gate.

## P0 gates before the design release

- [ ] One exact lab implementation commit and tree contain the complete
  normative protocol, canonical schemas, collector, NIST verifier, runner,
  durable state machine, source sealer, evidence packager, and independent
  verifier.
- [ ] On that exact source and locked runtime, the tracked real-data
  development E2E control completes producer -> VTL5 -> independent real-model
  replay for all three registered models on the exact pinned UD English PUD
  r2.18 CoNLL-U bytes. The upstream `test` split is reused only for this
  non-scientific development control and is not the prospective scientific
  holdout. Its canonical report/logs are archived by hash, state
  `countsTowardScientificVerdict=false`, apply no scientific thresholds, and
  cause no candidate/protocol change. It never uses synthetic input,
  future-corpus bytes, NIST, or reservation/marker state. The offline
  development-artifact verifier must independently parse all 1,000 CoNLL-U
  sentence blocks,
  reconstruct the 32 partitions and jobs, parse every JSONL/VTL5 byte,
  recompute page metrics and replay digests, and prove the top-level evidence
  streams are exact model-order concatenations. The complete 2,088-artifact set
  contains and re-verifies the corpus manifest/source,
  `inputs/LICENSES/source-evidence.json`, `inputs/LICENSES/ASSET_LICENSES.md`,
  the exact upstream README and license, and
  `inputs/LICENSES/UD_ENGLISH_PUD_ATTRIBUTION.md`.
- [ ] Confirm that the 2,088 evidence artifacts contain no model weights. All
  24 model files remain external private inputs and are bound by exact path,
  byte count, and SHA-256 in the sealed plan, pinned asset manifest, and full
  rehash receipt. Confirm the deterministic ZIP is strictly below the
  1,800,000,000-byte cap and has exactly the report inventory member set.
- [ ] The report and complete deterministic artifact ZIP are published in the
  immutable `corelm-crossmodel-livewiki-v2-development-control` release from a
  signed annotated tag targeting that same commit. A canonical v2 receipt binds
  all three release assets and requires the GitHub immutable-release RFC3161
  `attestedAt` strictly before `2026-08-09T00:00:00Z`; local files,
  operator-entered timestamps, API `published_at`, and API `Date` do not
  satisfy this gate.
- [ ] Release-receipt collection and independent replay both use exact pinned
  Cosign 3.0.6 bytes for the host and the tracked
  `v2/trust/github/trusted_root.json` (`28,886` bytes, SHA-256
  `26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485`).
  The archived bundle passes DSSE, X.509-chain, exact GitHub SAN,
  selected-asset-digest, and RFC3161 timestamp signature/chain verification;
  signed `attestedAt` equals the semantic result. The registered
  `--private-infrastructure --insecure-ignore-sct` boundary is explicit:
  GitHub's bundle supplies neither Rekor inclusion nor a certificate SCT, so no
  transparency-log/SCT claim is permitted, while the listed cryptographic
  checks remain mandatory. This attestation claim does not upgrade the separate
  review/CI API receipt described below. The tracked real, non-synthetic
  release-attestation known-answer vector passes offline with the pinned host
  binary inside a Linux network namespace with no host interfaces and a macOS
  `sandbox-exec` profile that denies all network operations.
- [ ] The development archive manifest declares the corpus and reversible or
  source-derived evidence under CC BY-SA 3.0, preserves contributor attribution
  and the license URI, marks extraction/partition changes, retains share-alike
  compatibility, adds no effective restrictions, and carries the exact rights
  evidence. The upstream declarations are consistent but are not represented as
  an independent ownership or chain-of-title conclusion. The packager and
  archive verifier must re-open these bytes; a manual ZIP cannot satisfy this
  gate.
- [ ] A clean clone of that exact commit passes the locked zero-skip suite on
  Linux x86-64 and macOS arm64. The collector directly observes over verified
  TLS archived CI responses that record the exact head commit, preregistered
  workflow bytes, jobs, conclusion, and server completion time. The mandatory
  `evidenceBoundary` states that GitHub does not sign these responses and their
  offline verification is structural consistency only; the archived receipt
  alone is not independent proof of GitHub origin or authoritative server time.
  Because the API receipt intentionally archives metadata
  rather than artifact bytes, the design release must include the exact raw
  downloads as `linux-ci-artifact.zip` and `macos-arm64-ci-artifact.zip`.
  Their SHA-256 values, Actions name/run/attempt, exact five-member inventory,
  platform reports, workflow digest, runtime/source identity, zero-skip log,
  and real cryptographic known-answer result must pass
  `package_design_release.py` before publication.
- [ ] An independent reviewer other than the repository owner approves that
  exact commit using the exact registered review declaration. A different
  implementation commit, missing declaration, or design-tag target invalidates
  the approval. GitHub account identity alone is not claimed as proof of the
  reviewer's real-world identity or conflicts.
- [ ] The complete model-asset receipt is regenerated from all 24 exact local
  files, including all three safetensors files, and matches 1,916,375,741
  bytes.  The receipt and its SHA-256 are immutable release assets.
- [ ] The complete clean runtime manifest and CycloneDX SBOM bind the exact lab
  commit, codec commit/tree, interpreter, locked dependencies, every runtime
  file, and the full asset receipt.
- [ ] Production NIST transport CA bytes and a complete offline leaf,
  intermediate, and root certificate trust bundle are pinned, re-opened, and
  accepted by the non-fixture known-answer verifier for the target time. The
  design separately pins the allowed root DER hash; trusting a self-consistent
  manifest alone is forbidden.
- [ ] The dedicated SSH signing public key is tracked and preregistered by exact
  fingerprint and file SHA-256, is registered with the hosting account as a
  signing key, and verifies a rehearsal annotated tag before the real freeze.
- [ ] The two-stage freeze manifest re-opens all inputs and binds archived
  review/CI observations together with their structural-only evidence boundary.
  It must not represent offline replay as GitHub-origin attestation. The freeze
  manifest and frozen design are constructed
  outside the reviewed Git tree as release assets; the frozen design binds the
  exact complete freeze-manifest file SHA-256 without a self-reference.
- [ ] The design publication uses a signed annotated tag and immutable GitHub
  release.  The tag targets the exact reviewed and CI-approved implementation
  commit/tree recorded in `labSource`; there is no later publication commit. A
  canonical publication receipt binds that repository, tag object, signature
  verification, commit, tree, release ID, complete asset set, and the verified
  GitHub immutable-release attestation, including the externally constructed
  frozen design. Its `attestedAt` is strictly before the design deadline.
- [ ] The public design release is available strictly before
  `2026-08-09T00:00:00Z`; local time, draft PR time, commit author time, or an
  unsigned lightweight tag does not satisfy the deadline.

Until every P0 box has immutable evidence, the only valid lifecycle state is
`DRAFT_NOT_PREREGISTERED`, `readyToFreeze=false`, and
`countsTowardScientificVerdict=false`.

## P0 gates after the design release and before the attempt

- [ ] Both registered MediaWiki crawls and the finalize phase run at their
  registered times.  Exact HTTP responses, complete ledgers, raw creation
  revision bytes, token commitments, and attribution are archived.
- [ ] A pre-publication snapshot registration commits only already-existing
  bytes and the planned snapshot release identity. It never claims the hash,
  attestation, or API timestamp of a release that does not yet exist.
- [ ] A separate signed snapshot publication receipt proves the exact
  registration, commit/tree, release, complete assets, and immutable-release
  `attestedAt` strictly before the snapshot deadline.
- [ ] `runner.py prepare` re-opens and seals the two publication receipts,
  corpus, runtime, assets, trust bundle, exact Git objects, and all manifests
  into the private snapshot before an attempt marker exists.
- [ ] The canonical result root is absent and the registered Mac passes power,
  memory, disk, runtime, source, and network-sandbox preflight.

## Whole-window rescheduling rule

If any P0 design gate cannot be proven by the registered decision checkpoint
`2026-08-08T12:00:00Z`, do not publish or label the current draft as frozen.
Publish an explicit abandoned/superseded development notice if needed, choose
a new suite identifier, and move the complete dependent timeline together:

1. design-publication deadline;
2. future-corpus interval;
3. both crawl not-before times and snapshot-publication window;
4. NIST target pulse;
5. one-shot not-before and hard deadline;
6. evidence-publication deadline.
7. closeout-publication deadline.

The replacement must receive a new exact implementation commit/tree, review,
green CI, freeze manifest, signed tag, release receipt, and known-answer date
checks.  Moving one date in isolation, retroactively accepting late evidence,
or preserving a pulse/corpus that became observable before the replacement
design was public is forbidden.

## Post-attempt publication gate

Every terminal class, including reservation/marker-only interruption and execution
failure, is packaged. The evidence release must contain the durable reservation
and every later artifact that actually exists. A complete attempt therefore
contains the marker, terminal outcome, raw NIST request/headers/body and
certificate chain, corpus bytes and attribution, environment, token IDs and
losses, containers, worker and supervisor logs, SHA-256 inventory,
independent-verifier report, and an immutable evidence release.  The canonical
signed release receipt is collected only after publication and archived as a
separate post-release record, because a release cannot contain a receipt that
observes that same release without creating a self-reference. An interrupted
attempt instead preserves every partial/pending byte and reports the exact
absent artifacts; it never fabricates placeholders. A later regression is
published under a different identity and cannot replace the one-shot outcome.

`CITATION.cff`, ORCID, DOI/Zenodo metadata, SBOM, `LICENSES/`, and `NOTICE.md`
are archive requirements.  They do not waive any P0 scientific-evidence gate.
