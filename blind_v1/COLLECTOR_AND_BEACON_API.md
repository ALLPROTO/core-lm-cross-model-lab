# Collector and NIST verifier API (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

This blind-v1 contract is author-self-verified. It claims no independent human
review, peer review, operator blindness, or independent replication. The
separate replay/verifier paths below are technical separation within the same
author-controlled project.

This document preserves the abandoned supervisor contract for the blind-v1
corpus collector and NIST Beacon verifier. These components were designed to
collect and verify bytes; they do not
load model weights, run the codec, compute logits, or create a scientific
verdict.

Primary specifications:

- [MediaWiki RecentChanges API](https://www.mediawiki.org/wiki/API%3ARecentChanges)
- [MediaWiki continuation protocol](https://www.mediawiki.org/wiki/API%3AContinue)
- [MediaWiki Revisions API](https://www.mediawiki.org/wiki/API%3ARevisions)
- [NIST Randomness Beacon 2.0](https://csrc.nist.gov/projects/interoperable-randomness-beacons/beacon-20)
- [Tracked exact NIST Beacon 2.0 schema](trust/nist/spec/beacon-2.0.xsd)
- [Official NIST Beacon 2.0 schema source](https://csrc.nist.gov/csrc/media/Projects/interoperable-randomness-beacons/documents/certificate/beacon-2.0.xsd)
- [NISTIR 8213 draft](https://doi.org/10.6028/NIST.IR.8213-draft)

## MediaWiki phases

The supervisor must construct `PinnedHTTPSClient` with the already verified CA
bundle bytes, its lowercase SHA-256, and only the three registered project
hosts. The client loads trust anchors from those verified owned bytes and does
not add ambient system roots or consult proxy settings.

The historical counterfactual phase order was:

1. On or after `2026-08-18T06:00:00Z`, call
   `collect_crawl_stage(root=..., crawl_index=0, transport=..., clock=...)` with
   a new or empty root.
2. On or after `2026-08-19T06:00:00Z`, call the same function with
   `crawl_index=1`. It first replays and verifies stage 1.
3. Call `finalize_snapshot(root=..., transport=..., tokenizers=...)` with all
   six verified frozen-pool tokenizers in exact `MODEL_KEYS` order. This binds
   the future corpus to every eligible model before NIST selects three.
4. Call `verify_corpus_snapshot(root, tokenizers=tokenizers)` and require
   `status == "VERIFIED_SNAPSHOT_BYTES"`, `readyForFreeze is True`, and
   `tokenCommitmentsRecomputed is True`.

`collect_snapshot(...)` is only a convenience wrapper for a run after the
second not-before time. It deliberately does not replace the two-day production
sequence.

Every HTTP page is committed as exact `request-uri.txt`, raw response-header
bytes, and raw response-body bytes. Completion files and their parent directory
entries are fsynced before a phase returns. A failed partial crawl stage has no
completion manifest and must not be treated as complete or resumed in place.

For revision finalization, the RecentChanges creation title is the frozen input
title. The title returned by the Revisions API is strictly validated and stored
only as `revisionAPICurrentTitle` inventory provenance; page moves do not alter
record or tokenizer-input bytes. Attribution history links use `curid=<pageid>`.
Each complete revision response bundle is atomically published and replayed
without transport on restart. Exact committed records, ledgers, and corpus
manifest bytes are likewise reused. A complete `.partial` response bundle is
validated and promoted without transport. An incomplete `.partial` bundle
fails before transport and requires discarding the prospective corpus under the
registered reschedule rule; it is never silently deleted and refetched. A
completed corpus manifest triggers full zero-network replay and exact-tree
validation, including both crawl-stage manifests and archives.

The verifier rebuilds every request URI, follows the archived continuation
chain to exhaustion, recomputes the two-crawl union, reparses every revision,
recomputes content and record bytes, and compares canonical ledgers. Legitimate
`userhidden`, `sha1hidden`, and exact `badrevids` responses are archived as
explicit source-ineligible inventory entries. They never enter a ledger and do
not cause visible eligible records to be silently dropped.

After `verify_corpus_snapshot`, a supervisor selects a frozen record only with:

```python
record_bytes = load_record_bytes(manifest, project, revid, snapshot_root)
```

That lookup verifies the safe relative path, byte count, SHA-256, serialized
record identity, and title/content/input digests. It must not be replaced with
an independently constructed filesystem path.

## Historical deterministic snapshot registration (do not execute)

Only after the tokenizer-recomputed verification in MediaWiki phase 4 reports
`readyForFreeze=true`, build the pre-publication registration from existing
bytes. Do not hand-author its projects, models, ledger hashes, release plan, or
input digests:

```sh
"$RUNTIME_ROOT/bin/python" -I -B blind_v1/build_snapshot_registration.py \
  --frozen-design /absolute/path/frozen-design.json \
  --corpus-root /absolute/path/corpus \
  --asset-root /absolute/path/verified-model-assets \
  --design-release-asset-root /absolute/path/exact-design-release-assets \
  --signing-public-key /absolute/path/release-signing-key.pub \
  --design-publication-receipt /absolute/path/design-publication-receipt.json \
  --asset-source-manifest /absolute/path/model-assets.draft.json \
  --full-asset-receipt /absolute/path/confirmatory-full-asset-receipt.json \
  --created-at 2026-08-19T06:30:00Z \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output /absolute/new/path/snapshot-registration.json
```

`createdAt` is an explicit operator observation with whole UTC seconds. It must
be at or after the registered second-crawl not-before time and strictly before
the snapshot publication deadline. The destination must not exist and must be
outside the exact frozen lab checkout.

The builder validates canonical frozen-design, design-publication-receipt, and
full-asset-receipt bytes; checks that the design receipt binds the exact design,
tracked asset-source manifest, and full rehash receipt; runs the complete
offline design-publication verifier over all twelve exact release assets, archived
GitHub API responses, raw commit/tag objects, and the SSH signature using the
frozen public key; requires its exact implementation commit/tree; reopens the complete
registered asset inventory without following symlinks; retains the six exact
`tokenizer.json` byte streams; constructs tokenizers only from those owned
bytes; invokes `verify_corpus_snapshot(..., tokenizers=...)`; and requires
`tokenCommitmentsRecomputed=true`. It then rereads the manifest and every
ledger after replay, derives all normative fields from those inputs, invokes
`validate_snapshot_registration(..., allow_fixture=False)`; and writes only
canonical JSON plus one LF. This replay still does not replace phase 4's prior
verification: it independently repeats the tokenizer commitments at publication
time. The command loads no model weights, performs no inference, network access,
or selection, and creates no attempt state. It must run in the locked runtime
that supplies the pinned `tokenizers` package. Every input and corpus-ledger
path is opened one filesystem component at a time with no-follow semantics;
placing a symlink anywhere in an input parent chain is a hard failure.

## Offline NIST trust bundle

The normative bundle is canonical JSON with no terminal LF with this shape:

```json
{
  "schemaVersion": "corelm-blind-crossmodel-v1-nist-trust-bundle-v2",
  "status": "CANDIDATE_OFFLINE_TRUST_BUNDLE",
  "fixtureOnly": false,
  "trustPolicy": {
    "allowedCertificateIds": ["<lowercase SHA-512 of leaf DER>"],
    "rotationPolicy": "NO_ROTATION_AFTER_FREEZE",
    "revocationPolicy": "EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK",
    "revocationChecked": false,
    "revocationResidualRisk": "A pinned certificate that is revoked or compromised before the target pulse can still be accepted; no contemporaneous OCSP or CRL status is checked or claimed.",
    "acceptedLeafExtendedKeyUsages": [
      "1.3.6.1.5.5.7.3.1",
      "1.3.6.1.5.5.7.3.2"
    ]
  },
  "certificates": {
    "<lowercase SHA-512 of leaf DER>": {
      "chainPolicy": "offline-x509-rsa-pkcs1",
      "pem": {
        "relativePath": "certificates/leaf.pem",
        "bytes": 0,
        "sha256": "<lowercase hex>"
      },
      "chain": [
        {
          "relativePath": "certificates/leaf.der",
          "bytes": 0,
          "sha256": "<lowercase hex>",
          "sha512": "<lowercase hex>"
        },
        {
          "relativePath": "certificates/root.der",
          "bytes": 0,
          "sha256": "<lowercase hex>",
          "sha512": "<lowercase hex>"
        }
      ]
    }
  }
}
```

The tracked pre-freeze object uses `CANDIDATE_OFFLINE_TRUST_BUNDLE` and is
rejected by scientific/freeze callers. `allow_candidate=True` is a local
validation-only loader option. A final object may use
`FROZEN_OFFLINE_TRUST_BUNDLE` only after the policy, manifest bytes, and all
dependent design commitments have been reviewed and rebound. The canonical
shape is `schemas/nist-trust-bundle.schema.json`.

For this suite the identities are already deterministic: the tracked candidate
is 1,933 bytes with SHA-256
`cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`;
changing only `status` produces a 1,930-byte frozen manifest with SHA-256
`5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`.
Create a new self-contained external bundle with:

```sh
"$RUNTIME_ROOT/bin/python" -I -B \
  blind_v1/build_frozen_nist_trust_bundle.py \
  --output-root /absolute/new/path/frozen-nist-trust
```

The tool accepts only the exact tracked candidate, copies every referenced
PEM/DER byte, changes only the status, and verifies candidate and frozen forms
with both the producer and independent implementations. It performs no network
request, pulse fetch, or inference and never overwrites an output. Freeze and
scientific callers accept only the external frozen manifest. They additionally
restore the candidate status and require byte equality with the tracked
candidate, so another policy-compatible bundle cannot substitute for it.

`allowedCertificateIds` contains exactly one lowercase ID and must exactly
equal the sole key in `certificates`. `NO_ROTATION_AFTER_FREEZE` means any
different certificate ID fails closed after freeze. The accepted EKU tuple is
exactly `serverAuth`, then `clientAuth`, in DER order; both implementations
also require an end-entity leaf with `digitalSignature=true` and
`keyCertSign=false`. This EKU is accepted only in combination with the exact
certificate/hostname/root pins and is not described as a beacon-specific EKU.

The `chain` order is leaf, zero or more intermediates, then the pinned
self-signed root. A normative chain therefore contains at least two distinct
certificates. Replace the illustrative zero byte counts and placeholder hashes
with exact frozen values. The supervisor must pass the independently
preregistered manifest digest as `expected_manifest_sha256` and the design's
independently preregistered DER root hashes as `expected_root_der_sha256`; a
digest or trust anchor derived from the same bundle is not an independent pin.

For the one-shot response:

1. Fetch only `TARGET_ENDPOINT` and archive it with `archive_response`.
2. Call `load_offline_trust_bundle(...)` with
   `expected_time=<target UTC datetime>`,
   `expected_manifest_sha256=<registered digest>`, and
   `expected_root_der_sha256=<registered root hashes>`.
3. Call `verify_archived_nist_pulse(...)` with `root=...`, `archive=...`, and
   `trust_bundle=...`.
4. Persist only `canonical_verification_bytes(result)` and require
   `status == "VERIFIED_FROZEN_NIST_PULSE"` and
   `countsTowardScientificVerdict is True` before selection.

The HTTPS `Date` used by the supervisor's attempt-start gate is an observation
authenticated by the live hostname-verified pinned-TLS connection. It is not
covered by the NIST pulse signature, and replaying its archived bytes does not
turn it into an independent public time attestation.

The verifier requires the exact time endpoint and exact millisecond timestamp,
checks X.509 v3 framing, validity, Basic Constraints, Key Usage,
path-length constraints, unknown critical extensions, the exact
`engine.beacon.nist.gov` leaf SAN, and the pinned RSA signature chain offline,
reconstructs the Beacon 2.0 signed bytes, verifies the pulse RSA/SHA-512
signature, and recomputes `outputValue`. `nearest`, `previous`, `next`, `last`,
online certificate trust, and fallback behavior are not accepted.

Revocation is deliberately not queried during the offline one-shot. The
machine-verifiable policy is
`EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK`, and every accepted manifest must
state `revocationChecked=false` plus the exact residual-risk disclosure shown
above. Exact leaf/intermediate/root byte pins, validity-at-pulse, extension
constraints, and cryptographic chain/signature verification do not establish
non-revocation. A stronger revocation claim would require a separately
preregistered, timestamped OCSP/CRL evidence collector and verifier before
freeze; it cannot be added after seeing the pulse.

Production additionally requires the preregistered exact profile
`version="2.0"`, `cipherSuite=0`, `period=60000`, and top-level
`statusCode=0`. Status values 1, 2, and 3 are signed parts of the wire format
but are not normal pulses for this suite and fail closed before selection. The
tracked exact XSD version 2.0.0 controls serialization where its annotations
conflict with draft NISTIR prose. The historical official
known-answer fixture contains `version="Version 2.0"` and signed
start-of-chain `statusCode=1`; only the explicit fixture-only verification path
accepts that exact historical profile.

`blind_v1/test-vectors/nist-chain1-pulse1.json` and its certificate are a historical
official known-answer fixture only. Loading or verifying it requires the
explicit `allow_fixture=True`; its result always has
`countsTowardScientificVerdict == false`. Production code must never set that
flag.

## Remaining time-dependent blockers

- The corpus interval has not yet closed, so the two production crawl stages
  and final corpus manifest do not exist yet.
- The target `2026-08-21T18:00:00.000Z` pulse does not exist yet.
- The complete future-compatible NIST signing chain/root bundle is tracked at
  `trust/nist/manifest.json` and bound by the draft design. If the target pulse
  uses an unregistered certificate, the experiment must fail closed rather
  than fetch and trust it.
- Snapshot commit/tree, release time, and server-side publication evidence are
  separate freeze controls and must bind the verified manifest SHA-256 before
  any selected record is consumed.

Run the local contract tests with:

```sh
python3 -m unittest blind_v1.tests.test_mediawiki_snapshot blind_v1.tests.test_nist_beacon -v
```
