# Archival publication (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

The GitHub release and the archival deposit have different evidentiary roles.
GitHub provides signed Git objects, release identifiers, and release assets.
The exact-commit CI-only collector separately preserves four responses obtained over direct,
hostname-checked TLS. Those response bodies and headers are not GitHub-signed,
so their offline replay proves structural consistency only, not GitHub origin
or authoritative server time. Zenodo provides a persistent DOI and an
independent archival copy. Neither can repair missing one-shot evidence or a
late preregistration.

This is an author-self-verified deposit. The repository owner is the author,
experiment operator, and release operator. Neither GitHub, Zenodo, the DOI, the
separate verifier process, nor the archival copy constitutes independent human
review, peer review, operator blindness, or independent experimental
replication. The GitHub collector makes no reviews-endpoint request and stores
no reviewer, approval, or review declaration.

The repository contains a software-only `CITATION.cff`, Ivan Tyshchenko's ORCID
`0009-0000-7935-6090`, a CycloneDX SBOM generator, `LICENSES/`, and `NOTICE.md`.
It intentionally contains no `.zenodo.json`: the legacy GitHub integration has
one global license field and must not assign a default license to this mixed-
rights evidence deposit. No DOI is written into tracked metadata until Zenodo
has actually reserved it; invented or anticipated identifiers are forbidden.

The `LICENSES` archive must include the separate canonical
`blind-v1-model-card-evidence.json` plus its six declared
`upstream/blind-v1-*` card blobs. The Blind V1 verifier decodes and rehashes
those bytes, checks each exact README license declaration, and cross-binds the
ordered repository/revision/license identities to the frozen design. The
historical seven-entry `source-evidence.json` remains unchanged.

Under the retired counterfactual protocol, a design archive would have required
the 2,088-artifact UD English PUD development control to be packaged into its
three canonical assets, published from the signed annotated development tag,
and bound by the canonical GitHub immutable-release attestation receipt. That
historical development-release requirement was non-scientific and would not
have replaced the later design, snapshot, public execution-reservation, or
one-shot evidence releases.

The V4 pilot-model E2E and all earlier V2/V3 controls are preserved only as
prior non-scientific observations from superseded or failed-freeze contours.
None can be relabeled or reused as the mandatory exact-commit blind-v1
development control.

The pre-pulse public execution reservation is its own signed immutable GitHub
release. Its three exact assets and canonical receipt must be archived with the
later evidence or closeout deposit. It binds the frozen design, snapshot,
six-model pool, target pulse, execution window, and publication obligation, but
it performs no inference and is not a scientific result. A design, snapshot,
DOI reservation, local timestamp, or later evidence release cannot substitute
for its verified RFC3161 publication window.

## Historical counterfactual release procedure (do not execute)

The numbered procedure below records the abandoned V1 design. Its imperative
wording is quoted as specification history only and grants no authorization to
create, publish, collect, or upload any Blind V1 artifact.

1. Use one manual Zenodo draft created through the authenticated current Zenodo
   deposit interface or API. Do not enable the legacy GitHub-to-Zenodo release
   integration for this suite; a second automatic deposit would create an
   ambiguous record or DOI.
2. Create the GitHub release assets and their canonical SHA-256 manifest, but
   do not publish an incomplete scientific release.
3. In that one manual Zenodo draft, reserve the DOI and archive the reservation
   response bytes. Configure explicit multiple licenses/custom rights for the
   mixed upload: repository code is MIT, Wikipedia revision bytes remain CC
   BY-SA 4.0, the UD English PUD r2.18 development corpus and its reversible or
   source-derived evidence retain CC BY-SA 3.0 with attribution, change notice,
   and share-alike handling, models retain their upstream terms, and other
   archived response or certificate bytes retain the rights stated in
   `LICENSES/` and `NOTICE.md`. These labels preserve upstream declarations and
   are not an independent ownership conclusion.
4. Add only that real reserved DOI, record identity, release version, and
   terminal outcome to release-specific citation/deposit metadata. Rebuild the
   publication bundle and recompute every affected hash before publication.
5. Publish the immutable signed GitHub release and collect its canonical
   attested release receipt. The pinned GitHub CLI obtains and verifies the
   immutable-release bundle online; pinned Cosign 3.0.6 then verifies the
   archived DSSE/X.509/RFC3161 evidence offline against the tracked GitHub root,
   and the independent verifier repeats that operation. `attestedAt` is derived
   from the raw signed RFC3161 timestamp and cross-bound to semantic replay; it,
   not an API timestamp, is the release deadline boundary. GitHub's bundle has
   no Rekor entry or certificate SCT, so the fixed private-infrastructure and
   ignore-SCT flags explicitly exclude transparency-log/SCT claims without
   disabling DSSE, X.509-chain, asset-digest, or RFC3161 verification. See
   [`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md) for the exact command and pinned
   binary/root hashes.
6. Build a canonical Zenodo-deposit manifest. The deposit is an intentional
   manifested superset of the GitHub release assets: it contains every exact
   GitHub release asset plus the external GitHub release receipt,
   release-specific citation/rights metadata, `LICENSES/`, `NOTICE.md`, SBOM,
   signed-tag verification, the complete Linux and macOS-arm64 CI artifact
   payloads (runtime manifests, zero-skip logs, preflight, and design checks),
   and the required hash-bound `lab-source.tar` and `codec-source.tar`
   archives. The GitHub gate receipt structurally binds artifact metadata within
   its archived observation, but neither authenticates its origin offline nor
   replaces those two payloads. Every entry records its path, role, byte count,
   and SHA-256; no unmanifested file is uploaded.
7. Upload that manifested superset to the reserved manual draft, verify every
   uploaded file against the deposit manifest, and only then publish Zenodo.
   Archive the Zenodo record response, DOI, record ID, complete file metadata,
   byte counts, hashes, rights, and observed HTTP `Date` values as a separate
   receipt. Those captured values are not signed by Zenodo and are not
   authoritative offline server-time proof.

The design DOI, snapshot DOI, and evidence DOI may be separate version DOIs.
The evidence DOI must identify the actual terminal outcome, including a failure
or local reservation/marker-only interruption. A no-local-attempt closeout after
a valid public execution reservation must identify
`NO_ATTEMPT_EXPIRED`. A later regression receives another release identity and
must not overwrite the one-shot record.

Zenodo reservation and publication require the author's authenticated account;
repository automation must never store a Zenodo token in source, logs, CI
artifacts, or scientific evidence.

## Canonical manifest and receipt

`schemas/zenodo-deposit-manifest.schema.json` and
`schemas/zenodo-deposit-receipt.schema.json` define the archival contract. The
manifest builder consumes a strict plan assigning a role, media type, and one
or more declared rights IDs to every file. The plan also binds the real
reserved production deposition ID, record ID and version DOI. Every file entry
carries `githubAssetRole` and `githubActionsArtifactName`; each is `null`
unless that exact binding applies. It rejects missing, changed, hard-linked,
symlinked, or unmanifested files and proves that all exact assets named by the
GitHub release receipt are present. The manifest is written outside the
payload root and is uploaded alongside that exact root as
`zenodo-deposit-manifest.json`:

```bash
python3 -m blind_v1.create_zenodo_deposit_manifest \
  --deposit-root <EXACT_PAYLOAD_ROOT> \
  --plan <EXACT_PLAN_JSON> \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output <OUTSIDE_PAYLOAD_ROOT>/zenodo-deposit-manifest.json
```

Before emitting the manifest, the builder invokes the complete canonical
GitHub release-receipt verifier against the deposited `github-assets/`
directory. It replays the signed Git object with the tracked SSH trust inputs
and reruns the archived immutable-release bundle with the supplied byte-pinned
Cosign executable. The structural attestation projection alone is not enough.

Role labels are not accepted as evidence by themselves. During both manifest
construction and offline receipt verification the implementation checks:

- exactly one artifact for every mandatory archival role;
- the frozen design's lab/codec commit and tree, runtime self-digest, external
  SBOM, and corresponding exact GitHub release assets;
- the repository's canonical uncompressed POSIX-ustar source archives: one
  self-digested `source-manifest.json` followed by the exact `source/*` files.
  `verify_source_archive` re-hashes the commit object, blobs and complete Git
  tree, regenerates the ustar byte stream, and rejects links, extensions,
  alternate headers, extra members or non-canonical ordering;
- the exact Linux and macOS-arm64 Actions ZIPs named and SHA-256-bound by the
  GitHub gate receipt. Each contains exactly its runtime manifest, development
  preflight, design check, real release-attestation cryptographic known-answer
  result, and terminal zero-skip log; Python 3.12.10, source identities,
  platform, no-network/no-inference flags, and `0 skipped` are checked from the
  enclosed bytes;
- a CycloneDX 1.5 SBOM binding both Git sources; deterministic JSON/YAML-1.2
  `CITATION.cff` metadata containing the real DOI, tag, release date, Ivan
  Tyshchenko, and ORCID; a self-digested exact file-to-rights map; NOTICE text
  naming the DOI/repository/rights; a safe LICENSES tar whose source-evidence
  hashes are recomputed; and a self-digested signed-tag projection bound to the
  release receipt and its archived verification transcript.

The rights map lists `zenodo-deposit-manifest.json` and its rights but does not
put the manifest digest inside a payload file, which would create a hash cycle.
The manifest itself binds the rights-map bytes.

Publication remains an explicit manual account action. After publication, the
collector performs exactly three authenticated production `GET` requests
(deposition, deposition files, and public record). It has no publish/upload/
edit/delete request path, never archives the Authorization header, and aborts
if the bearer token is echoed into any response:

```bash
ZENODO_ACCESS_TOKEN='<READ-CAPABLE_TOKEN>' \
python3 -m blind_v1.collect_zenodo_receipt \
  --manifest <zenodo-deposit-manifest.json> \
  --deposit-root <EXACT_PAYLOAD_ROOT> \
  --deposition-id <REAL_DEPOSITION_ID> \
  --record-id <REAL_RECORD_ID> \
  --doi 10.5281/zenodo.<REAL_RECORD_ID> \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output <NEW_RECEIPT_PATH>
```

Every receipt carries the exact boundary
`DIRECT_TLS_VERIFIED_AT_COLLECTION;NO_ZENODO_RESPONSE_SIGNATURE;OFFLINE_STRUCTURAL_CONSISTENCY_ONLY`.
The independent verifier is network-free. It reruns the full SSH+Cosign GitHub
release verification and then requires structural agreement among a production
version DOI, the archived published/done fields, exact record and deposition
identities, every declared rights entry, and the exact file set. It does not
claim that the archived API bytes authenticate their Zenodo origin or server
time. Zenodo exposes byte counts and MD5 in file metadata; the verifier checks
those in both archived API views and checks local bytes against the canonical
SHA-256 manifest. It does not mislabel Zenodo's MD5 as a server-provided
SHA-256:

```bash
python3 -m blind_v1.verify_zenodo_receipt \
  --receipt <ZENODO_RECEIPT_JSON> \
  --manifest <zenodo-deposit-manifest.json> \
  --deposit-root <EXACT_PAYLOAD_ROOT> \
  --deposition-id <REAL_DEPOSITION_ID> \
  --record-id <REAL_RECORD_ID> \
  --doi 10.5281/zenodo.<REAL_RECORD_ID> \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6
```

A real DOI and self-verified receipt still remain publication gates; the code
does not claim that an uncreated draft or a locally invented identifier exists.
