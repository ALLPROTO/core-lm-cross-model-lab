# Third-party license index

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

The root `LICENSE` applies only to repository-authored code unless a file says
otherwise. Downloaded assets remain outside Git and retain their upstream
terms. This directory records license identities and immutable source links;
it does not copy or relicense model weights.

- [`ASSET_LICENSES.md`](ASSET_LICENSES.md) — registered development models,
  the retired V1 proposal, codec source, and archived evidence classes.
- [`source-evidence.json`](source-evidence.json) — byte counts and SHA-256
  commitments for the UD English PUD README and license, model cards, the full
  BigCode agreement source, and codec license bytes fetched from exact immutable
  revisions; tracked copies are under `upstream/`.
  `archivedEncoding: base64` is used only when exact upstream text has no
  terminal LF, and is decoded before hashing.
- [`blind-v1-model-card-evidence.json`](blind-v1-model-card-evidence.json) —
  the archived Blind V1 proposal's record of all six exact-revision Hugging
  Face model cards. Its six archived README blobs are under
  `upstream/blind-v1-*`. None of those six revision trees contains a standalone
  `LICENSE*` or `NOTICE*` file, so the archive preserves the exact card
  declarations without inventing an upstream license file. This separate
  identity deliberately leaves the historical seven-entry
  `source-evidence.json` contract unchanged.
- [`UD_ENGLISH_PUD_ATTRIBUTION.md`](UD_ENGLISH_PUD_ATTRIBUTION.md) — the
  development corpus source identity, contributor credit, transformations, and
  CC BY-SA 3.0 attribution/share-alike handling.
- [`../v2/test-vectors/github-release-attestation-v1/metadata.json`](../v2/test-vectors/github-release-attestation-v1/metadata.json)
  — provenance and rights classification for the minimal real `cli/cli`
  immutable-release known-answer vector; its exact upstream MIT license is
  preserved beside the vector.
- [`../v3/test-vectors/github-release-attestation-v1/metadata.json`](../v3/test-vectors/github-release-attestation-v1/metadata.json)
  — the identical known-answer bytes retained by the historical v3 contour.
- [`../v4/test-vectors/github-release-attestation-v1/metadata.json`](../v4/test-vectors/github-release-attestation-v1/metadata.json)
  — the identical known-answer bytes retained by the historical v4 contour.
- [`../blind_v1/test-vectors/github-release-attestation-v1/metadata.json`](../blind_v1/test-vectors/github-release-attestation-v1/metadata.json)
  — the identical known-answer bytes retained from the retired Blind V1
  development-control design.

The counterfactual Blind V1 freeze would have required the author to replay
every entry in `source-evidence.json` and the Blind V1 model-card evidence.
That freeze did not occur and the requirement is no longer actionable for V1.
The local development artifact set binds the historical file,
`ASSET_LICENSES.md`, the pinned UD English PUD README and license, and
`UD_ENGLISH_PUD_ATTRIBUTION.md` under `inputs/LICENSES/`; the counterfactual V1
archival deposit would also have bound the complete `LICENSES` bundle,
including the six Blind V1 cards, and runtime SBOM.
Corpus excerpts, partitions, raw-token records, and other reversible or
source-derived evidence must preserve attribution, identify CC BY-SA 3.0 and
its URI, mark changes, retain share-alike compatibility, and add no effective
technical restrictions. The pinned upstream declarations are consistent, but
that statement records evidence rather than making a legal or ownership
conclusion. A license identifier is provenance metadata, not a grant beyond the
cited upstream terms.

These retained rights records authorize no V1 model download, corpus
collection, NIST access, freeze, release, or scientific execution. A successor
must adopt them, if applicable, under a new suite ID and fully rescheduled
timeline.
