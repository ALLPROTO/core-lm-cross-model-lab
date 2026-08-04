# Third-party license index

The root `LICENSE` applies only to repository-authored code unless a file says
otherwise. Downloaded assets remain outside Git and retain their upstream
terms. This directory records license identities and immutable source links;
it does not copy or relicense model weights.

- [`ASSET_LICENSES.md`](ASSET_LICENSES.md) — registered models, future data,
  codec source, and generated evidence.
- [`source-evidence.json`](source-evidence.json) — byte counts and SHA-256
  commitments for the UD English PUD README and license, model cards, the full
  BigCode agreement source, and codec license bytes fetched from exact immutable
  revisions; tracked copies are under `upstream/`.
  `archivedEncoding: base64` is used only when exact upstream text has no
  terminal LF, and is decoded before hashing.
- [`UD_ENGLISH_PUD_ATTRIBUTION.md`](UD_ENGLISH_PUD_ATTRIBUTION.md) — the
  development corpus source identity, contributor credit, transformations, and
  CC BY-SA 3.0 attribution/share-alike handling.
- [`../v2/test-vectors/github-release-attestation-v1/metadata.json`](../v2/test-vectors/github-release-attestation-v1/metadata.json)
  — provenance and rights classification for the minimal real `cli/cli`
  immutable-release known-answer vector; its exact upstream MIT license is
  preserved beside the vector.

Before the immutable design release, independently replay every entry in
`source-evidence.json`. The local development artifact set binds that file,
`ASSET_LICENSES.md`, the pinned UD English PUD README and license, and
`UD_ENGLISH_PUD_ATTRIBUTION.md` under `inputs/LICENSES/`; the eventual archival
deposit separately binds the complete `LICENSES` bundle and runtime SBOM.
Corpus excerpts, partitions, raw-token records, and other reversible or
source-derived evidence must preserve attribution, identify CC BY-SA 3.0 and
its URI, mark changes, retain share-alike compatibility, and add no effective
technical restrictions. The pinned upstream declarations are consistent, but
that statement records evidence rather than making a legal or ownership
conclusion. A license identifier is provenance metadata, not a grant beyond the
cited upstream terms.
