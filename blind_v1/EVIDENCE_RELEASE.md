# Post-one-shot evidence release (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

This abandoned release design would have operated under
`AUTHOR_SELF_VERIFICATION`. The repository owner would have been the author,
experiment operator, and release operator. Packaging,
signed publication, the separate verifier, and a DOI do not constitute
independent human review, peer review, operator blindness, or independent
replication. They preserve and verify the exact author-operated attempt.

`package_evidence_release.py` would have created the sealed evidence directory.
`package_evidence_assets.py` would then have converted that already verified directory and
its external package-verifier report into the exact four assets attached to the
separate post-one-shot evidence release. Both tools use only the Python
standard library and perform no network access, model loading, tokenization,
codec execution, or metric calculation. Their verifiers establish package
integrity and cross-file bindings; `verify_evidence.py` remains the independent
scientific recomputation. A complete scientific report contains a strict,
self-digested `modelReplaySummary`: fresh frozen-weight inference,
retokenization, independent VTL5 decode bound to regenerated baseline caches,
and exact comparison of every token ID, binary32 loss bit pattern, and top-1 ID.

The release-level role `evidence-package-verifier-report` is the exact external
report produced by verifying the sealed evidence directory before outer-asset
construction. It is distinct from
`payload/attempt/independent-verifier-report.json`, the scientific
recomputation report produced after a complete terminal attempt. A local
attempt-reservation/marker-only `CONSUMED_INCOMPLETE` package legitimately lacks
the latter and must never be given a placeholder scientific report.

## Package boundary

The output contains exact regular bytes under these roots:

- `payload/attempt/`: the entire one-shot result root, including the durable
  local attempt reservation and marker, raw NIST request/response, selection,
  environment, jobs, all worker logs and summaries, top-level and per-worker
  page-token evidence, per-token losses/IDs, container evidence and container
  bytes, producer result, independent-verifier report/log, and terminal outcome
  when they exist;
- `payload/corpus/`: the entire public collector root, including both raw
  RecentChanges crawls, every archived revision response, canonical records,
  ledgers, attribution in the manifest/ledgers, and `corpus-manifest.json`;
- `payload/bindings/`: the frozen design, snapshot registration, freeze
  manifest, runtime manifest, model-asset source manifest, separate full-asset
  receipt, CycloneDX SBOM, canonical design, snapshot, and public
  execution-reservation publication receipts, the exact three public
  execution-reservation release assets, the preregistered SSH signing public
  key, every design/snapshot release asset, transport CA bundle, and complete
  offline NIST certificate-chain directory.

Every byte appears exactly once in the sorted `entries` array of
`evidence-release-manifest.json`, with its size, SHA-256, and semantic role.
The manifest also commits the entry array, per-group inventories, total size,
and its own content. No source or package symlink, device, socket, or other
special filesystem object is accepted. The requested final output is never
overwritten.

## Public attempt identity check

Before accepting either the sealed directory or the four outer release
assets, rederive the public `attemptId` from the embedded canonical execution
reservation: `20260821T180000Z-` plus the first 16 lowercase hexadecimal
characters of SHA-256 over that reservation before `attemptId` and
`reservationContentSHA256` are added. The embedded reservation, local attempt
reservation and marker, worker authorization/jobs, raw-token, page-token and
container records, producer result, independent replay/report, and
`evidence-release-manifest.json` must all carry that exact value. The package
verifier performs these cross-bindings independently; matching only the
generic `YYYYMMDDTHHMMSSZ-<hex>` shape is insufficient.

For a terminal `PASS` or `FAIL_GATES`, the packager additionally requires the
complete fixed evidence set, including top-level and all three per-worker
page-token files, and checks that those four page-token files are bound by the
producer evidence manifest. It checks the outcome hashes for the result,
producer evidence manifest, and independent-verifier report and requires the
three verdicts to agree. It also rejects a complete package unless the report's
real-model replay summary is self-consistent, complete, fixture-free, bound to
the regenerated baseline containers, and exact for token IDs, losses, and
top-1 IDs.

For `FAIL_EXECUTION` or an explicit `CONSUMED_INCOMPLETE`, the terminal outcome
is preserved but absent downstream files are not invented. If the process died
after publishing the local attempt reservation and before publishing a
canonical marker or terminal outcome, the package
is classified `PARTIAL_CONSUMED_INCOMPLETE`, has `terminalState: null`, cannot
claim a scientific verdict, and lists every absent canonical artifact in
`missingArtifacts`. That is a publication classification, not a replacement
terminal outcome. `recoveryClassification` is explicitly
`CONSUMED_INCOMPLETE`. Any surviving `.pending` file and any partial or
noncanonical final marker/outcome is copied byte-for-byte and listed in
`forensicArtifacts` with its byte count, SHA-256, path, and failure condition.
The packager validates frozen bindings against the canonical local attempt
reservation when no canonical marker exists; it never parses partial bytes as
evidence and never turns them into retry permission.

Only a valid, timely `PASS` package supports the registered positive
exact-sample claim. `FAIL_GATES` preserves a valid negative metric result.
`FAIL_EXECUTION`, `CONSUMED_INCOMPLETE`, and
`PARTIAL_CONSUMED_INCOMPLETE` preserve unsuccessful consumed attempts: they do
not establish a negative codec metric, cannot be omitted from publication, and
never authorize reconstruction or retry under the same suite identity.

## Build after the one-shot

Use the exact frozen runtime if it is still available, although this tool itself
has no third-party dependencies:

```sh
python3 -I -B blind_v1/package_evidence_release.py package \
  --attempt-root /absolute/path/to/one-shot-result \
  --corpus-root /absolute/path/to/public-corpus-root \
  --design /absolute/path/to/frozen-design.json \
  --snapshot-registration /absolute/path/to/snapshot-registration.json \
  --freeze-manifest /absolute/path/to/freeze-manifest.json \
  --runtime-manifest /absolute/path/to/runtime-manifest.json \
  --asset-source-manifest /absolute/path/to/model-assets-source.json \
  --asset-receipt /absolute/path/to/full-asset-receipt.json \
  --sbom /absolute/path/to/sbom.cdx.json \
  --design-publication-receipt /absolute/path/to/design-publication-receipt.json \
  --snapshot-publication-receipt /absolute/path/to/snapshot-publication-receipt.json \
  --reservation-publication-receipt /absolute/path/to/execution-reservation-publication-receipt.json \
  --reservation-release-assets /absolute/path/to/execution-reservation-assets \
  --signing-public-key /absolute/path/to/preregistered-signing-key.pub \
  --design-release-assets /absolute/path/to/design-release-assets \
  --snapshot-release-assets /absolute/path/to/snapshot-release-assets \
  --nist-trust-root /absolute/path/to/frozen-nist-trust \
  --transport-ca-bundle /absolute/path/to/transport-ca.pem \
  --output-directory /absolute/path/to/evidence-release
```

`--created-at YYYY-MM-DDTHH:MM:SSZ` is available when the packaging timestamp
must be supplied by an external durable clock record. Without it, the tool
records the current UTC whole second. Publication never uses a replacing
directory rename. It atomically creates the requested final root exclusively,
links already verified staged regular files into it without overwrite, and
links `evidence-release-manifest.json` last. A concurrent empty directory or
file at the requested name is therefore left untouched. Until the materialized
final directory passes verification, an error preserves the complete visibly
named `.partial-*` directory for forensics. If an error occurs after exclusive
final-root creation, that incomplete final root is also preserved; without the
last-linked top manifest it cannot verify as a release. Once the final root has
verified, the private stage is removed before the final read-only seal and
verification pass.

The packager verifies the complete stage, verifies the exclusively materialized
final directory, removes the successful private hard-link stage, seals the
final directories read-only, and verifies the final name once more. Read-only
permissions are an accident guard, not a cryptographic trust mechanism.

Create the external package-verifier report outside that sealed directory, then
create and verify the release assets:

```sh
python3 -I -B blind_v1/package_evidence_release.py verify \
  --release-root /absolute/path/to/evidence-release \
  --report /absolute/path/to/evidence-package-verifier-report.json

python3 -I -B blind_v1/package_evidence_assets.py package \
  --evidence-root /absolute/path/to/evidence-release \
  --verifier-report /absolute/path/to/evidence-package-verifier-report.json \
  --output-directory /absolute/path/to/evidence-release-assets

python3 -I -B blind_v1/package_evidence_assets.py verify \
  --asset-root /absolute/path/to/evidence-release-assets
```

The output directory contains exactly these filename/role pairs:

- `evidence-package.tar` — `evidence-package`;
- `evidence-release-manifest.json` — `evidence-release-manifest`;
- `evidence-package-verifier-report.json` —
  `evidence-package-verifier-report`;
- `sha256-manifest.json` — `sha256-manifest`.

`evidence-package.tar` is not an implementation-defined `tar` or `zip` output.
It is a deterministic, uncompressed POSIX USTAR stream with sorted regular-file
members, fixed mode `0444`, zero UID/GID/mtime, empty owner names, no links, and
canonical zero padding. The SHA-256 manifest binds the exact archive, top
manifest, and external report; the report independently binds the top manifest.

## Independent offline verification

Copy the four release assets to another clean host and run the outer verifier
shown above. To materialize the sealed directory without invoking a generic
archive extractor, use:

```sh
python3 -I -B blind_v1/package_evidence_assets.py extract \
  --asset-root /absolute/path/to/evidence-release-assets \
  --output-directory /absolute/path/to/extracted-evidence-release
```

The extractor first verifies all four assets, then reads the archive as a
bounded sequential stream and creates only the manifest-declared regular files
with no-follow, exclusive writes. It rejects missing, extra, reordered,
changed, linked, noncanonical, oversized, or trailing archive data. Run the
full scientific verifier against the extracted attempt and frozen inputs as
specified in `PROTOCOL.md`.

The public asset-source manifest deliberately has
`weightsRedistributed: false`; the evidence package does not grant or imply a
right to redistribute upstream model weights. A later full scientific replay
therefore requires independently reacquiring every registered file from its
immutable source revision and obtaining exact byte/size/SHA-256 matches before
execution. If any exact weight/tokenizer byte is unavailable, or if a different
CPU/runtime changes a floating-point bit, the archival replay is unavailable or
failed—not silently relaxed. Package-only verification still proves archive
integrity, but it does not rerun inference.

## Signed release and archive steps

GitHub upload, signature creation, release-receipt collection, and DOI minting
are deliberately external to this offline tool. They must be ordered without a
self-reference:

1. Reserve the Zenodo DOI before the immutable evidence release. A reserved DOI
   is not evidence that the deposit is public. Because every publication tag
   is bound to the already frozen `labSource.commit`/`labSource.tree`, do not
   create or mutate an evidence-publication commit to add the reservation.
   Bind the reservation in the Zenodo deposit metadata and a release-specific
   citation artifact outside the frozen Git tree.
2. Run `package_evidence_assets.py package` exactly as above. Do not substitute
   a system `tar`, Finder archive, ZIP utility, or recompressed container: their
   metadata and bytes are not canonical evidence assets.
3. Create the dedicated evidence tag/release targeting the exact frozen
   `labSource.commit`/`labSource.tree`, sign the annotated tag with the
   preregistered identity, attach exactly the four files
   listed above under their corresponding release-receipt roles, and publish it
   strictly before `2026-08-26T18:00:00Z`. Do not replace a failed/partial
   package with a reconstructed success package.
4. Only after publication, collect the canonical server-timestamped evidence
   release receipt with the exact pinned `--github-cli` and `--cosign` inputs
   documented in [`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md). The pinned Cosign
   check and later independent replay cryptographically verify the archived
   DSSE/X.509/RFC3161 bundle against the tracked GitHub root and cross-bind the
   signed `attestedAt`; the registered no-Rekor/no-SCT transparency boundary
   still applies. The receipt cannot be an asset of the same already immutable
   release it describes. Publish it through a separate append-only
   witness/archive record and include it in the reserved Zenodo deposit.
5. Publish the Zenodo deposit under the already reserved DOI with the exact
   release assets, external receipt, and checksums. Retain Zenodo's deposit and
   file metadata as a separate archival receipt.
6. Publish the frozen `CITATION.cff`, ORCID, `LICENSES/`, `NOTICE`, SBOM,
   signed-tag verification, release receipt, DOI metadata, and any
   release-specific citation artifact alongside the evidence. Never mutate the
   frozen Git tree or original evidence release to retrofit its own receipt or
   DOI.

A signed release or DOI authenticates publication provenance, but neither can
substitute for the marker, raw NIST/corpus bytes, per-token/container evidence,
terminal outcome, canonical manifest, and independent scientific report.
