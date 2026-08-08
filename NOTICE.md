# Notices for code, models, and data

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

Copyright 2026 Ivan Tyshchenko.

Repository-authored source code is provided under the root MIT `LICENSE`.
That license does not replace licenses attached to downloaded model,
tokenizer, dataset, Wikipedia, or third-party dependency assets.

The Git checkout does not contain model weights or the real
UD English PUD r2.18 corpus. The retired Blind V1 design specified three
excluded development-control models and six confirmatory-pool revisions at
exact immutable upstream revisions, with any downloaded bytes kept in an
ignored local directory. That specification no longer authorizes downloads or
use under the V1 suite identity. Model weights are not redistributed by this
project. The separately published development-control evidence release does
include the exact UD English PUD source and source-derived evidence under CC
BY-SA 3.0, together with the preserved upstream license, README, attribution,
and description of changes. Each user remains responsible for reviewing the
applicable upstream terms before downloading or using an asset. BigCode OpenRAIL-M
is not the MIT license and includes use-based terms.

The pinned UD English PUD repository metadata, included Google notice, and
attached license consistently declare CC BY-SA 3.0. This is a record of the
upstream declarations, not a legal opinion or independent conclusion about
ownership. Local development E2E output containing corpus excerpts, partitions,
raw-token records, or other reversible/source-derived evidence must preserve
the contributor attribution, identify CC BY-SA 3.0 with its URI, describe the
extraction and partitioning changes, remain under CC BY-SA 3.0 or a compatible
license, and impose no additional effective restrictions. The exact upstream
README, license, and repository revision are retained as source evidence.

The proposed Blind V1 Wikipedia snapshot was never collected or published.
The counterfactual snapshot would have had to preserve per-revision
attribution, source links, history links, and the applicable CC BY-SA terms.
Removing a MediaWiki bot flag would not have established human authorship, and
the project makes no claim that the proposed text would have been free of
AI-generated material.

The retired Blind V1 confirmatory-pool proposal comprised exact Pythia-160M, Pythia-70M,
SmolLM-135M, SmolLM-360M, GPT-2, and DistilGPT2 revisions. Their pinned
upstream license declarations, immutable revision URLs, exact model-card bytes,
byte counts, and SHA-256 hashes are recorded in
`blind_v1/model-assets.draft.json`,
`LICENSES/blind-v1-model-card-evidence.json`, and
`LICENSES/ASSET_LICENSES.md`. None of those exact revision trees contains a
standalone `LICENSE*` or `NOTICE*` file; the project does not fabricate one or
mislabel a generic license text as an exact upstream-revision file. These
records do not relicense the upstream assets.

No retained notice authorizes a Blind V1 model download, snapshot collection,
NIST request, freeze, publication, or scientific execution. Any successor must
use a new suite ID and a fully rescheduled corpus, snapshot, NIST, attempt,
evidence, and closeout timeline while preserving all applicable upstream
rights and attribution obligations.

Python packages and native libraries retain their own licenses. The generated
CycloneDX SBOM and runtime manifest inventory exact installed components but do
not grant rights beyond their upstream licenses.

The real release-attestation known-answer vector retains one `cli/cli`
v2.97.0 checksum asset together with the exact upstream MIT license and
copyright notice. Its minimal GitHub-generated DSSE/X.509/RFC3161 record is
preserved verbatim only as public cryptographic and factual provenance; this
project asserts no license over GitHub certificates, signatures, or service
output and implies no GitHub endorsement.

See `LICENSES/ASSET_LICENSES.md` for the current data/model matrix.
