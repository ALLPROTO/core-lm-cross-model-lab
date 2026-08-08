# Public experiment closeout (retired Blind V1 specification)

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

The closeout design below was author-self-verified. It would have preserved a
terminal absence/late-release classification but would not have claimed
independent human review, peer review, operator blindness, or independent
replication. The separate verifier was designed as an implementation control
within the same author-controlled project.

The retired counterfactual procedure was only for the two public, non-verdict classifications
`NO_ATTEMPT_EXPIRED` and `LATE_PUBLICATION_INVALID`. Neither is an attempt
terminal state, neither permits a retry, and neither can be presented as a
PASS or FAIL_GATES result.

Had V1 reached a valid preregistration, its closeout publication would have
been an immutable GitHub release under the signed annotated tag
`corelm-blind-crossmodel-v1-closeout`, published strictly before
`2026-08-30T18:00:00Z`. Its exact four semantic roles would have been:

1. `closeout-statement` — canonical `experiment-closeout.json`;
2. `closeout-basis` — canonical bundle of the exact basis and required support;
3. `closeout-verifier-report` — deterministic offline verification report;
4. `sha256-manifest` — manifest of the preceding three files.

`package_closeout_release.py` would have created and reopened this inventory.
The normal `collect_release_receipt.py --kind closeout` path would then have bound it to the signed
tag, exact commit/tree, immutable release, verified GitHub immutable-release
attestation, and signing identity. The resulting closeout release receipt is archived separately because
a release cannot contain a receipt that observes itself.

For closeout, “exact commit/tree” always means the `labSource.commit` and
`labSource.tree` already frozen in the design registration. They are derived
from the exact design bytes by the packager and cannot be replaced with the
commit that happens to be current when closeout is published.

Every closeout also carries
`publicationBindings.reservedAttemptId`. The packager obtains it from the
exact canonical public execution reservation, requires the fixed
`20260821T180000Z-` prefix, rechecks it against the full reservation-package
verifier, and includes it in the closeout verifier report. For
`NO_ATTEMPT_EXPIRED`, this is deliberately named the *reserved* attempt ID: it
binds the closeout to the public execution obligation without claiming that a
local attempt reservation or marker was ever created.

## Historical no-local-attempt branch (unavailable; do not execute)

This abandoned branch would have required the already verified pre-pulse public
`execution-reservation.json` release and canonical receipt. That public intent
record is not local attempt state. The branch is forbidden if any local
`attempt-reservation.json`, marker, pending transition, or other result-root
byte exists: local reservation-only state is `CONSUMED_INCOMPLETE`, not
`NO_ATTEMPT_EXPIRED`. It would first have created the canonical empty-result-root observation after
`2026-08-22T18:00:00Z`. Its claim is deliberately limited to the named result
root on the named host at the observation time. It must not claim global
absence. The collector refuses a symlink or nonempty directory, audits the same
directory descriptor twice, and emits both the observation and its audit
report into a new no-overwrite directory:

```sh
python3 -I -B blind_v1/collect_empty_result_root.py \
  --result-root /absolute/path/to/exact-result-root \
  --host-environment /absolute/path/to/environment.json \
  --auditor-identity '<account or declared observer identity>' \
  --output-directory /new/path/empty-root-audit
```

It would then have created `NO_ATTEMPT_EXPIRED` with
`create_no_attempt_expired(...)` and packaged it with the exact observation,
original environment bytes, and emitted audit
report. Those three documents plus the exact audit implementation bytes are
embedded in canonical `closeout-basis.json`; hash-only references are
insufficient:

```sh
python3 -I -B blind_v1/package_closeout_release.py package \
  --closeout /absolute/path/experiment-closeout.json \
  --basis /new/path/empty-root-audit/empty-result-root-observation.json \
  --host-environment /absolute/path/to/environment.json \
  --audit-report /new/path/empty-root-audit/empty-result-root-audit-report.json \
  --design-registration /absolute/path/design-registration.json \
  --design-publication-receipt /absolute/path/design-publication-receipt.json \
  --snapshot-registration /absolute/path/snapshot-registration.json \
  --snapshot-publication-receipt /absolute/path/snapshot-publication-receipt.json \
  --reservation-publication-receipt /absolute/path/execution-reservation-publication-receipt.json \
  --reservation-release-assets /absolute/path/execution-reservation-assets \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output-directory /new/path/closeout-release
```

The observation proves only its bounded inventory. An absent marker on one
host is not proof that no attempt exists on another host or result root.
The closeout package and verifier must additionally byte-bind the three exact
public execution-reservation release assets and their verified receipt so the
no-attempt statement cannot be detached from the pre-pulse execution and
publication obligation. Its `publicationBindings.reservedAttemptId` must equal
the independently rederived `attemptId` in those exact reservation bytes; the
execution-reservation SHA-256 remains an additional byte-level binding rather
than the only visible identity link.

## Historical late-publication branch (unavailable; do not execute)

The historical rule forbade editing the deadline or calling a late release
valid. It would have downloaded the exact four evidence assets and collected
their receipt once with the explicit inverse temporal predicate:

```sh
python3 -I -B blind_v1/collect_release_receipt.py \
  --repository ALLPROTO/core-lm-cross-model-lab \
  --kind evidence \
  --tag corelm-blind-crossmodel-v1-evidence \
  --commit '<frozen-labSource.commit>' \
  --tree '<frozen-labSource.tree>' \
  --deadline '2026-08-26T18:00:00Z' \
  --signature-type SSH \
  --key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --public-key blind_v1/signing/corelm-blind-crossmodel-v1-signing.pub \
  --repo-path /absolute/path/to/clean-clone \
  --release-id '<numeric-release-id>' \
  --assets-dir /absolute/path/to/exact-evidence-assets \
  --github-cli /absolute/path/to/pinned-gh-2.97.0-macos-arm64 \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6-macos-arm64 \
  --asset evidence-package='<name>' \
  --asset evidence-release-manifest='<name>' \
  --asset evidence-package-verifier-report='<name>' \
  --asset sha256-manifest='<name>' \
  --late-closeout-observation \
  --output /new/path/late-evidence-release-receipt.json
```

That switch is evidence-only and requires the verified GitHub immutable-release
RFC3161 `attestedAt` to be at or after the registered evidence deadline. API
`published_at` remains an archived observation. The ordinary `verify_release_receipt`
continues to reject the same exact bytes. The retired procedure would have used
those bytes as the closeout
`--basis`; the packager embeds the unchanged receipt and its exact external
asset inventory in canonical `closeout-basis.json`. Packaging additionally
requires the exact evidence asset directory and the frozen design `labSource`
commit/tree, signing fingerprint, and public-key SHA-256 so every non-temporal
release check is replayed. The packager derives that source identity from the
canonical design bytes and rejects caller-supplied values that differ.

The late-observation switch changes only the registered deadline relation. It
does not bypass the pinned Cosign 3.0.6 offline check: DSSE, X.509 chain, exact
GitHub release SAN, selected asset digest, and the RFC3161 timestamp
signature/chain are still verified against the tracked GitHub root, and
`attestedAt` is still derived from the signed timestamp and cross-bound to the
semantic result. The fixed `--private-infrastructure --insecure-ignore-sct`
flags acknowledge that this GitHub bundle has no Rekor entry or certificate
SCT; no transparency-log/SCT claim is made. See
[`RELEASE_RECEIPTS.md`](RELEASE_RECEIPTS.md) for the complete boundary.

```sh
python3 -I -B blind_v1/package_closeout_release.py package \
  --closeout /absolute/path/experiment-closeout.json \
  --basis /absolute/path/late-evidence-release-receipt.json \
  --design-registration /absolute/path/design-registration.json \
  --design-publication-receipt /absolute/path/design-publication-receipt.json \
  --snapshot-registration /absolute/path/snapshot-registration.json \
  --snapshot-publication-receipt /absolute/path/snapshot-publication-receipt.json \
  --reservation-publication-receipt /absolute/path/execution-reservation-publication-receipt.json \
  --reservation-release-assets /absolute/path/execution-reservation-assets \
  --evidence-assets-dir /absolute/path/to/exact-evidence-assets \
  --expected-commit '<frozen-labSource.commit>' \
  --expected-tree '<frozen-labSource.tree>' \
  --expected-key-fingerprint 'SHA256:8A4y/GkoFglweSfg3rP21BtWWqIBOeQAUoAJDQM8sMM' \
  --expected-public-key-sha256 '9d299ff032927caef3f1355fb55c01f206ebf27ef35bcb5da547f962168b1274' \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6 \
  --output-directory /new/path/closeout-release
```

The final counterfactual step would have published the four closeout assets,
made that release immutable, and collected its ordinary `--kind closeout`
receipt before the closeout deadline.
The receipt collector's `--commit` and `--tree` arguments must be the frozen
design `labSource` values. Then perform the composed independent check:

```sh
python3 -I -B blind_v1/package_closeout_release.py verify-published \
  --release-root /absolute/path/to/exact-closeout-assets \
  --release-receipt /absolute/path/closeout-release-receipt.json \
  --design-registration /absolute/path/design-registration.json \
  --design-publication-receipt /absolute/path/design-publication-receipt.json \
  --snapshot-registration /absolute/path/snapshot-registration.json \
  --snapshot-publication-receipt /absolute/path/snapshot-publication-receipt.json \
  --cosign /absolute/path/to/pinned-cosign-v3.0.6
```

For `LATE_PUBLICATION_INVALID`, append the same evidence asset and exact
evidence source/signing arguments used while packaging. This final check fixes
the repository, tag, deadline, signing key, source commit/tree, four role/name
pairs, and requires classification and offline verification to precede the
GitHub publication timestamp. Archive the closeout receipt plus the exact
evidence assets needed to replay the late branch. A missing, late, unsigned, or
source-divergent closeout release is an unproven closeout, not a reason to infer
a more favorable outcome.
