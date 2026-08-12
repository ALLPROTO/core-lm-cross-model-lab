# Recorded RunPod sweeps

This directory holds compact, reviewable publications derived from a locally
retrieved, checksum-checked RunPod export. The large evidence archive is not stored
in Git. Each recorded run contains its exact archive digest, 28 cell rows,
attempt history, lifecycle cleanup attestations, an audit table, and an
ordinary-user reproduction guide.

Lifecycle timestamps, cost, termination, volume deletion, and credential
cleanup are always labelled
`OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED`. The builder checks only their
schema, grammar, and internal consistency. It does not contact RunPod, inspect
the user's provider account, or claim a provider verification receipt.

Every record remains `EXPLORATORY_PUBLIC_REGRESSION_ONLY`. It is author
self-verification, not scientific evidence, independent human review, or an
independent replication. The producer, structural verifier, and seven model
replays ran on the same Pod from the same source, runtime, assets, and
operator-controlled attempt.

## Build only after cleanup

Do not prepare the successful publication input until all of these facts are
true: the archive and `SHA256SUMS` were retrieved and checked, the Pod was
terminated (not stopped), its Pod volume disappeared, no network volume was
used, the RunPod Secret was deleted, the dedicated Hugging Face and lifecycle
API tokens were revoked, and the ephemeral SSH credential was retired. The
builder requires every cleanup field to be true and fails if the final cost is
above USD 35.

Create an owner-private, canonical JSON file with this exact shape. Placeholder
values below are explanatory and are not accepted literally:

```json
{
  "attempts": [
    {
      "attemptNumber": 1,
      "failureCode": "TRITON_NOEXEC_CACHE",
      "failureStage": "EXECUTABLE_CACHE_SMOKE",
      "forensics": {
        "bytes": 1,
        "manifestSHA256": "64-lowercase-hex"
      },
      "generatedRunRootDisposition": "REMOVED_AFTER_BOUNDED_FORENSICS",
      "sourceCommit": "40-lowercase-hex",
      "sourceTree": "40-lowercase-hex",
      "status": "INCOMPLETE"
    },
    {
      "attemptNumber": 2,
      "failureCode": null,
      "failureStage": null,
      "forensics": null,
      "generatedRunRootDisposition": "ARCHIVE_RETRIEVED_AND_VERIFIED",
      "sourceCommit": "successful-40-lowercase-hex",
      "sourceTree": "successful-40-lowercase-hex",
      "status": "COMPLETE"
    }
  ],
  "lifecycle": {
    "attestationBasis": "OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED",
    "builderValidationScope": "SCHEMA_GRAMMAR_AND_INTERNAL_CONSISTENCY_ONLY",
    "admissionProjectedCombinedHourlyRateUSD": 0.0,
    "containerImageDigest": "sha256:64-lowercase-hex",
    "costCeilingUSD": 35.0,
    "costObservationBasis": "RUNPOD_BILLING_API_FINAL_SO_FAR_AFTER_POD_ABSENCE_BEFORE_KEY_REVOCATION",
    "createdAt": "YYYY-MM-DDTHH:MM:SSZ",
    "currency": "USD",
    "providerObservedCostUSD": 0.0,
    "providerObservedEffectiveHourlyRateUSD": 0.0,
    "providerObservedTimeBilledMs": 1,
    "huggingFaceTokenRevoked": true,
    "isolationBoundary": "PROVIDER_MANAGED_CONTAINER_NOT_INDEPENDENT_VM",
    "lifecycleApiKeyRevoked": true,
    "networkVolumeUsed": false,
    "platform": "RunPod Pod",
    "podTerminated": true,
    "podVolumeDeleted": true,
    "providerTerminationFuseHours": 20,
    "providerVerified": false,
    "runpodSecretDeleted": true,
    "sshCredentialRetired": true,
    "terminatedAt": "YYYY-MM-DDTHH:MM:SSZ"
  },
  "operatorVerification": {
    "archiveSHA256": "64-lowercase-hex",
    "independentHumanReview": false,
    "independentReplication": false,
    "kind": "AUTHOR_SELF_VERIFICATION",
    "localArchiveChecksumVerified": true,
    "localArchiveInventoryVerified": true,
    "modelReplayReceipts": 7,
    "podStructuralVerifier": "SAME_POD_SAME_SOURCE_RUNTIME_CACHE"
  },
  "recordedAt": "YYYY-MM-DDTHH:MM:SSZ",
  "schemaVersion": "corelm-runpod-adapter-publication-input-v1",
  "successfulAttemptNumber": 2
}
```

The cost observation is the last RunPod billing-API snapshot taken after the
Pod disappeared and before the restricted lifecycle key was revoked. It is
therefore labelled `FINAL_SO_FAR`, not a later provider invoice. The builder
requires `providerObservedEffectiveHourlyRateUSD` to equal
`providerObservedCostUSD * 3600000 / providerObservedTimeBilledMs`, and requires
the billed duration not to exceed the creation-to-termination wall interval.
The separately named admission projection is not substituted for that provider
observation.

The attempt array is contiguous from 1 through
`successfulAttemptNumber`. Every earlier attempt must remain `INCOMPLETE`,
carry one of the closed failure pairs below, and include a forensic-manifest
binding. The last attempt must match the source commit/tree inside the
retrieved export.

The only accepted failure pairs and dispositions are:

- `EXECUTABLE_CACHE_SMOKE` / `TRITON_NOEXEC_CACHE` →
  `REMOVED_AFTER_BOUNDED_FORENSICS`.
- `SWEEP_ORCHESTRATE` /
  `DISTILGPT2_LEGACY_CAUSAL_MASK_INCOMPATIBILITY` →
  `REMOVED_AFTER_BOUNDED_FORENSICS`.
- `PRELAUNCH_CHECK` / `OPERATOR_EXPECTED_IDENTITY_SCOPE_ERROR` →
  `NO_RUN_ROOT_CREATED_BOUNDED_FORENSICS_RETAINED` because no run root was
  created in that attempt.

Free-text failure descriptions are not accepted. This closed vocabulary keeps
private paths, endpoints, Pod identifiers, and credentials out of the public
record.

Canonicalize the completed input with the standard library if necessary:

```bash
python3 - operator-metadata.json <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
path.write_text(
    json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
               separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
chmod 0600 operator-metadata.json
```

## Generate and verify

From the repository root, with the retrieved archive and checksum alone in one
owner-private directory:

```bash
python3 runpod-adapter-sweep-v1/recorded-runs/build_recorded_run.py build \
  --export-dir /private/path/to/retrieved-export \
  --operator-metadata /private/path/to/operator-metadata.json \
  --output runpod-adapter-sweep-v1/recorded-runs/YYYY-MM-DD-attempt-NN \
  --repository .

python3 runpod-adapter-sweep-v1/recorded-runs/build_recorded_run.py verify \
  --publication-dir runpod-adapter-sweep-v1/recorded-runs/YYYY-MM-DD-attempt-NN \
  --export-dir /private/path/to/retrieved-export \
  --repository .

python3 runpod-adapter-sweep-v1/recorded-runs/build_recorded_run.py update-index \
  --runs-root runpod-adapter-sweep-v1/recorded-runs
```

`build` is one-shot and refuses an existing output directory. It verifies the
local archive checksum, consumes exactly one complete gzip member through its
CRC/ISIZE trailer, rejects concatenated members or any trailing bytes, checks
tar member safety and exact inventory, checks canonical JSON and sidecar
hashes, and locally reverifies the sweep commit signature
against the trust root whose exact bytes are also bound to that commit. The
builder reconstructs every workload from the exact signed-commit Git blobs and
registered UTF-8 frames, then compares the Git mode, blob SHA-1, byte count,
SHA-256, framed byte count, and prompt SHA-256. It does not locally retokenize:
`availableTokens`, selected token counts, and token-ID digests remain explicitly
`SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED`.

Asset receipts are bound to every signed profile path and byte count, to every
profile SHA-256 available in the signed registry, and to identical raw/verified
file inventories. Gated asset digests absent from the registry and the actual
asset bytes are not locally retrieved, so content verification remains a
same-Pod receipt assertion. The codec receipt must contain the exact registered
commit, tree, eight-file manifest, and lock hashes. The codec signature and
actual codec bytes remain `SAME_POD_RECEIPT_NOT_LOCALLY_REVERIFIED`; the codec
repository is not an input to this builder. The tool also verifies
all 28 result/container/log bindings, the complete structural receipt, all
seven registered replay receipts, and cell arithmetic. For attempt history,
cost, lifecycle, and cleanup, it validates only the operator metadata's schema,
grammar, and internal consistency; these remain self-attested and are not
externally or provider verified. It emits `operator-metadata.json`, `archive-receipt.json`,
`record.json`, `RESULTS.md`, and `REPRODUCE.md`, each with a SHA-256 sidecar.

The generated audit has exactly one row per cell and no cross-cell, per-model,
or global metric averages. Protocol-defined within-cell means over the fixed
32-token horizon and the full per-token arrays remain visible. The report also
states the causal limitation explicitly: deterministic execution controls
repeatability, while the present fixed-length-per-model matrix cannot establish
that compression grows with data-path length. That question needs a separate
within-model, within-workload prefill-length ladder.
