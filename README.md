# Core LM cross-model lab

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

[![Linux cross-model regression](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/linux-cross-model.yml/badge.svg)](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/linux-cross-model.yml)
[![Blind V1 development controls](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/blind-v1-development-controls.yml/badge.svg)](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/blind-v1-development-controls.yml)
[![Repository secret scan](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/repository-secret-scan.yml/badge.svg)](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/repository-secret-scan.yml)

The legacy root regression runs one unchanged VoidToken v5 cache-compression
profile on four pinned, real pretrained causal language models. Its workload is
the pinned real WikiText-2 `validation` parquet; no synthetic, generated,
mocked, or beacon input is accepted by that legacy runner. The separate
archived v4 development contour retains a read-only fail-closed beacon runner
and protocol, but its scientific path is no longer active.

## Blind V1 — retired, unrun terminal draft

[`blind_v1/`](blind_v1/README.md) preserves the historical design for the
unrun `corelm-blind-crossmodel-v1` suite. Its decision checkpoint elapsed
before the mandatory P0 inputs, exact-commit CI receipt, and immutable design
release existed. The resulting status is permanently
`CHECKPOINT_MISSED_TERMINAL_DRAFT`: `freezeAllowed=false`,
`publicationAllowed=false`, `scientificExecutionAllowed=false`, and
`countsTowardScientificVerdict=false`.

No confirmatory model forward pass, future-corpus selection, target-pulse
request, reservation, or scientific attempt occurred. The retained schedule,
state machine, collector, release, and evidence procedures describe only the
counterfactual experiment that could have run before the missed checkpoint;
they are not a current runbook. Blind V1 must never be frozen, published as a
preregistration, or scientifically executed. Only offline structural
verification and explicitly non-scientific development or post-release
regressions remain permissible. Any scientific successor requires a new suite
ID and a fully rescheduled corpus, snapshot, NIST, attempt, evidence, and
closeout timeline.

Every supported public Blind V1 API or CLI state creator fails closed on the
terminal lifecycle state. `_historical_*` names are private counterfactual
fixture mechanics, outside the supported contract, and must never be called
for scientific execution or publication. Same-process Python can always call
or modify source; this project does not claim a language-level sandbox.
Integrity is enforced by exact source hashes, review, and exact-commit CI.
`bootstrap_runtime.sh`, `create_runtime_manifest.py`, `create_sbom.py`, and
`source_archive.py create` are allowed only as development/provenance
transforms; they cannot authorize, freeze, publish, or scientifically execute
Blind V1.

## Legacy four-model public-validation regression

The following four model cells belong only to the legacy root regression; they
were not members of the retired Blind V1 confirmatory pool or its historically
proposed three-model selection. The cells are independent:

| Key | Model | Revision | Role |
|---|---|---|---|
| `qwen2.5-0.5b` | Qwen2.5-0.5B | `060db6499f32faf8b98477b0a26969ef7d8b9987` | regression control |
| `gpt2-medium` | GPT-2 Medium | `6dcaa7a952f72f9298047fd5137cd6e4f05f41da` | transfer diagnostic |
| `pythia-410m-deduped` | Pythia-410M-deduped | `c4fc8d586d62df497f1f9b69d66d3ca419992d3e` | transfer diagnostic |
| `bloom-560m` | BLOOM-560M | `ac2ae5fab2ce3f9f40dc79b5ca9f637430d24971` | transfer diagnostic |

Exact asset byte lengths and SHA-256 values are committed in
[`models.json`](models.json). Every model has 24 layers, so the fixed 24-entry
bit schedule is applied literally: no layer is added, removed, padded,
reordered, or retuned.

This is not an unbiased sample of all language models: the matrix was selected
for exactly 24 layers and for feasibility on an 8 GB development Mac.

## Verified Linux outcome

The first complete public Linux run is
[`Actions #2`](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/runs/30750087812)
at lab commit `6731c6d203f9a3ceafbcc82d64cfcc11a15386e5`.
All four jobs completed and their container/aggregate verifier returned
`VERIFIED`. The diagnostic result remains model-specific:

| Model | Complete-container ratio vs BF16 | Delta NLL | Top-1 agreement | Diagnostic |
|---|---:|---:|---:|:---:|
| Qwen2.5-0.5B | 2.052385545x | +0.000002146 | 0.996093750 | PASS |
| GPT-2 Medium | 2.054564234x | -0.000204623 | 0.999023438 | PASS |
| Pythia-410M-deduped | 2.059581758x | +0.270073175 | 0.749023438 | **FAIL** |
| BLOOM-560M | 2.066423786x | -0.000506163 | 0.990234375 | PASS |

Every cell contains eight real validation blocks, 1,024 teacher-forced
decisions, and 192 complete VTL5 containers. Pythia demonstrates the claim
boundary directly: compression above 2x does not by itself preserve model
behavior. Exact result, token-selection, artifact, and source hashes are in
[`RESULTS.md`](RESULTS.md).

## What the experiment can establish

The workflow is a reproducible **public-validation regression**. It can test
whether the same codec profile remains operational and diagnostically useful
on these four pinned model-tokenizer pairs under Linux CPU execution.

It is **not blind**, is not a beacon run, does not count toward the frozen Core
LM scientific verdict, and cannot establish corpus-wide or LLM-wide
generalization. A model failure remains a first-class negative result; one
model's PASS cannot hide another model's FAIL.

## Archived v4 development contour

The [`v4/`](v4/README.md) tree records the former prospective model-holdout
design and its fixed real-data development control. The control used pinned UD
English PUD r2.18 bytes, forbade future-corpus/NIST/attempt state, and reported
`countsTowardScientificVerdict=false`. It remains useful for source,
architecture, and real-model regression verification, but it is not a blind
result, preregistration, or scientific evidence. Its governance was
`AUTHOR_SELF_VERIFICATION`; no independent human review, peer review, operator
blindness, or independent replication is claimed.

V4 did not reach a scientific freeze: its tracked NIST signing leaf expires
before the proposed pulse. The contour is therefore retained only as a
non-scientific development archive. Blind V1 was the separately identified
successor draft, but it also missed its own checkpoint and is now retired and
unrun; it did not repair, continue, or retroactively validate V4. Any later
blind/generalization experiment must use another new suite identity, a fully
rescheduled timeline, replacement trust pinned before its pulse, and new
dependent commitments. V4 and Blind V1 candidate inference on a future
corpus, one-shot selection, and scientific attempt state remain forbidden.

The signed V4 development-control tag and its three-asset immutable release are
now public. They remain non-scientific and do not close the NIST blocker. For
exact tag/key verification, the Linux portability boundary, and a separately
labelled macOS real-model regression, follow [`REPRODUCE.md`](REPRODUCE.md).

The completed post-release chain is also public: the immutable
[`source-identity release`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-regression-v1),
its immutable
[`metadata correction`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-identity-correction-v1),
and the immutable
[`macOS real-model evidence release`](https://github.com/ALLPROTO/core-lm-cross-model-lab/releases/tag/corelm-crossmodel-v4-post-release-macos-e2e-evidence-v1).
The last release preserves both the first host-memory FAIL and the successful
three-model retry. Its verification class is `AUTHOR_SELF_VERIFICATION`; it is
not a scientific, blind, generalization, or NIST result.

The former [`v3/`](v3/README.md) contour and its immutable development release
are retained as a transparent non-scientific failed-freeze archive. Its
reports, receipt identity, tag, and release cannot be reused as v4 evidence.

The former [`v2/`](v2/README.md) contour is a superseded, unfrozen draft. Its
real PUD run remains a prior non-scientific development observation and cannot
be reused as v4 freeze or scientific evidence.

The familiar ratio >= 2.0x, delta-NLL <= 0.01, and top-1 agreement >= 0.99
thresholds are reported only as transfer diagnostics. They were not
preregistered for GPT-2, Pythia, or BLOOM.

## Reproduce on GitHub Linux

Open
[`Linux cross-model regression`](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/linux-cross-model.yml),
choose **Run workflow**, and run `main`. The workflow has no tunable inputs. It
starts four isolated `ubuntu-24.04` CPU jobs and fixes all cells to:

- codec source `ALLPROTO/core-lm-benchmark` commit
  `61afcf1a44007dec54bd1c56e3403bc74182a400`;
- Python `3.12.13` and the codec repository's hash-locked Linux runtime;
- WikiText-2 raw validation blocks 64 through 71;
- 512 tokens per block: 383 prefill tokens and 128 teacher-forced decisions;
- FP32 model weights, eager attention, and canonical FP32 -> BF16 -> FP32
  baseline caches;
- complete VTL5 container bytes for compression accounting.

Each job uploads the complete run directory, container/aggregate-verifier output,
environment inventory, and SHA-256 manifest even when the diagnostic verdict
is FAIL. Model weights and datasets are downloaded from their pinned upstream
revisions and are not stored in this repository.

The verifier parses and canonically reconstructs every VTL5 container and
recomputes byte accounting, aggregate metrics, gates, and verdict from the
producer's recorded per-block measurements. It does not repeat model inference;
the producer performs and records the cache replay and behavioral evaluation.
CPU kernels are requested deterministically where supported, but the project
does not claim bit-identical floating-point output across arbitrary hosts.

## Reproduce on another Linux machine

The commands below use a clean checkout of the exact codec source. They require
network access for the first hash-locked runtime and model-asset build, plus an
absolute path to CPython 3.12.13. A stock Ubuntu 24.04 interpreter and a
possibly absent `python` alias are not substitutes for that registered patch
version.

```bash
set -eu
git clone https://github.com/ALLPROTO/core-lm-cross-model-lab.git lab
git clone https://github.com/ALLPROTO/core-lm-benchmark.git codec-source
git -C lab checkout --detach 6731c6d203f9a3ceafbcc82d64cfcc11a15386e5
test "$(git -C lab rev-parse 'HEAD^{tree}')" = \
  364d320a1cf2ebbb472d75a3f4c6aa8c1652d3de
git -C codec-source checkout --detach 61afcf1a44007dec54bd1c56e3403bc74182a400
cd lab

export CORELM_LINUX_PYTHON=/absolute/path/to/python3.12.13
test "$($CORELM_LINUX_PYTHON -I -B -c \
  'import platform; print(platform.python_version())')" = 3.12.13
export CORELM_LINUX_RUNTIME="$PWD/.runtime"
export CORELM_LINUX_HF_HOME="$PWD/.codec-assets"
../codec-source/corelm linux doctor
../codec-source/corelm linux build

"$CORELM_LINUX_RUNTIME/bin/python" -I -B run_cross_model.py \
  --model qwen2.5-0.5b \
  --device cpu \
  --start-block 64 \
  --blocks 8 \
  --codec-root "$PWD/../codec-source" \
  --cache-dir "$PWD/.cross-model-assets" \
  --output-root "$PWD/runs"

RESULT=$(find runs/qwen2.5-0.5b -name result.json -type f -print -quit)
"$CORELM_LINUX_RUNTIME/bin/python" -I -B verify_run.py "$RESULT" \
  --codec-root "$PWD/../codec-source"
```

Run each remaining model in a fresh process without changing the protocol.
Local outputs and downloaded assets are ignored by Git.

## Results and cross-platform reference

[`RESULTS.md`](RESULTS.md) records the verified Linux run and the earlier
macOS CPU public-validation reference. Both remain exploratory regressions
outside the scientific verdict.

## License

The lab code is MIT-licensed. Downloaded model assets retain their upstream
licenses listed in the applicable exact-revision manifests; in particular,
BLOOM uses the BigScience BLOOM RAIL 1.0 license, while the Blind V1 pool is
listed in `blind_v1/model-assets.draft.json`. The current model/data rights
matrix, exact UD English PUD r2.18 source evidence, CC BY-SA 3.0
attribution/share-alike handling, and the boundary that upstream declarations
are not an independent ownership conclusion are documented in
[`LICENSES/ASSET_LICENSES.md`](LICENSES/ASSET_LICENSES.md) and
[`NOTICE.md`](NOTICE.md).
