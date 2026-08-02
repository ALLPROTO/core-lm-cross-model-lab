# Core LM cross-model lab

[![Linux cross-model regression](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/linux-cross-model.yml/badge.svg)](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/workflows/linux-cross-model.yml)

This repository runs one unchanged VoidToken v5 cache-compression profile on
four pinned, real pretrained causal language models. The workload is the pinned
real WikiText-2 `validation` parquet; no synthetic, generated, mocked, or beacon
input is accepted by the runner.

The four model cells are independent:

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

## What the experiment can establish

The workflow is a reproducible **public-validation regression**. It can test
whether the same codec profile remains operational and diagnostically useful
on these four pinned model-tokenizer pairs under Linux CPU execution.

It is **not blind**, is not a beacon run, does not count toward the frozen Core
LM scientific verdict, and cannot establish corpus-wide or LLM-wide
generalization. A model failure remains a first-class negative result; one
model's PASS cannot hide another model's FAIL.

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
network access for the first hash-locked runtime and model-asset build.

```bash
git clone https://github.com/ALLPROTO/core-lm-cross-model-lab.git
git clone https://github.com/ALLPROTO/core-lm-benchmark.git codec-source
git -C codec-source checkout --detach 61afcf1a44007dec54bd1c56e3403bc74182a400

export CORELM_LINUX_PYTHON=python
export CORELM_LINUX_RUNTIME="$PWD/.runtime"
export CORELM_LINUX_HF_HOME="$PWD/.codec-assets"
./codec-source/corelm linux doctor
./codec-source/corelm linux build

"$CORELM_LINUX_RUNTIME/bin/python" -I -B run_cross_model.py \
  --model qwen2.5-0.5b \
  --device cpu \
  --start-block 64 \
  --blocks 8 \
  --codec-root "$PWD/codec-source" \
  --cache-dir "$PWD/.cross-model-assets" \
  --output-root "$PWD/runs"

RESULT=$(find runs/qwen2.5-0.5b -name result.json -type f -print -quit)
"$CORELM_LINUX_RUNTIME/bin/python" -I -B verify_run.py "$RESULT" \
  --codec-root "$PWD/codec-source"
```

Run each remaining model in a fresh process without changing the protocol.
Local outputs and downloaded assets are ignored by Git.

## Existing reference

[`RESULTS.md`](RESULTS.md) records the earlier macOS CPU public-validation
regression. Those numbers are useful as a cross-platform reference, but they
are not Linux results and remain outside the scientific verdict.

## License

The lab code is MIT-licensed. Downloaded model assets retain their upstream
licenses listed in `models.json`; in particular, BLOOM uses the BigScience
BLOOM RAIL 1.0 license.
