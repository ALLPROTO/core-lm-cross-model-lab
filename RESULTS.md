# macOS cross-model real-data reference results

These are prior macOS reference measurements, not outputs of the Linux Actions
workflow and not scientific-verdict evidence. Their raw run directories are
not bundled in this source repository, so treat the table as historical context;
the SHA-256 values below identify the original local artifacts.

Execution date: 2026-08-02. Device: CPU on an 8 GB Apple Silicon Mac.
Input: pinned real WikiText-2 raw validation, tokenizer-native blocks 64-71.
Each cell contains 8 blocks, 1,024 teacher-forced decisions, and 192 complete
VTL5 containers. The Qwen-derived candidate configuration was not changed.

| Model | Complete-container ratio vs BF16 | Delta NLL | Top-1 agreement | Diagnostic gate |
|---|---:|---:|---:|---|
| Qwen2.5-0.5B | 2.052396845x | 0.000011921 | 0.995117188 | PASS |
| GPT-2 Medium | 2.054566028x | -0.000182182 | 0.999023438 | PASS |
| Pythia-410M-deduped | 2.059579843x | 0.272444487 | 0.763671875 | **FAIL** |
| BLOOM-560M | 2.066425728x | -0.000597209 | 0.990234375 | PASS |

All 32 block evaluations passed the exact direct-cache versus flatten/rebuild
gate and the exact canonical-cache replay gate before codec metrics were
accepted. The independent verifier parsed and reconstructed all 768 container
files and recomputed byte accounting and aggregate gates.

The negative Pythia result is not averaged away. Its compression-size gate
passes, but both behavioral gates fail on every observed block: block delta NLL
ranges from 0.194975 to 0.402425 and block top-1 agreement from 0.703125 to
0.812500. The same cache-level normalized RMSE can therefore have very
different behavioral consequences across architectures.

BLOOM's aggregate top-1 value passes narrowly, while one block falls to
0.9765625. Qwen likewise has a block at 0.984375. The registered diagnostic
gate is aggregate-level; these two cells must not be described as passing an
unregistered every-block or confidence-bound criterion.

## Exact artifacts

- Qwen result SHA-256:
  `57d95b00691a6d57344605e13cc649f192fb4a4fa6cf3b3bb7d95dfd01baaa16`
- GPT-2 result SHA-256:
  `523c635cc6c0a923b0be73e38e359ea5f25275505440d9882481173d4959f942`
- Pythia result SHA-256:
  `f54b965dbfabb9dab31d9c26277ddfa064eed24239665b2281e9a5ab2fcc1743`
- BLOOM result SHA-256:
  `9a851c7a0f712d8940acda38ef6207d57074358bf6eaa3fb2fd5b288adb0b172`
- Runner SHA-256:
  `06b5fb0f588aa5c9aa459f27c1c730d5d80349632ab9b498138ff2ae18c09709`
- Verifier SHA-256:
  `3625ac5b23efa32e67154f62892055386e37f6aee48a0104393b7c6a2da7c81f`
- Model matrix SHA-256:
  `2b000a23f658b022f9f90d31fb5a8b773648e10f93047f7dfd57741278a51039`

## Claim boundary

These are public validation regressions, not blind trials. Native tokenizers
select different token sequences for the same dataset/block rule, so absolute
NLL values and tokenwise model outputs are not paired across models. The
results support limited transfer of one unchanged cache-codec profile to GPT-2
and BLOOM, and directly refute universal transfer to Pythia. They do not count
toward the frozen beacon verdict and do not establish generalization to LLMs
or corpora in general.

The initial GPT-2 preflight exposed a Transformers 5.14.1 mmap-alignment bug for
the already-FP32 safetensors checkpoint. Final runs use `disable_mmap=True`,
which materializes the same pinned safe-tensor bytes in aligned owned memory;
it does not alter the model, data, dtype, or compression configuration.
