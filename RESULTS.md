# Cross-model real-data regression results

## Verified Linux GitHub Actions run

Run date: 2026-08-02. Public workflow:
[`30750087812`](https://github.com/ALLPROTO/core-lm-cross-model-lab/actions/runs/30750087812).
Lab commit: `6731c6d203f9a3ceafbcc82d64cfcc11a15386e5`.
Codec commit: `61afcf1a44007dec54bd1c56e3403bc74182a400`.

All four isolated `ubuntu-24.04` jobs concluded `success`. This means the real
model run completed, the recorded VTL5 containers and aggregate arithmetic
were verified, the evidence manifest was created, and the artifact was
uploaded. It does not force the diagnostic metric verdict to PASS.

Runtime recorded by every cell: Linux x86_64 with glibc 2.39, Python 3.12.13,
Torch 2.13.0+cpu, Transformers 5.14.1, device `cpu`. Each cell contains eight
real WikiText-2 validation blocks 64-71, 1,024 teacher-forced decisions, and
192 complete VTL5 containers.

| Model | Complete-container ratio vs BF16 | Delta NLL | Top-1 agreement | Diagnostic |
|---|---:|---:|---:|:---:|
| Qwen2.5-0.5B | 2.052385545x | +0.000002146 | 0.996093750 | PASS |
| GPT-2 Medium | 2.054564234x | -0.000204623 | 0.999023438 | PASS |
| Pythia-410M-deduped | 2.059581758x | +0.270073175 | 0.749023438 | **FAIL** |
| BLOOM-560M | 2.066423786x | -0.000506163 | 0.990234375 | PASS |

The Pythia cell is an execution/verification success and a behavioral
diagnostic failure. Its size gate passes while delta-NLL and top-1 gates fail;
it is not averaged away. The Linux qualitative verdict matches the macOS
reference below, although floating-point metrics are not bit-identical across
the two hosts.

### Linux result and input commitments

The model-specific selected-token SHA-256 values are identical to the earlier
macOS run, so each cross-platform pair used the same token IDs, not merely the
same block numbers.

| Model | Selected token IDs SHA-256 | `result.json` SHA-256 |
|---|---|---|
| Qwen2.5-0.5B | `1bb36c91d441379596361ae779ca0542c85457e9902a290a6ab6945cb2513453` | `b38d68f19c81eab7fd19f3441be295ec4a4a3a9d5eba4585790654e0e595e68c` |
| GPT-2 Medium | `48099ffd2ba9833b50727ab19f34251135d6042e7de0aebb8cae70be2f688d00` | `b406c378f287c317624bc1240fa434b8f2f1d019da408295fa4585024404838b` |
| Pythia-410M-deduped | `17097c739a2da3e599d15cfaefe1ab92402e9796a048098e69db0e01521897dd` | `45e6d8c8a342a51aa586df8488e8a9df0e871df444b0d8e487eb89b638f9d951` |
| BLOOM-560M | `8f352c7dbd2962f27c5585fe52a55ea39a01be479b66f89e9cd942e4a17b41c1` | `3730421fd3712679631a95abe0aa1a54da8b94b2171a196e00f71d54fbde00d6` |

### Linux workflow artifacts

All downloaded ZIP digests matched the SHA-256 reported by GitHub. Each
archive contained 199 files covered by its internal `_workflow/SHA256SUMS`,
and all 796 checks passed locally after download.

| Model | Artifact ID | ZIP bytes | ZIP SHA-256 |
|---|---:|---:|---|
| Qwen2.5-0.5B | `8834178206` | 18,426,047 | `b33d55bba86e6cb3a0df2ada6010ce77be81d1c820e96a90693b248cacaaa959` |
| GPT-2 Medium | `8834213516` | 146,722,534 | `7d118d9e7b5bc397435811a756bd618306f0cc877688f081b4b10236bbec6fb5` |
| Pythia-410M-deduped | `8834217234` | 146,365,818 | `67095b18c36379be4efd4f45b8ee309fd4b6e6afff4cd1084279fb8467c2f4b7` |
| BLOOM-560M | `8834223587` | 145,881,835 | `82c47c202f23f080a067c14580daa046341a1661d729facbfa39354b976400a2` |

GitHub retains these workflow artifacts through 2026-08-16. The committed
hashes continue to identify the original bytes after the temporary downloads
expire.

## macOS historical reference

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

### macOS result commitments

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
