# RunPod adapter sweep V1 model profiles

This directory defines an **exploratory public regression**, not a scientific
experiment and not an extension of the registered V15 result. “All models” in
this sweep means one real public pretrained checkpoint for each of the seven
closed metadata adapters already named by Core LM: Qwen2, Llama, Mistral,
GPT-NeoX, GPT-2, OPT, and Gemma. It does not mean every LLM, every checkpoint,
or every cache topology.

The machine-readable authority is [`profiles.json`](profiles.json). Every
repository is pinned to a full 40-hex Hugging Face commit. Remote model code,
quantized weights, pickle loading during model execution, encoder-decoder
models, multimodal models, mixture-of-experts models, and unlisted assets are
outside this contour.

Execution is on a RunPod provider-managed Linux **Pod container**, not a virtual
machine. The producer, structural verifier, and representative replay verifier
share the same Pod, exact source, runtime, and asset cache. Their agreement is
not an independent replication or an independently administered Linux result.

## Exact sweep

| Adapter | Exact checkpoint | License / gate | Geometry | Weight bytes | GPU admission cap | Profile state |
|---|---|---|---|---:|---:|---|
| Qwen2 | `Qwen/Qwen2.5-0.5B@060db6499f32faf8b98477b0a26969ef7d8b9987` | Apache-2.0; ungated | 24 layers; 32,768 context; 14 Q / 2 KV heads; head 64 | 988,097,824 | 16 GiB / 22.5 min | asset pin complete |
| Llama | `HuggingFaceTB/SmolLM2-135M@93efa2f097d58c2a74874c7e644dbc9b0cee75a2` | Apache-2.0; ungated | 30 layers; 8,192 context; 9 Q / 3 KV heads; head 64 | 269,060,552 | 8 GiB / 15 min | asset pin complete |
| Mistral | `mistralai/Mistral-7B-v0.1@27d67f1b5f57dc0953326b2601d68371d40ea8da` | Apache-2.0; ungated | 32 layers; 32,768 context; 4,096 sliding window; 32 Q / 8 KV heads; head 128 | 14,483,498,040 | 32 GiB / 45 min | asset pin complete |
| GPT-NeoX | `EleutherAI/pythia-14m@cf967c0a9a04383db6f7b1108d86b2962634b4ac` | Apache-2.0; ungated | 6 layers; 2,048 context; 4 Q / 4 KV heads; head 32 | 28,143,920 | 8 GiB / 15 min | asset pin complete |
| GPT-2 | `distilbert/distilgpt2@2290a62682d06624634c1f46a6ad5be0f47f38aa` | Apache-2.0; ungated | 6 layers; 1,024 context; 12 Q / 12 KV heads; head 64 | 352,824,413 | 8 GiB / 15 min | asset pin complete; mmap disabled |
| OPT | `facebook/opt-125m@27dcfa74d334bc871f3234de431e71c6eeba5dd6` | custom OPT license; ungated; noncommercial research only | 12 layers; 2,048 context; 12 Q / 12 KV heads; head 64 | 250,540,281 source | 8 GiB / 15 min | trusted conversion required |
| Gemma | `google/gemma-2b@9cf48e52b224239de00d483ec8eb84fb8d0f3a3a` | Gemma terms; manual gate | 18 layers; 8,192 context; 8 Q / 1 KV head; head 256 | 5,012,363,872 | 16 GiB / 30 min | authorized materialization required |

The codec matrix bound is separate from the architecture context ceiling.
`maxPrefillTokens` is exactly 8,192 for Qwen, 5,461 for SmolLM2, 1,024 for
Mistral, 2,015 for Pythia, 991 for DistilGPT2, 1,365 for OPT, and 4,096 for
Gemma. Each value is the smaller of `contextTokens - 33` and
`floor(2,097,152 / (2 * kvHeads * headDimension))`; the registered 32-token
horizon follows the prefill.

The memory and time values are fail-closed `gpuAdmission` limits for sequential,
batch-one execution on exactly one generic NVIDIA CUDA GPU with at least 78,000
MiB visible VRAM. They do not bind a GPU product name. `maxInputTokens` retains
each model's architecture context ceiling (or the 4,096-token effective sliding
window for Mistral), while the actual sweep obeys the smaller codec matrix bound
above. Every per-profile timeout is at most 2,700 seconds; Mistral owns that
maximum. The orchestrator must be invoked with the registered ceiling
`--cell-timeout-seconds 2700`, applies each profile's smaller exact limit, and
is itself bounded by `run_on_runpod.sh` to 41,400 seconds so all 28 terminal
cell records and process-group cleanup fit within the admitted envelope.

These are admission limits, not measured results and not evidence about a
previous RunPod execution.
The sweep must record the actual CUDA availability, device name, driver/runtime,
allocated/reserved/peak GPU memory, dtype, deterministic-algorithm policy, and
timeout outcome for every profile.

## Exact CUDA runtime

The only admitted runtime construction path is `build_cuda_runtime.sh`. It
combines the exact codec checkout's pinned CPython 3.12 Linux bootstrap and
portable hash locks with `torch-linux-cu130-py312.txt`. That CUDA lock pins the
`torch==2.13.0+cu130` Linux x86_64 wheel plus the exact CUDA 13.0, cuDNN, NCCL,
Triton, and supporting distributions selected by its official metadata. The
builder verifies the exact three-lock installed closure, CPython 3.12.13, CUDA
13.0, one visible CUDA device, BF16 support, and owner-only runtime paths before
atomic publication.

`run_on_runpod.sh` also requires an operator-supplied immutable container image
digest through `CORELM_SWEEP_IMAGE_DIGEST` and records it in the source receipt.
That value binds the claimed managed-container input; it is not a provider
attestation and does not turn the Pod into a VM.

## Asset integrity

For ungated files, `profiles.json` records the exact byte size, Hugging Face Git
blob OID, and SHA-256 of the byte stream resolved from the pinned revision.
For official LFS files, the LFS OID is the content SHA-256 and is recorded in
both fields. Only the listed safetensor files may be downloaded for Qwen,
SmolLM2, Mistral, Pythia, DistilGPT2, and Gemma; duplicate `.bin`, framework,
Core ML, GGUF, and training-state files are excluded.

Materialization and model execution are separate phases. Materialization may
use the network only to fetch an exact repository/revision/path tuple. It must
verify path, regular-file type, byte count, and available digest before making
the asset visible in an owner-only cache. Execution starts only after the
complete profile and its receipt are verified. Execution sets Hugging Face and
Transformers offline/local-files flags and disables implicit authentication.
This is application/library-level offline behavior, not OS firewalling or proof
that the managed Pod had no egress route.

The Gemma repository is manually gated. Anonymous official tree metadata
exposes exact paths, sizes, and Git blob IDs, while redacting its LFS OIDs. The
SHA-256 values present in Hugging Face security metadata are recorded for the
four LFS assets. SHA-256 remains deliberately `null` for the five small gated
Git assets: an authorized materializer must verify their pinned Git blob ID,
compute SHA-256, bind it into the run's materialization manifest, and reverify
that manifest before execution. This profile must fail closed if any expected
digest, size, or Git OID differs. A Hugging Face token may be supplied only as
an ephemeral environment value after the operator has accepted the Gemma
terms; its value must never enter source, arguments, logs, manifests, receipts,
cache paths, or evidence.

## OPT conversion boundary

The official `facebook/opt-125m` revision has no safetensors weights on its
main branch. Its only admitted weight source is the exact
`pytorch_model.bin` listed in `profiles.json` (250,540,281 bytes, SHA-256
`2d74da6615135c58cf3cf9ad4cb11e7c613ff9e55fe658a47ab83b6c8d1174a9`).
It must never be passed to `from_pretrained` or loaded by ordinary pickle.

After source verification, credential destruction, and activation of the
offline library settings, a fresh single-purpose process may call only
`torch.load(verified_open_file, map_location="cpu", weights_only=True)`. The
regular, single-linked source is opened without symlink following, and its exact
registered byte count and SHA-256 are checked on that same descriptor before
parsing. It
must reject anything except a plain string-keyed tensor map, sort keys, move
contiguous tensors to CPU, and write `model.safetensors`. The process receives
no Hugging Face or provider credential and records the application-offline
environment. This is not an OS-level network namespace. The derived SHA-256 is
recorded and reverified before the normal model process starts; only that
derived safetensors file may be loaded. The conversion environment and output
digest belong in the receipt. This controlled conversion is a distinct trust
surface, not equivalent to an upstream safetensors publication.

## Evidence semantics

Each profile has two separately reported outcomes:

- execution/integrity: assets verified, real model forward pass completed,
  dynamic cache extracted, flattened, rebuilt, and used for continuation; and
- observed metrics: compression ratio, delta NLL, and top-1 agreement reported
  without inheriting Qwen's thresholds.

A successful execution cannot turn a behavioral failure into PASS. In
particular, the existing real Pythia-410M-deduped negative result remains a
negative result; this smaller Pythia checkpoint is an adapter smoke profile,
not a replacement for it. No row in this sweep counts toward the V15
scientific verdict, independent replication, a GPU claim, or support for
arbitrary models.

The producer creates 28 real cells: seven profiles by four workloads. The
structural verifier parses and recomputes all 28 retained cells without loading
all 28 models again. The launcher then requires seven representative model
replays, exactly one fixed workload per profile. It therefore produces 28
structurally verified cell records and seven replay receipts, **not 28 model
replays**.

The versioned producer and verifier are separate implementations, but they run
inside the same managed Pod and use the same exact source, runtime, and cache.
Their receipts are not an independent replication. The deterministic archive
excludes model assets/cache; a downloaded archive checksum is transfer-integrity
evidence only and cannot perform local semantic `verify-run` or `replay-cell`.
