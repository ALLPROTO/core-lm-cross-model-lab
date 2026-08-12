# RunPod adapter sweep v1 protocol

## Status and claim boundary

This contour is an **exploratory public regression only**. It exercises real,
exactly pinned pretrained causal language models on real files already tracked
by this repository. It is not a holdout, a blind evaluation, an independent
replication, or scientific evidence. Every result and event document must set
`countsTowardScientificVerdict` to `false` and must identify the classification
`EXPLORATORY_PUBLIC_REGRESSION_ONLY`.

The sweep must not modify, replace, or inherit the verdict of the frozen Qwen
V15, beacon, application-proof, or Linux regression contours. A successful
process proves only that one exact adapter/profile/workload cell executed and
that its retained evidence verified. It does not establish support for an
architecture family or for arbitrary checkpoints.

## Immutable inputs

`profiles.json` is the execution-profile registry. A cell is runnable only when
its profile pins a full repository revision, license status, configuration,
weights, tokenizer assets, required auxiliary assets, cache policy, and memory
budget. Metadata compatibility alone is not execution admission. Remote model
code, unregistered assets, implicit credentials, and unrecorded conversions are
forbidden.

`workloads.json` is the workload and context registration. It contains no copied
corpus and no generated prompt. Each workload is an exact, sorted allowlist of
tracked repository paths in one of four disjoint source groups:

- technical prose;
- source code;
- structured JSON; and
- legal, security, and protocol material.

Some allowlisted text comes from the repository's archived V4 contour. Those
bytes are inert workload text only: this sweep does not import or invoke V4,
does not create V4 state, and cannot use an archived V4 document as a successor
scientific gate. Blind V1 files are excluded from the workload allowlists.

For each path, the runner must read the exact blob at `HEAD:<path>` from the Git
object database, not the mutable working-tree file. The checkout must be clean,
and the runner must record the source commit, source tree, Git blob object ID,
blob byte length, and SHA-256 for every input path.

All selected blobs must decode as strict UTF-8 and contain no NUL. Paths are
concatenated in ascending POSIX byte order without newline normalization. For a
path `P` and exact blob bytes `B`, its frame is precisely:

```text
===== BEGIN CORELM TRACKED FILE: P =====\n
B
\n===== END CORELM TRACKED FILE: P =====\n
```

The bytes shown as `\n` are one LF byte. The runner must record the SHA-256 and
byte length of the complete framed workload. Any missing path, non-blob Git
object, symlink/submodule mode, decoding failure, path-order change, blob digest
change, or working-tree source read is an input-integrity error.

## Matrix and token geometry

The registered matrix contains seven adapters and four workloads, for exactly
28 planned cells. Each cell runs in a fresh operating-system process. No model
object, tokenizer, allocator state, cache, environment mutation, or failure
state may be reused by another cell.

| Adapter | Maximum compressed prefill | Limiting bound |
|---|---:|---|
| GPT-2 | 991 tokens | model context minus horizon and final prompt token |
| GPT-NeoX / Pythia | 2,015 tokens | model context minus horizon and final prompt token |
| OPT | 1,365 tokens | 2,097,152 decoded matrix elements per layer |
| Mistral | 1,024 tokens | codec matrix bound; below its 4,096 sliding window |
| Llama / SmolLM | 5,461 tokens | 2,097,152 decoded matrix elements per layer |
| Gemma | 4,096 tokens | 2,097,152 decoded matrix elements per layer |
| Qwen2 | 8,192 tokens | 2,097,152 decoded matrix elements per layer |

The prediction horizon is exactly 32 greedy decisions. If `P` is the registered
maximum compressed prefill, tokenization uses `add_special_tokens=false` and no
truncation, then selects the first `P + 1` token IDs. Tokens `0 .. P-1` form the
prefill and token `P` is the final prompt token supplied to both rebuilt caches.
The baseline then greedily selects 32 tokens. Candidate logits are compared on
that same controlled baseline trajectory, and a separate candidate free run
records its own 32-token greedy trajectory.

The exact selected uint32 little-endian token-ID SHA-256 is retained for every
cell. If the workload has fewer than `P + 1` tokens, the tokenizer truncates,
inserts special tokens, changes assets, or produces an out-of-range ID, the cell
terminates as `EXECUTION_ERROR` and the matrix is incomplete.

For Mistral, the 1,024-token cache is deliberately below its pinned 4,096-token
sliding window. No eviction is expected or permitted in this V1 sweep. A cell
must fail closed if observed retention or attention semantics differ from its
pinned profile. Mistral results are not aggregated with full-context results.

## Cell process contract

The supervisor creates a private, previously nonexistent directory for each
`adapterId/workloadId` cell and writes an exclusive attempt record before model
loading. It launches the worker with direct argument vectors, `shell=false`, a
new process group, a fixed timeout, and a minimal environment. Hugging Face and
Transformers offline modes are mandatory during execution. `trust_remote_code`
is always false. A worker may resolve only the exact hash-checked assets in the
private cache named by its profile.

Before loading weights, the worker verifies the profile, all asset hashes, the
workload registration, source identity, token geometry, available disk, and the
profile's registered hard GPU admission budget. Peak process RSS is sampled by
the worker; cgroup-v2 current/limit and container-lifetime peak counters are
recorded separately and are not mislabeled as a per-cell cgroup peak. Timeout,
signal, OOM, budget
excess, or partial output becomes a terminal execution error for that cell; it
must never be rewritten as a metric failure or silently retried under the same
run identity.

The worker must derive cache geometry from the observed tensors and compare it
to the pinned profile before encoding. Batch size must be one. K and V must be
finite, have the same token extent, and be reconstructible through the admitted
adapter. Flattening and rebuilding the uncompressed cache must reproduce direct
continuation exactly before any lossy metric is accepted. Encoded bytes must be
fresh-parsed, and only the parsed reconstruction may drive candidate replay.

## Evidence and verification

A completed orchestrator attempt has one terminal execution row for every
planned cell. An external termination of the orchestrator or Pod can leave
only partial attempts/logs and no final `run.json`; such an interrupted attempt
is not structurally verifiable and must never be presented as a complete
matrix. Successful result metrics, the whole-run structural-verification
receipt, and per-cell model-replay
receipts remain separate artifacts; none is inferred from another. At minimum
the retained record binds:

- source commit/tree and the exact profile/workload document SHA-256 values;
- model, tokenizer, runtime-lock, and input-blob identities;
- selected token IDs and their digest;
- requested, logical, prefill, continuation, target, effective-cache, and
  evicted token counts;
- observed layers, KV heads, head dimension, tensor layout, dtype, and cache
  class;
- codec configuration, every complete container's byte length and SHA-256,
  canonical dense bytes, and complete encoded bytes;
- baseline/candidate top-1 IDs, controlled KL and selected-token surprisal
  delta for all 32 decisions, plus both greedy continuation texts;
- complete-container compression and descriptive behavioral metrics for that
  cell, with no inherited PASS threshold; and
- timeout limit/outcome, exit code or signal, peak RSS, clearly labeled cgroup
  counters, and termination reason.

The structural verifier is independent of the model worker. It must strictly
parse JSON with duplicate-key and non-finite-number rejection, reject symlinks,
special files, traversal, missing or extra artifacts, enforce decompression and
total-size bounds, recompute all hashes and byte accounting, recompute token
metrics and gates, and require exactly all 28 registered **complete** cells. A
separate offline replay verifier loads one preregistered representative cell for
each of the seven profiles and establishes that its decoded caches reproduce the
retained 32 baseline and candidate decisions. The other 21 cells receive
structural, not model, replay in this V1 contour.

Process exit zero, structural verification, and replay verification are three
distinct facts. A producer cell is either `COMPLETE` or `EXECUTION_ERROR`; the
run is `INCOMPLETE` if any of its 28 rows is not complete. The structural
verifier deliberately issues no success receipt for an incomplete run. A
timeout, resource/input rejection, signal, missing output, partial output, or
unverifiable cell therefore remains visible as `EXECUTION_ERROR` with its exact
return/timeout/termination fields and never counts as successful evidence.

## Aggregation and publication

Per-token metrics may be aggregated only inside one exact cell. The publication
may count cell states, but it must not average compression, NLL, top-1, memory,
or latency across models, tokenizers, workload classes, cache policies, or
context targets. One model's PASS never transfers to another model, another
adapter, another workload, or another context length. Negative and incomplete
cells remain visible and are never filtered from the matrix.

No secret, bearer token, SSH material, RunPod endpoint, pod identifier, private
cache path, or environment dump belongs in a tracked registry or retained
public result. Setup and asset acquisition are separate from offline execution.
This v1 public regression cannot be promoted into a scientific claim by adding
more runs; a scientific experiment would require a new preregistered suite,
disjoint real inputs, a new evidence class, and a separately frozen verifier.
