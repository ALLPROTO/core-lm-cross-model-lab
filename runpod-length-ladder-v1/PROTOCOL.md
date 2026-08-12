# RunPod length ladder v1 protocol

## Status and question

This suite is a preregistered public length ladder for one exact model, one
exact workload, one exact cache adapter, and one exact codec configuration. It
asks whether the complete-container compression ratio increases along six
nested prefill lengths. It is classified
`PREREGISTERED_PUBLIC_LENGTH_LADDER_ONLY`; every retained document must set
`countsTowardScientificVerdict` to `false`.

This suite does not inherit or modify any frozen Core LM verdict. It cannot
establish a content-independent, model-independent, architecture-wide, or
universal relationship between context length and compression. The workload is
public and the model and codec were selected after earlier public regression
work, so this contour is not a blind or independent replication.
Because longer points add particular technical-prose tokens, this nested-prefix
design cannot separate an abstract length effect from the content of those
added tokens. It establishes only `R(P)` along this exact token trajectory.

The same Qwen model, technical-prose workload definition, and `P=8192` length
were already observed and
published in `runpod-adapter-sweep-v1/recorded-runs/2026-08-12-attempt-04`
before this design; `ladder.json` binds that public record and selected-result
digest. The tracked source tree has since changed, so the current framed prompt
bytes and token IDs differ from that prior run. Therefore the design is
informed by a related known anchor, but none of the exact current six points is
known. This suite imports no prior cache, container, metric, or outcome byte
and recomputes a fresh `P=8192` direct cell in its preregistered execution
position. The five lower `P` points were not previously measured in this exact
contour.

## Prospective operational CPU-quota amendment

The original signed preregistration commit
`b0f3b207dcddcd19c921d52bd73871508e335e79` and its signed
provider-credential-boundary successor
`28cfda0b32b9cb3f33a028b73b325a9e6751da5a` required at least eight online
logical CPUs and also admitted a finite current-process cgroup CPU ceiling only
when it provided at least eight quota-equivalent cores. After those two public
predecessors, three operational allocation/admission probes were terminated
before asset acquisition. The first two stopped at control-plane envelope
readback; the third reached and stopped at the current-process cgroup resource
gate. No model asset was downloaded, no model inference was performed, and no
experimental result or outcome was observed in any probe.

Prospectively, before any evidence-producing attempt, the minimum number of
online logical CPUs remains **eight**. The sole amendment is that the minimum
accepted finite cgroup CPU quota ceiling is now exactly **seven
core-equivalents**: for cgroup v2, `quota >= 7 * period` in `cpu.max`; for
cgroup v1, `cpu.cfs_quota_us >= 7 * cpu.cfs_period_us`. An explicit unlimited
quota remains admissible, and any finite quota below seven core-equivalents is
rejected. This does not redefine the online-logical-CPU requirement as seven.

The hypothesis, model and assets, workload bytes and tokenization, six `P`
values, codec configuration, direct and secondary execution order, estimand,
decision and publication rules, and every worker, stage, and provider timeout
remain unchanged. No timeout is widened to compensate for the lower finite
quota floor. If the lower quota has an operational effect, it can only cause an
existing timeout or stage failure and therefore a visible `INCOMPLETE` attempt;
it cannot authorize a retry, substitution, filtered cell, or changed result
rule.

After the signed amendment commit
`77353942a2d885e00bfc6c876d2ec666c50e0b35`, the first execution successor
passed source, contract, cgroup, and executable-cache admission but stopped at
the start of `ASSET_DOWNLOAD`, before any asset network request or model
inference. The downloader's generic credential-name guard had classified the
literal non-secret control `HF_HUB_DISABLE_IMPLICIT_TOKEN=1` as a credential.
The operational correction admits only that exact name/value pair; a missing,
empty, differently valued, or other token-shaped field remains rejected. No
hypothesis, workload byte, token prefix, model, codec, order, estimand, decision
rule, materiality rule, or timeout changes. The failed root is not reused.

## Immutable experimental unit

The only admitted tuple is:

- model: `qwen2.5-0.5b` using the pinned profile
  `qwen2.5-0.5b-runpod-sweep-v1`;
- adapter: `qwen2-dynamic-cache-v1` with a full-context dynamic cache;
- workload: `tracked-technical-prose-v1`;
- prediction horizon: 32 greedy decisions; and
- prefill ladder: exactly 256, 512, 1,024, 2,048, 4,096, and 8,192 tokens,
  in that order.

`ladder.json` is the frozen registration. Its six `levelId` values and lengths
are closed; no omitted, substituted, adaptively chosen, or repeated length may
be presented as part of this v1 matrix. To reduce monotone wall-clock drift as
a confound, fresh cells execute in the preregistered nonmonotone order 4,096,
512, 8,192, 256, 1,024, and 2,048 tokens. Results and comparisons are always
displayed in ascending `P` order; execution order never changes the estimand.

The selected Qwen profile and technical-prose workload are imported from the
adjacent `runpod-adapter-sweep-v1` suite and are bound by the SHA-256 of its
complete `profiles.json` and `workloads.json` documents. The model repository,
revision, configuration, tokenizer, weights, geometry, memory limit, and asset
hashes therefore remain identical at every length.

This suite imports the selected profile object, its per-profile GPU admission,
and exact assets; it does not silently inherit the adapter sweep's matrix-wide
78 GiB device class. `ladder.json` registers a suite-specific envelope of one
BF16-capable NVIDIA CUDA GPU with at least 40,960 MiB, at least eight logical
CPUs, a current-process cgroup CPU quota ceiling of at least seven
core-equivalents (or an explicit unlimited quota), and at least 32 GiB host
memory. The exact GPU identity and driver are fixed and recorded within one
attempt. This envelope is an operational admission for the single Qwen model,
not evidence that results transfer across hardware or runs.

## Exact nested input prefixes

Workload construction is exactly the tracked-Git-blob framing contract of
`runpod-adapter-sweep-v1/workloads.json`. Bytes are read from `HEAD:<path>` in
ascending POSIX byte order. Working-tree workload bytes, newline normalization,
implicit special tokens, tokenizer truncation, and remote model code are
forbidden.

The complete framed workload is tokenized once per fresh cell with
`add_special_tokens=false` and no truncation. For registered prefill length
`P`, token IDs `0 .. P-1` are the prefill and token ID `P` is the final prompt
token. Thus the selected vectors contain `P+1` IDs and are exact nested prefixes
of the same tokenizer output. The preflight records the complete available
token count and the uint32-little-endian SHA-256 of each selected vector. The
independent verifier retokenizes the Git-bound workload and recomputes every
digest and prefix relation. The master evidence also retains the complete first
8,193 token IDs as a uint32-little-endian file with exact byte count and SHA-256.
Every direct cell verifies its own first `P+1` IDs against that file prefix.

## Primary direct-prefill intervention

The primary intervention is a fresh direct LLM prefill at each registered `P`.
Each of the six isolated cell processes loads the same pinned model and
tokenizer, supplies exactly the first `P` workload tokens to the model, derives
the direct native BF16 KV cache, and encodes that complete direct cache. No
direct cache, model object, or allocator state is reused across lengths. Only
the direct-series container bytes determine the primary and endpoint criteria.
Every direct cell retains each complete canonical BF16 layer as a raw
little-endian file, including exact path, rows, columns, byte count, SHA-256,
and a whole-cache framed digest. The 198,180,864-byte total (about 198 MB or
189 MiB)
permits independent byte comparison and fresh re-encoding.

## Secondary master-slice control

There is no extra master model execution. The registered primary direct cell at
`P=8192` is the sole master anchor. Its retained canonical BF16 layers and
8,193-token ID file bind the secondary control to an actual primary
intervention point rather than a seventh forward pass.

For length `P`, the secondary codec-control matrix for every layer is exactly
the first `P` rows of that master layer. The raw byte prefix, per-slice digest,
and a digest framing all sliced layers are retained. This secondary series
holds the numerical master execution constant while changing only encoded row
count; it must never be relabelled, pooled, or substituted for the primary
direct-prefill intervention.

Each length executes in a fresh operating-system process and loads a fresh
model and tokenizer for its primary direct prefill and behavior. Only after all
six primary processes terminate do six fresh codec-only secondary processes
run. Each reads the verified `P=8192` direct BF16 prefix, encodes it under the
separately named secondary namespace, and compares it byte-for-byte with the
corresponding retained direct cache. A direct cell cannot read the master
anchor or depend on a secondary result. No model object, allocator state,
reconstructed cache, encoded container, environment mutation, or failure state
is reused across direct cells. The immutable `P=8192` raw evidence is the only
shared secondary-control state.
All deterministic, offline, asset, source, cgroup, process-group timeout, and
runtime-lock contracts are the same fail-closed contracts used by the adapter
sweep.

Direct process timeouts are preregistered by level: 600 seconds for 256, 512,
1,024, and 2,048 tokens; 900 seconds for 4,096; and the selected profile's
1,350-second maximum for 8,192. Each codec-only secondary process has 300
seconds. A timeout remains a visible incomplete cell and is never silently
retried within the attempt. These bounds total 6,450 worker-seconds before
orchestrator overhead and cleanup.

For every cell, flattening and rebuilding the direct cache as a native dynamic
cache must reproduce its direct next-token logits exactly before lossy encoding
is admitted. Every direct cache layer is encoded independently under
`direct/containers/`; every master slice is later encoded by its codec-only
process under `secondary/<levelId>/containers/`, with the same frozen VoidToken
V5 configuration.
Encoded bytes are written, reparsed, and reconstructed only from their own
fresh parse. The controlled 32-token baseline and candidate trajectories start
from the direct native cache and direct parsed lossy reconstruction. The
candidate free run and the same behavioral fields as the adapter sweep are
retained for the primary direct series.

The secondary worker records whether the direct canonical BF16 cache is byte-identical
to the master slice, the count of differing BF16 words, the maximum absolute
element difference, and both framed cache digests. These are secondary prefix
equivalence diagnostics. A difference remains visible and helps interpret the
two series, but does not replace, filter, or invalidate the registered primary
direct-prefill compression point.

## Primary estimand and decision rule

For each registered length `P`, the descriptive compression ratio is

```text
R(P) = complete dense BF16 cache bytes / complete serialized container bytes
```

Both numerator and denominator cover every K/V element of every model layer.
Payload-only ratios and cross-cell byte reuse are forbidden. `R(P)=2` means the
complete containers occupy half the bytes of the canonical dense BF16 cache; it
does not mean twice as many tokens fit in all system memory.

The primary directional criterion is true only when all five adjacent ratios
are strictly increasing. Its decision is made with exact integer arithmetic.
For adjacent points `(denseL, containerL)` and `(denseR, containerR)`, the
signed numerator is

```text
denseR * containerL - denseL * containerR
```

and the adjacent point increases if and only if this integer is positive. Thus
no rounded or binary floating-point ratio controls the verdict. The five exact
comparisons correspond to:

```text
R(512)-R(256) > 0
R(1024)-R(512) > 0
R(2048)-R(1024) > 0
R(4096)-R(2048) > 0
R(8192)-R(4096) > 0
```

The endpoint contrast is computed by the same exact cross-product rule and is
secondary; it cannot override a failed primary criterion. Floating-point
ratios and deltas are retained only as descriptive conveniences. The verifier
recomputes all integer numerators, all six descriptive ratios, strict
monotonicity, and nondecreasing monotonicity directly from complete container
evidence.

The endpoint materiality threshold is an exact relative increase of at least
one percent. It holds precisely when

```text
100 * dense8192 * container256 - 101 * dense256 * container8192 >= 0
```

Every potentially large cross-product numerator is serialized as a signed
base-10 integer string. No JSON floating-point or implementation integer width
controls a decision.

The registered support class has indeterminate precedence. Any incomplete or
unverifiable evidence is `INDETERMINATE`. A complete direct series is
`STRONG_DIRECTIONAL_SUPPORT` exactly when all five adjacent ratios strictly
increase. It is `WEAK_DIRECTIONAL_SUPPORT` when the endpoint ratio increases
but at least one adjacent ratio does not. When the endpoint does not increase,
it is `NO_POSITIVE_SUPPORT_EQUAL` or `NO_POSITIVE_SUPPORT_DECREASE` according
to the exact endpoint numerator. The one-percent materiality flag is always
reported separately and never changes this class. The secondary master-slice
series is descriptive and never determines it.

Both series also retain a separately labelled payload-only diagnostic to expose
fixed container-header amortization: payload bytes, container overhead bytes,
container and payload bytes per prefill token, payload-only ratio, five exact
payload cross-product signs, endpoint sign, and the exact one-percent endpoint
flag. Payload-only quantities never replace the complete-container estimand and
never control the support class.

There are no stochastic repetitions and no inferential p-values or confidence
intervals. Deterministic reruns test reproducibility, not sampling variation,
and must not be counted as independent observations. Behavioral fields are
reported per length as fidelity diagnostics; they are not substituted for the
compression estimand.

## Evidence closure

A complete run contains exactly six terminal primary `COMPLETE` cells in the
registered nonmonotone order and six terminal secondary `SECONDARY_COMPLETE`
codec-only controls. Each has a private attempt record, exact source and asset
bindings, token geometry, canonical-cache or slice digests, complete container
manifest where applicable, behavior or diagnostic fields, runtime, memory,
logs, and digest sidecars. Any timeout, signal, OOM, missing artifact,
geometry mismatch, token mismatch, partial output, or nonzero exit makes the
run `INCOMPLETE`; it is never silently retried under the same run identity or
filtered from publication.

The structural verifier independently enforces strict canonical JSON, duplicate
key and non-finite rejection, bounded files and decompression, no links or
special files, the exact six-cell filesystem, complete container parsing, byte
accounting, token and metric recomputation, and the registered length analysis.
A separate replay command reloads the pinned model for each registered length
and reproduces the raw native cache, structural replay, and retained 32-token
behavior. Publication of a directional support class requires six distinct
replay receipts, one for every length. Fewer replays leave the result
producer-attested and insufficient for publishable directional support.
Process success, structural verification, and complete model replay are three
separate facts.

No secret, token, endpoint, Pod identifier, private cache path, environment
dump, or SSH material may enter retained public evidence. Asset acquisition and
authenticated setup remain outside offline execution.
