# Reproducing the recorded RunPod sweep

This guide has two distinct goals: reproduce the published record bytes from the retrieved export, or rerun the exploratory matrix from its exact source. Neither operation is an independent scientific replication unless a separately controlled experiment is designed and executed.

## Pinned identity

- Sweep commit: `bdce0b48670bfcb11caa706b99e85cff475abfa7`
- Sweep tree: `ed06a82a054fe5df54ffbeac97ca0b604c7eaa1f`
- Codec commit: `e7e0504b15769c925206ad1783d45a9ca0b62207`
- Codec tree: `924d3195122e3a486e2d26e4fbdfe574654ae6c8`
- Container image: `sha256:4bd7c1a4e9ab92119e0e635385caba9439b4459db751a069d1ca6907ea7624bb`
- Retrieved archive SHA-256: `e785665f9ec63dd324797b4a7bbfac66d4c2e1b20000bfaa998da3b8f04d04cf`
- GPU/driver observed: `NVIDIA A100-SXM4-80GB` / `580.126.20`

The complete runtime-lock digests, source receipt, 28 raw rows, attempt history, and cleanup attestations are in `record.json`. Lifecycle fields are explicitly `OPERATOR_SELF_ATTESTED_NOT_PROVIDER_VERIFIED`: this builder checks their schema, grammar, and internal consistency, but does not query RunPod or independently verify termination, billing, volume deletion, or credential revocation. Do not substitute a model revision, tokenizer asset, workload path, runtime wheel, codec commit, image tag, or context target.

## Rebuild this publication record

1. Obtain the two retrieved files `corelm-runpod-adapter-sweep-v1.tar.gz` and `SHA256SUMS` in one owner-private directory. The archive itself is intentionally not committed to Git.
2. Check out this repository and make sure the recorded sweep commit is present. Its signature must verify against `v4/signing/allowed_signers`.
3. From the repository root, run:

```bash
python3 runpod-adapter-sweep-v1/recorded-runs/build_recorded_run.py verify \
  --publication-dir runpod-adapter-sweep-v1/recorded-runs/2026-08-12-attempt-04 \
  --export-dir /private/path/to/retrieved-export \
  --repository .
```

This rechecks the archive checksum, exactly one complete gzip member with no trailing bytes, the safe inventory, every canonical JSON sidecar, all 28 result/container/log bindings, the structural receipt, the seven representative replay receipts, the sweep commit signature and committed trust root, the exact signed-commit workload blobs and registered frames, the operator metadata, and the deterministic Markdown rendering.

The builder binds asset receipts to signed profile paths/byte counts and every profile SHA-256 available in the registry, and requires identical raw/verified file inventories. It does not retrieve gated asset bytes. It also requires the exact registered codec commit/tree, eight-file manifest, and lock hashes. The codec signature and codec bytes remain a same-Pod source-receipt assertion (`SAME_POD_RECEIPT_NOT_LOCALLY_REVERIFIED`) because the codec repository is not an input. Token IDs and available/selected token counts remain `SAME_POD_ASSERTION_NOT_LOCALLY_RETOKENIZED`; the model-free publication builder does not locally retokenize. It does not rerun the model or independently decode the containers.

## Rerun the matrix

1. Read `../../RUNPOD.md` in full. Use exactly one admitted NVIDIA GPU with at least 78,000 MiB visible VRAM, the immutable image digest above, the 20-hour provider fuse, and the USD 35 ceiling.
2. Accept the gated Gemma terms and create only a dedicated fine-grained read token. Map it through RunPod Secrets; never put it in a command, file, notebook, log, or repository.
3. Clone both repositories into separate sterile checkouts, detach the sweep at the exact commit/tree above, verify both signed commits, and build the exact CUDA runtime with `build_cuda_runtime.sh`.
4. Launch only through `run_on_runpod.sh`. It performs the model-free tests, asset materialization, 28 fresh-process cells, structural verification, seven same-Pod replays, privacy scan, and deterministic packaging.
5. Retrieve the archive and checksum over the host-key-pinned SSH channel. Verify them before terminating the Pod.
6. Terminate rather than stop the Pod; confirm the Pod volume is gone; delete the RunPod Secret; revoke the Hugging Face and lifecycle API tokens; retire the ephemeral SSH credential.

A rerun creates a new attempt and new evidence hashes. Do not overwrite this directory or treat a matching trend as a frozen scientific verdict.
