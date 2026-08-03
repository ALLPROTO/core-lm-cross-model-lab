# Blind multi-model v2

Status: **implementation draft — not frozen, not published, not
preregistered, and not run**.

This directory is the fail-closed development contour for the proposed
`corelm-voidtoken-crossmodel-livewiki-v2` experiment. It is intentionally
separate from the completed public-validation regression in the repository
root.

The prospective claim is narrow: one candidate fixed before the corpus exists
must preserve behavior independently for three pinned, previously unrun model
revisions on two future Wikipedia creation-revision corpora selected by one
future authenticated NIST pulse. A PASS would apply only to those models,
corpora, dates, codec, and gates. It would not prove transfer to every LLM.

## Fixed high-level design

- Models: GPT-Neo-125M, SmolLM2-360M, and tiny_starcoder_py at the exact
  revisions in [`design-registration.draft.json`](design-registration.draft.json).
- Corpus: eligible page-creation revisions from the German, English, and
  French Wikipedias in `[2026-08-10T00:00:00Z,
  2026-08-24T00:00:00Z)`.
- Selection: two language editions, sixteen distinct pages from each, and
  model execution order are derived without modulo bias from the exact NIST
  pulse at `2026-08-27T18:00:00.000Z`. The normative selector accepts exact
  ledger bytes, strict-parses them, and requires their SHA-256 values to match
  the frozen snapshot before drawing any page.
- Candidate: group/transform size 128, zlib level 9, no sign transform, 9 bits
  for layers 0 and `floor(layerCount / 3)` and 8 bits for every other layer.
  This reproduces the old `{0, 8}` schedule at 24 layers while defining one
  architecture-neutral rule for 12, 20, and 32 layers. There is no calibration
  or architecture-specific retuning.
- Execution: CPU, two threads, FP32 model execution, canonical BF16 cache
  baseline, 383-token prefill and 128 teacher-forced decisions per page.
- Verdict: all six model/corpus cells and all three model aggregates must pass;
  a negative model cannot be averaged away.

## Current safety boundary

No v2 result exists. The selector's committed known-answer vector is a
protocol-control fixture only and can never enter a result directory. The
development verifier performs no network access, model loading, inference, or
corpus collection.

Run the current offline controls with:

```sh
python3 -m unittest discover -s v2/tests -v
python3 v2/verify_design.py
python3 v2/preflight.py --codec-root ../core-lm-full-retest-main
```

Materialize and verify only the 21 small configuration/tokenizer files with:

```sh
python3 v2/fetch_assets.py \
  --destination v2/.assets \
  --small-files-only
```

Omitting `--small-files-only` additionally downloads the three exact
`model.safetensors` files (1,906,255,408 bytes total). The standard-library
loader uses immutable revisions, HTTPS allowlists without environment proxies,
bounded reads, exclusive partial files, SHA-256/size checks, and atomic
no-overwrite publication. Asset materialization performs no model import or
inference and does not create scientific evidence or an attempt marker.

The dependency-free selector/design controls run with system Python. Cache
layout controls run when the benchmark's hash-locked runtime (including NumPy)
is used; otherwise those tests report an explicit skip rather than installing
an unpinned package.

`verify_design.py --require-freezable` is deliberately fail-closed in this
development contour. Deleting blocker strings or inventing commit hashes cannot
make it pass. A separately reviewed freeze validator must first derive every
gate from concrete artifacts and public release identities. Public release
creation, snapshot collection, and the one-shot run remain separate authorized
actions.

`preflight.py` is read-only: it verifies the exact codec commit, tree, and files,
an optional no-symlink asset snapshot, power/memory state, and pristine result boundary.
It never downloads, imports a model, opens corpus data, or creates an attempt
marker. `--require-execution-ready` intentionally returns a non-zero status
until the complete frozen runtime, assets, AC power, memory floor, and design
requirements are satisfied.

## Required implementation stages

1. Complete and independently verify every model/tokenizer asset hash and
   license entry.
2. Implement variable-layer cache handling and the GPTBigCode MQA adapter.
3. Prove bounded immutable-byte model loading without `from_pretrained`, mmap,
   pickle, `trust_remote_code`, or a second full FP32 copy.
4. Implement and audit the two-pass MediaWiki collector, attribution ledger,
   strict UTF-8 rules, and immutable snapshot release verifier.
5. Populate and verify the offline NIST trust bundle and known-answer pulses.
6. Implement the durable one-shot state machine, deadline supervisor, raw
   evidence verifier, schemas, and negative-path tests.
7. Publish the immutable design before the future corpus interval starts.

The detailed normative draft is
[`design-registration.draft.json`](design-registration.draft.json). Earlier
design exploration remains only in local notes and Git history; a fresh clone
does not need an ignored file to understand or verify this contour.
