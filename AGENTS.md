# Real-data cross-model execution policy

Legacy root result-producing runs must use the pinned real pretrained models
and pinned real WikiText validation asset declared in `models.json`. The active
prospective contour is `blind_v1/`. Its non-scientific development control uses
the separately pinned UD English PUD r2.18 CoNLL-U source and three excluded
pilot models; its confirmatory pool contains six different exact revisions.
V4 is a non-scientific development archive, v3 is a non-scientific
failed-freeze archive, and v2 is a superseded unfrozen draft.

Synthetic, generated, toy, mocked, or beacon inputs must not produce current
benchmark metrics, PASS/FAIL claims, or publication evidence. Mocked values are
permitted only in isolated unit, parser, security, and protocol-control tests;
their outputs must never enter a result directory.

The legacy root Linux workflow must keep the codec source fixed at commit
`61afcf1a44007dec54bd1c56e3403bc74182a400`, use public validation blocks
64 through 71, and execute every model in its own process. Do not tune the
configuration, block range, thresholds, dtype, tokenizer, or dependency set
between model cells.

Every run through that legacy root workflow is an exploratory
public-validation regression. It is not blind, does not execute the beacon
one-shot, does not count toward the Core LM frozen scientific verdict, and
must not be described as proof of corpus-wide or LLM-wide generalization.

The prospective `blind_v1/` experiment is a separate execution contour with a
new suite identity. Its codec commit, future-corpus selection rule, six-model
pool, dependency locks, deadlines, public execution reservation, and one-shot
policy are governed exclusively by the canonical design and
`blind_v1/PROTOCOL.md`. Before a public design freeze, only the single tracked
non-scientific E2E control may run on the pinned UD English PUD r2.18 `test`
split at `blind_v1/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`. That upstream
test split is reused only as development input and is not the prospective
scientific test corpus. Its diagnostics stay outside scientific result roots,
cannot use future corpus/NIST/attempt state, and cannot be used for tuning.
The corpus and reversible derivatives retain the upstream CC BY-SA 3.0
attribution/share-alike obligations. No forward pass, candidate scoring, or
behavioral probe may run on any of the six confirmatory revisions before the
registered pulse. After freeze, only the durable runner may create the single
scientific attempt, and only after the signed public execution reservation is
verified. Fixtures, development records, and legacy blocks 64 through 71 must
never be substituted into that attempt or its evidence.

Blind V1 governance is author self-verification. No independent human
review, peer review, operator blindness, or independent replication is
claimed. Exact-commit Linux/macOS CI, signed releases, independent software
replay, and post-publication reproducibility remain mandatory technical gates.
The tracked Blind V1 NIST leaf is time-valid at the registered target, but the
suite remains an unfrozen draft until the complete trust policy and every other
P0 gate are bound to an immutable exact commit and signed design release. No
v2, v3, or v4 report, tag, receipt, release, corpus, pulse, or attempt may
satisfy a Blind V1 gate.

Preserve negative cells and execution failures. Never average a failing model
away, silently replace a failed model or asset, or convert a diagnostic FAIL
into a successful scientific claim.
