# Real-data cross-model execution policy

Legacy root result-producing runs must use the pinned real pretrained models
and pinned real WikiText validation asset declared in `models.json`. The active
v4 development contour instead uses the separately pinned UD English PUD r2.18
CoNLL-U source and three models declared under `v4/`. The v3 contour is a
non-scientific failed-freeze archive; v2 is a superseded, unfrozen draft.

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

The prospective `v4/` experiment is a separate execution contour. Its codec
commit, real-corpus selection rule, model set, dependency locks, deadlines,
and one-shot policy are governed exclusively by the frozen canonical design
and `v4/PROTOCOL.md`. Before a public design freeze, only the single tracked
non-scientific E2E control may run on the pinned UD English PUD r2.18 `test`
split at `v4/.assets/ud-english-pud-r2.18/en_pud-ud-test.conllu`. That upstream
test split is reused only as development input and is not the prospective
scientific test corpus. Its diagnostics stay outside scientific result roots,
cannot use future corpus/NIST/attempt state, and cannot be used for tuning.
The corpus and reversible derivatives retain the upstream CC BY-SA 3.0
attribution/share-alike obligations. After the freeze,
only the durable runner may create the single scientific attempt; fixtures or
legacy blocks 64 through 71 must never be substituted into that attempt or its
evidence.

The v4 governance mode is author self-verification. No independent human
review, peer review, operator blindness, or independent replication is
claimed. Exact-commit Linux/macOS CI, signed releases, independent software
replay, and post-publication reproducibility remain mandatory technical gates.
The tracked NIST development leaf expires before the proposed v4 pulse, so v4
must remain unfrozen until replacement trust is pinned and verified. No v2 or
v3 report, tag, receipt, or release may satisfy a v4 gate.

Preserve negative cells and execution failures. Never average a failing model
away, silently replace a failed model or asset, or convert a diagnostic FAIL
into a successful scientific claim.
