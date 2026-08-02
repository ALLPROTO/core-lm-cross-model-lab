# Real-data cross-model execution policy

All result-producing runs in this repository must use the pinned real
pretrained models and pinned real WikiText validation asset declared in
`models.json`.

Synthetic, generated, toy, mocked, or beacon inputs must not produce current
benchmark metrics, PASS/FAIL claims, or publication evidence. Mocked values are
permitted only in isolated unit, parser, security, and protocol-control tests;
their outputs must never enter a result directory.

The Linux workflow must keep the codec source fixed at commit
`61afcf1a44007dec54bd1c56e3403bc74182a400`, use public validation blocks
64 through 71, and execute every model in its own process. Do not tune the
configuration, block range, thresholds, dtype, tokenizer, or dependency set
between model cells.

Every run is an exploratory public-validation regression. It is not blind,
does not execute the beacon one-shot, does not count toward the Core LM frozen
scientific verdict, and must not be described as proof of corpus-wide or
LLM-wide generalization.

Preserve negative cells and execution failures. Never average a failing model
away, silently replace a failed model or asset, or convert a diagnostic FAIL
into a successful scientific claim.
