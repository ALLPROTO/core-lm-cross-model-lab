# Real-data cross-model execution policy

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

Legacy root result-producing runs must use the pinned real pretrained models
and pinned real WikiText validation asset declared in `models.json`. V4 is a
non-scientific development archive, v3 is a non-scientific failed-freeze
archive, and v2 is a superseded unfrozen draft. Blind V1 is a separate retired,
unrun terminal draft and is not an active prospective contour.

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

The `blind_v1/` decision checkpoint elapsed before its mandatory P0 inputs,
exact-commit CI receipt, and immutable design release existed. Agents MUST NOT
freeze the V1 design, publish or package a V1 design/reservation/evidence or
closeout release, request or collect its target NIST pulse, collect its future
corpus, materialize or run its confirmatory models, create V1 reservation or
attempt state, invoke its scientific runner, or describe any later output as a
V1 preregistration or scientific result. No environment variable, direct
function call, CLI branch, copied artifact, late timestamp, or edited deadline
may bypass this terminal lifecycle state.

Within `blind_v1/`, agents may run only offline structural verification that
opens no model, corpus, NIST, reservation, release, or attempt state, plus
explicitly labelled non-scientific development-control or post-release
regressions. Such regressions must remain outside scientific result roots,
must not use the six historical confirmatory revisions, future corpus, target
NIST pulse, or scientific state, and must report that they do not count toward
a scientific verdict. Mocked values remain confined to isolated unit, parser,
security, and protocol-control tests and must never enter a result directory.

Every V1 operational instruction, deadline, state transition, collector,
runner, freeze, release, and evidence procedure is retained solely as a
historical counterfactual specification. A later scientific experiment must
start with a new suite ID and move the complete corpus, snapshot, NIST,
reservation, attempt, evidence, and closeout timeline together. No V1, v2, v3,
or v4 report, tag, receipt, release, corpus, pulse, or attempt may satisfy a
successor gate.

Every supported public Blind V1 API or CLI state creator fails closed on the
terminal lifecycle state. `_historical_*` names are private counterfactual
fixture mechanics, outside the supported contract, and must never be called
for scientific execution or publication. Same-process Python can always call
or modify source; this project does not claim a language-level sandbox.
Integrity is enforced by exact source hashes, review, and exact-commit CI.
`bootstrap_runtime.sh`, `create_runtime_manifest.py`, `create_sbom.py`, and
`source_archive.py create` are allowed only as development/provenance
transforms; they cannot authorize, freeze, publish, or scientifically execute
Blind V1.

Blind V1 governance was author self-verification. No independent human review,
peer review, operator blindness, or independent replication is claimed.

Preserve negative cells and execution failures. Never average a failing model
away, silently replace a failed model or asset, or convert a diagnostic FAIL
into a successful scientific claim.
