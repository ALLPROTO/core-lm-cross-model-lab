# Blind cross-model v1 retired result-boundary specification

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

This tracked directory contains documentation only. No development output,
protocol-control fixture, model preflight, corpus crawl, regression, or
scientific attempt may be written here.

Under the abandoned design, existence of this result root would first have
required a verified pre-pulse public `execution-reservation.json` release and
canonical receipt. That public intent record would not have been local attempt
state and would never have been written into this tracked directory.

The counterfactual one-shot runner would have derived the only allowed
scientific result root as the
external sibling `<private_root>.one-shot-result` of the sealed private
snapshot. During the registered post-pulse window it first verifies the public
execution-reservation assets and receipt, then creates the durable local
`attempt-reservation.json` and `attempt-marker.json` under the external result
root before resolving NIST selection or opening selected corpus/model bytes.
Once the local attempt reservation exists, no retry is permitted. If the public
execution reservation exists but no local attempt begins before the hard
deadline, the abandoned design would have required the registered
`NO_ATTEMPT_EXPIRED` closeout. Every later execution would have belonged under
a distinct external regression or replication identity and would have stated
`countsTowardScientificVerdict=false`.
