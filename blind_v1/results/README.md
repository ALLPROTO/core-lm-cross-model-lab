# Blind cross-model v1 result boundary

This tracked directory contains documentation only. No development output,
protocol-control fixture, model preflight, corpus crawl, regression, or
scientific attempt may be written here.

Before this result root may exist, the separate pre-pulse public
`execution-reservation.json` release and canonical receipt must already verify.
That public intent record is not local attempt state and is never written into
this tracked directory.

The one-shot runner derives the only allowed scientific result root as the
external sibling `<private_root>.one-shot-result` of the sealed private
snapshot. During the registered post-pulse window it first verifies the public
execution-reservation assets and receipt, then creates the durable local
`attempt-reservation.json` and `attempt-marker.json` under the external result
root before resolving NIST selection or opening selected corpus/model bytes.
Once the local attempt reservation exists, no retry is permitted. If the public
execution reservation exists but no local attempt begins before the hard
deadline, the registered `NO_ATTEMPT_EXPIRED` closeout is required. Every later
execution belongs under a distinct external regression or replication identity
and must state `countsTowardScientificVerdict=false`.
