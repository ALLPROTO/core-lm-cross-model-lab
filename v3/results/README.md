# Blind v3 result boundary

This tracked directory contains documentation only. No development output,
protocol-control fixture, model preflight, corpus crawl, regression, or
scientific attempt may be written here.

The one-shot runner derives the only allowed scientific result root as the
external sibling `<private_root>.one-shot-result` of the sealed private
snapshot. It creates the durable reservation and marker there before resolving
the NIST selection or opening selected corpus/model bytes. Once a reservation
exists, no retry is permitted. Every later execution belongs under a distinct
external regression identity and must state
`countsTowardScientificVerdict=false`.
