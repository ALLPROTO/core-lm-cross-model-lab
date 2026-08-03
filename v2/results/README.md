# Blind v2 result boundary

This directory is intentionally empty before the normative one-shot. No
development output, protocol-control fixture, model preflight, corpus crawl,
or regression may be written here.

The future one-shot runner must create a durable attempt marker here before it
resolves the NIST selection or opens selected corpus/model bytes. Once that
marker exists, no retry is permitted. Every later execution belongs in a
separate regression directory and must state
`countsTowardScientificVerdict=false`.
