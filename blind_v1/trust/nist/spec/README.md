# Archived Blind V1 NIST Beacon 2.0 wire profile

> **TERMINAL STATUS — DO NOT EXECUTE BLIND V1**
>
> Blind V1 is `CHECKPOINT_MISSED_TERMINAL_DRAFT`. It was retired without a
> scientific run and is not freezable, publishable, or executable. Every
> command and procedure in this document is preserved only as a historical,
> counterfactual specification and **MUST NOT be executed for Blind V1**. Any
> successor experiment requires a new suite ID and a fully rescheduled timeline.

`beacon-2.0.xsd` is the exact response body captured on 2026-08-05 from the
official NIST CSRC URL:

`https://csrc.nist.gov/csrc/media/Projects/interoperable-randomness-beacons/documents/certificate/beacon-2.0.xsd`

The file is preserved without newline normalization: 19,033 bytes, 356 CRLF
line endings, SHA-256
`24c5b5b6508c0c33db2cda1902ea7f3b2009224895ba4e3fe275b7f4511675d6`,
and SHA-512
`3fcd376a0d84ca8e73c0f708ec3f5dfd0d8fd05720b2ef327a73090602b405d73e533b1c78760b6d1d03d0ef3e54c15889675ca1ce015bb6d1a4f9619ce706fe`.

For historical offline verification of the retired V1 implementation, this
linked XSD version `2.0.0` had priority when its serialization annotations
conflicted with draft NISTIR prose. The draft supplied explanatory security
and protocol background. The archived implementation mapped the API's JSON
field names to the corresponding XSD pulse fields and followed the XSD's
big-endian unsigned 32-bit length prefixes, DER-certificate SHA-512
`certificateId`, unsigned 32-bit `external.statusCode`, list order, and
`SHA-512(unsigned-pulse-bytes || raw-signature-bytes)` output construction.
Offline verification must hash the preserved raw XSD bytes before parsing or
normalizing them.

This archived source cannot authorize a pulse fetch, freeze, publication, or
scientific execution for Blind V1, and it cannot bind a successor. Any
successor requires a new suite ID, a newly committed trust chain, and a fully
rescheduled corpus, snapshot, NIST, attempt, evidence, and closeout timeline.
