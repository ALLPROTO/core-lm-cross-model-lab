# Frozen NIST Beacon 2.0 wire profile

`beacon-2.0.xsd` is the exact response body captured on 2026-08-05 from the
official NIST CSRC URL:

`https://csrc.nist.gov/csrc/media/Projects/interoperable-randomness-beacons/documents/certificate/beacon-2.0.xsd`

The file is preserved without newline normalization: 19,033 bytes, 356 CRLF
line endings, SHA-256
`24c5b5b6508c0c33db2cda1902ea7f3b2009224895ba4e3fe275b7f4511675d6`,
and SHA-512
`3fcd376a0d84ca8e73c0f708ec3f5dfd0d8fd05720b2ef327a73090602b405d73e533b1c78760b6d1d03d0ef3e54c15889675ca1ce015bb6d1a4f9619ce706fe`.

For exact NIST Beacon 2.0 wire verification in this suite, this linked XSD
version `2.0.0` has priority when its serialization annotations conflict with
draft NISTIR prose. The draft remains explanatory security and protocol
background. In particular, the tracked implementation follows the XSD's
big-endian unsigned 32-bit length prefixes, DER-certificate SHA-512
`certificateId`, unsigned 32-bit `external.statusCode`, list order, and
`SHA-512(unsigned-pulse-bytes || raw-signature-bytes)` output construction.
The live API's JSON field names are mapped directly to the corresponding XSD
pulse fields. Hash the raw XSD bytes before parsing or normalizing them.

Freezing this source does not authorize fetching the future target pulse and
does not by itself freeze the experiment design.
