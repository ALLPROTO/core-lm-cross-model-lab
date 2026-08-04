# Frozen trust material

These public certificate bytes are normative inputs, not dynamically fetched
trust. `transport-ca.pem` is the ISRG Root X1 downloaded from the official
Let's Encrypt certificate endpoint. Its SHA-256 is
`22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1`.
On 2026-08-03 it validated the live TLS chains and hostnames for the registered
NIST Beacon and all three registered Wikipedia API hosts. Runtime hostname and
certificate validation remains mandatory; this is not a leaf-certificate pin.

`nist/manifest.json` is the independent offline signing chain used to verify
the Beacon pulse signature. Its SHA-256 is
`3c17cb8f6086e201eb4babc692616f621054339dc17376a7acee730e6a8cfc71`.
It binds the exact NIST API leaf whose DER SHA-512 equals certificate ID
`528943a555f5f8ca54423be6dfb95925a35c7b552046420e7d7cd072058a14d6536ad3a8e9754b6582f164a90b0cd86a65d659f5426a2659a947595d1c816c8c`,
the DigiCert intermediate, and self-signed DigiCert Global Root G2. The leaf is
valid at the registered target time. The verifier rechecks every byte, time,
issuer/subject link, and RSA signature without network access.

The design independently pins the final DER trust anchor as SHA-256
`cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f`.
This is deliberately separate from the manifest digest: a complete but
attacker-chosen self-signed chain must fail even if its internal commitments
are self-consistent.

Sources frozen on 2026-08-03:

- `https://letsencrypt.org/certs/isrgrootx1.pem`
- `https://beacon.nist.gov/beacon/2.0/certificate/<certificateId>`
- `https://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pem`
- `https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem`

If the future pulse is signed by any other certificate ID, the registered
experiment fails closed. It must not fetch or accept replacement signing trust
after seeing the pulse.

## GitHub immutable-release attestation trust

`github/trusted_root.json` is the immutable offline trust input for GitHub
release-attestation verification. It is exactly `28,886` bytes with SHA-256
`26b3382d5700afbcd84f980d1d5b6c52bff743dc2a8ee86b8b44c8e1245ce485`.
Its `certificateAuthorities` and `timestampAuthorities` entries provide the
certificate chains used to validate, respectively, the GitHub release signing
certificate and its signed RFC3161 timestamp. The verifier accepts only these
tracked bytes; it neither refreshes the trusted root nor consults ambient
Sigstore trust.

The byte-pinned Cosign 3.0.6 verifier receives this file through
`--trusted-root`, requires certificate identity
`https://dotcom.releases.github.com`, release predicate type
`https://in-toto.io/attestation/release/v0.2`, and a signed timestamp. It
cryptographically verifies the DSSE signature, X.509 chain, exact SAN,
selected release-asset digest, and RFC3161 timestamp signature/chain. The
protocol separately replays the complete signed subject set and requires
`attestedAt` decoded from the raw RFC3161 bytes to equal the semantic result.

The GitHub bundle has no Rekor entry and no certificate SCT. Consequently the
fixed command uses `--private-infrastructure --insecure-ignore-sct`. Those
flags deliberately make transparency-log inclusion, SCT, and public-log
non-equivocation out of scope; they do not disable the DSSE, X.509-chain,
exact-SAN, asset-digest, or RFC3161 checks above. See
[`../RELEASE_RECEIPTS.md`](../RELEASE_RECEIPTS.md) for pinned Cosign
binary hashes and the exact invocation.
