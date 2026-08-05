# Candidate trust material — not yet freeze-ready

These public certificate bytes are normative inputs, not dynamically fetched
trust. `transport-ca.pem` is the ISRG Root X1 downloaded from the official
Let's Encrypt certificate endpoint. Its SHA-256 is
`22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1`.
On 2026-08-03 it validated the live TLS chains and hostnames for the registered
NIST Beacon and all three registered Wikipedia API hosts. Runtime hostname and
certificate validation remains mandatory; this is not a leaf-certificate pin.

`nist/manifest.json` binds the current real NIST signing chain. Its tracked
bytes currently have SHA-256
`cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`;
all draft design/code commitments must be regenerated to that exact value (or
to a deliberately rebuilt manifest) before freeze. It binds the exact NIST API
leaf whose DER SHA-512 equals certificate ID
`528943a555f5f8ca54423be6dfb95925a35c7b552046420e7d7cd072058a14d6536ad3a8e9754b6582f164a90b0cd86a65d659f5426a2659a947595d1c816c8c`,
the DigiCert intermediate, and self-signed DigiCert Global Root G2. The leaf
is valid from `2025-08-28T00:00:00Z` through
`2026-09-04T23:59:59Z`; the registered
`2026-08-21T18:00:00.000Z` pulse is therefore inside the validity interval.
The earlier claim that the leaf expired before that pulse reversed the two
dates. Calendar validity alone does not make the draft freeze-ready: the exact
manifest digest, root pin, wire profile, hostname, transport trust, and declared
rotation/revocation policy must be independently verified and rebound through
every dependent design commitment before publication. The offline verifier
rechecks every byte, time, issuer/subject link, and RSA signature.

The tracked manifest is deliberately
`CANDIDATE_OFFLINE_TRUST_BUNDLE`, not frozen. Both verifier implementations
reject that status by default; `allow_candidate=True` exists only for local
pre-freeze validation. A scientific or freeze path must receive a separately
reviewed `FROZEN_OFFLINE_TRUST_BUNDLE` whose exact bytes are rebound through
the design. Merely deleting a prose blocker or changing the status string is
not sufficient.

The deterministic permitted promotion is implemented by
`../build_frozen_nist_trust_bundle.py`. It requires the exact 1,933-byte tracked
candidate above and writes a new external self-contained directory. The only
manifest mutation is candidate status to frozen status; the resulting manifest
is exactly 1,930 bytes with SHA-256
`5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`.
It verifies both forms with the producer and separately implemented verifier,
never overwrites an output, and uses no network, pulse, or model inference:

```sh
"$RUNTIME_ROOT/bin/python" -I -B \
  blind_v1/build_frozen_nist_trust_bundle.py \
  --output-root /absolute/new/path/frozen-nist-trust
```

The draft design records candidate SHA-256
`cf7bf0363d0d67441e5f6704d3dcc5d0ebab137a00b90346bb2eb3aa82723706`
and frozen SHA-256
`5290ffc64ee549029fb7f71cab7b1753266a94ca622a6f2ee366873b660a178a`
separately. Its active `offlineTrustBundleSHA256` is the candidate
hash in draft state and changes to the exact frozen hash only in the frozen
lifecycle. Mandatory discharge normalizes the external frozen manifest back to
candidate status and requires byte equality with this tracked file.

The certificate endpoint's exact server payload is preserved separately as
`nist/source/engine-beacon-nist-gov.server.pem`: 2,892 bytes, CRLF line
separators, no terminal line ending, SHA-256
`acd33ba715a14c1d2c1601983c38cb7e671de151c3536fdf25097f28f9533229`.
The runtime manifest references the normalized tracked PEM at
`nist/certificates/engine-beacon-nist-gov.pem`: 2,849 bytes, LF separators,
one terminal LF, SHA-256
`847bbfff2a1a842f07c2c5697e63a102d3cb7605559ec2da5cf8397ee0b5e9de`.
Those two PEM byte strings are deliberately not interchangeable as evidence,
although both decode to the same 2,064-byte DER certificate with SHA-256
`67e1c70f0654421f589f3c908480f6edbadc3521e2798b2b4718dfb4f3c77288`.
The exact official wire-profile source and its checksums are frozen under
`nist/spec/`.

The design independently pins the final DER trust anchor as SHA-256
`cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f`.
This is deliberately separate from the manifest digest: a complete but
attacker-chosen self-signed chain must fail even if its internal commitments
are self-consistent.

Development trust sources captured on 2026-08-03:

- `https://letsencrypt.org/certs/isrgrootx1.pem`
- `https://beacon.nist.gov/beacon/2.0/certificate/<certificateId>`
- `https://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt.pem`
- `https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem`
- `https://csrc.nist.gov/csrc/media/Projects/interoperable-randomness-beacons/documents/certificate/beacon-2.0.xsd`

If the exact current leaf is frozen and the future pulse is signed by any other
certificate ID, the experiment fails closed. A pre-freeze rotation may be
handled only by publishing a newly bound design before observing the target
pulse; signing trust must never be fetched or replaced after observation. The
machine-enforced rotation policy is `NO_ROTATION_AFTER_FREEZE`, and the
singleton `allowedCertificateIds` list must exactly equal the manifest's one
certificate-map key.

The explicit revocation policy is
`EXACT_CERTIFICATE_PIN_NO_REVOCATION_CHECK`, with
`revocationChecked=false`. The exact residual-risk statement is also a
required manifest field: a pinned certificate that is revoked or compromised
before the target pulse can still be accepted; no contemporaneous OCSP or CRL
status is checked or claimed. Certificate time validity must therefore never
be presented as a revocation check. A stronger policy would require a new,
predeclared evidence collector and a newly bound design; it cannot be inferred
or added after seeing the pulse.

The exact accepted leaf Extended Key Usage tuple, in DER order, is
`id-kp-serverAuth` (`1.3.6.1.5.5.7.3.1`) followed by `id-kp-clientAuth`
(`1.3.6.1.5.5.7.3.2`). This is not claimed to be a beacon-specific EKU: its
acceptance depends on the exact NIST certificate byte pin, exact hostname,
end-entity Key Usage, chain, and root commitments. Both verifiers reject a
leaf with `keyCertSign=true` or any different EKU tuple.

The canonical structural contract is
[`../schemas/nist-trust-bundle.schema.json`](../schemas/nist-trust-bundle.schema.json).

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
